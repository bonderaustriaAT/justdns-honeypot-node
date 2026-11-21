#!/usr/bin/env python3
"""JustDNS Fleet-Shipper (Sensor-Seite).

Tailt cowrie.json + opencanary.log, normalisiert zu Events, batcht und POSTet
sie mit Submission-Token an die Intake-API. At-least-once: Byte-Offsets je
Logdatei werden erst nach erfolgreichem POST fortgeschrieben; schlaegt der POST
fehl (Intake offline), bleiben die Offsets stehen und beim naechsten Lauf wird
alles erneut gesendet. Dedup macht die Zentrale ueber (sensor_id, event_uid).

Fremd-Deploy: nur SENSOR_ID, TOKEN, INTAKE_URL setzen (Env oder Config-Datei).
Nur Standardbibliothek. Als systemd-Timer/Service ausrollbar.

Config (Env ODER Datei via --config, KEY=VALUE je Zeile):
  SENSOR_ID    informativ (Zentrale leitet den Sensor aus dem Token ab)
  TOKEN        Submission-Token (jdhs_...)
  INTAKE_URL   z.B. https://intake.justdns.justfuture.at
  COWRIE_LOG   Glob, Default /home/cowrie/cowrie/var/log/cowrie/cowrie.json*
  OC_LOG       Glob, Default /var/tmp/opencanary.log*
  STATE_FILE   Default /var/lib/justdns-shipper/state.json
  BATCH        Events je POST-Request, Default 500
"""

import argparse
import glob
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

COWRIE_FAILED = "cowrie.login.failed"
PORT_SVC = {21: "FTP", 23: "TELNET", 80: "HTTP", 3306: "MYSQL",
            3389: "RDP", 5900: "VNC", 2222: "SSH", 22: "SSH"}

DEFAULTS = {
    "SENSOR_ID": "",
    "TOKEN": "",
    "INTAKE_URL": "",
    "COWRIE_LOG": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*",
    "OC_LOG": "/var/tmp/opencanary.log*",
    "STATE_FILE": "/var/lib/justdns-shipper/state.json",
    "BATCH": "500",
}


def log(msg):
    print(f"[shipper] {msg}", file=sys.stderr)


def load_config(path):
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    for k in cfg:
        if os.environ.get(k):
            cfg[k] = os.environ[k]
    return cfg


def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(path, state):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, path)


def file_key(fpath):
    """Stabiler Schluessel je physischer Datei (ueberlebt Rename/Rotation)."""
    try:
        st = os.stat(fpath)
        return f"{st.st_dev}:{st.st_ino}"
    except OSError:
        return None


def uid_for(fpath, offset):
    key = file_key(fpath) or os.path.basename(fpath)
    return hashlib.sha1(f"{key}:{offset}".encode("utf-8")).hexdigest()


def parse_cowrie(line):
    try:
        e = json.loads(line)
    except ValueError:
        return None
    if e.get("eventid") != COWRIE_FAILED:
        return None
    ip = e.get("src_ip")
    if not ip:
        return None
    return {
        "ts": e.get("timestamp"),
        "src_ip": ip,
        "service": "SSH",
        "dst_port": e.get("dst_port"),
        "username": e.get("username", ""),
        "password": e.get("password", ""),
    }


def parse_opencanary(line):
    try:
        e = json.loads(line)
    except ValueError:
        return None
    try:
        if int(e.get("logtype", 0)) < 2000:
            return None
    except (TypeError, ValueError):
        return None
    ip = e.get("src_host")
    if not ip:
        return None
    d = e.get("logdata", {})
    d = d if isinstance(d, dict) else {}
    port = e.get("dst_port")
    return {
        "ts": e.get("utc_time"),
        "src_ip": ip,
        "service": PORT_SVC.get(port, str(port) if port is not None else None),
        "dst_port": port,
        "username": d.get("USERNAME", ""),
        "password": d.get("PASSWORD", ""),
    }


def read_new_events(fpath, start_offset, parser):
    """Ab start_offset lesen, (events, new_offset) zurueckgeben. Bei Truncation
    (Datei kleiner als Offset) von 0 lesen."""
    events = []
    try:
        size = os.path.getsize(fpath)
    except OSError:
        return events, start_offset
    offset = start_offset
    if size < offset:          # copytruncate o.ae. -> neu ab 0
        offset = 0
    if size == offset:
        return events, offset
    with open(fpath, "rb") as fh:
        fh.seek(offset)
        while True:
            line_start = fh.tell()
            raw = fh.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                # unvollstaendige letzte Zeile: noch nicht verarbeiten
                offset = line_start
                return events, offset
            text = raw.decode("utf-8", "replace").strip()
            offset = fh.tell()
            if not text:
                continue
            ev = parser(text)
            if ev is None:
                continue
            ev["uid"] = uid_for(fpath, line_start)
            events.append(ev)
    return events, offset


def post_batch(url, token, events):
    body = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/events", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data


def ship_file(fpath, state, parser, url, token, batch):
    """Alle neuen Events einer Datei senden. Offset erst nach Erfolg schreiben.
    Gibt (gesendet, ok) zurueck."""
    key = file_key(fpath)
    if key is None:
        return 0, True
    start = int(state.get(key, {}).get("offset", 0)) if isinstance(state.get(key), dict) else 0
    events, new_offset = read_new_events(fpath, start, parser)
    if not events:
        state[key] = {"path": fpath, "offset": new_offset}
        return 0, True
    sent = 0
    for i in range(0, len(events), batch):
        chunk = events[i:i + batch]
        try:
            res = post_batch(url, token, chunk)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"POST fehlgeschlagen ({os.path.basename(fpath)}): {exc} - Offset bleibt, Retry naechster Lauf")
            return sent, False
        sent += res.get("accepted", 0) + res.get("duplicate", 0)
    state[key] = {"path": fpath, "offset": new_offset}
    return sent, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("SHIPPER_CONFIG", "/etc/justdns-shipper.conf"))
    args = ap.parse_args()

    cfg = load_config(args.config)
    if not cfg["TOKEN"] or not cfg["INTAKE_URL"]:
        log("TOKEN und INTAKE_URL erforderlich (Env oder --config).")
        return 2

    batch = max(1, int(cfg["BATCH"]))
    state = load_state(cfg["STATE_FILE"])
    total = 0
    all_ok = True

    jobs = [(cfg["COWRIE_LOG"], parse_cowrie), (cfg["OC_LOG"], parse_opencanary)]
    for pattern, parser in jobs:
        for fpath in sorted(glob.glob(pattern)):
            sent, ok = ship_file(fpath, state, parser, cfg["INTAKE_URL"], cfg["TOKEN"], batch)
            total += sent
            all_ok = all_ok and ok
            if not ok:
                break
        if not all_ok:
            break

    save_state(cfg["STATE_FILE"], state)
    log(f"gesendet/bestaetigt: {total} Event(s)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
