#!/usr/bin/env python3
"""JustDNS Fleet-Shipper (Sensor-Seite).

Tailt cowrie.json + opencanary.log, normalisiert zu Events, batcht und POSTet
sie an die Intake-API. At-least-once: Byte-Offsets je Logdatei werden erst nach
erfolgreichem POST fortgeschrieben; schlaegt der POST fehl (Intake offline),
bleiben die Offsets stehen und beim naechsten Lauf wird alles erneut gesendet.

Fremd-Deploy: im Normalfall reicht INTAKE_URL. Ohne TOKEN registriert sich der
Shipper beim ersten Lauf selbst und legt sein Token im STATE_FILE ab.
Alternativ TOKEN direkt setzen. Nur Standardbibliothek. Als
systemd-Timer/Service ausrollbar.

Config (Env ODER Datei via --config, KEY=VALUE je Zeile):
  INTAKE_URL   Pflicht, z.B. https://intake.justdns.justfuture.at
  TOKEN        optional. Leer -> Shipper registriert sich selbst beim ersten Lauf.
  SENSOR_ID    optional, nur als Namensvorschlag bei der Selbst-Registrierung.
  OPERATOR     optional, Label fuers zentrale Dashboard (z.B. Kontakt/Team).
  COWRIE_LOG   Glob, Default /home/cowrie/cowrie/var/log/cowrie/cowrie.json*
  OC_LOG       Glob, Default /var/tmp/opencanary.log*
  WEBDECOY_LOG Glob, Default /var/tmp/webdecoy.log*
  STATE_FILE   Default /var/lib/justdns-shipper/state.json
  BATCH        Events je POST-Request, Default 500
"""

import argparse
import glob
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request

COWRIE_FAILED = "cowrie.login.failed"
COWRIE_SUCCESS = "cowrie.login.success"
COWRIE_LOGIN = (COWRIE_FAILED, COWRIE_SUCCESS)
COWRIE_DL = ("cowrie.session.file_download", "cowrie.session.file_upload")
COWRIE_CMD = "cowrie.command.input"
PORT_SVC = {21: "FTP", 23: "TELNET", 80: "HTTP", 3306: "MYSQL",
            3389: "RDP", 5900: "VNC", 2222: "SSH", 22: "SSH"}

# URLs mit Schema aus einer Kommandozeile, plus "nackte" Hosts direkt hinter
# einem Download-Tool (wget/curl/...), die oft ohne http:// stehen.
_URL_RE = re.compile(r"(?:https?|ftps?|tftp)://[^\s'\"`;|&>)<]+", re.I)
_DLCMD_RE = re.compile(r"\b(?:wget|curl|tftp|ftpget|lwp-download|fetch)\b[^\n]*", re.I)
_HOST_RE = re.compile(r"\b([a-z0-9][a-z0-9.-]{0,252}\.[a-z]{2,24})\b", re.I)

DEFAULTS = {
    "SENSOR_ID": "",
    "OPERATOR": "",
    "TOKEN": "",
    "INTAKE_URL": "https://intake.justdns.justfuture.at",
    "COWRIE_LOG": "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*",
    "OC_LOG": "/var/tmp/opencanary.log*",
    "WEBDECOY_LOG": "/var/tmp/webdecoy.log*",
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
    if e.get("eventid") not in COWRIE_LOGIN:
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


def parse_webdecoy(line):
    """Web-Decoy-Log (HTTP/Docker/Elasticsearch). Jede Zeile ein Request.
    Gemeldet werden Angreifer-IP, Dienst und ggf. abgefangene Credentials."""
    try:
        e = json.loads(line)
    except ValueError:
        return None
    ip = e.get("src_ip")
    if not ip:
        return None
    return {
        "ts": e.get("ts"),
        "src_ip": ip,
        "service": e.get("service") or "HTTP",
        "dst_port": e.get("dst_port"),
        "username": e.get("username", ""),
        "password": e.get("password", ""),
    }


def _host_from_url(u):
    """Hostnamen aus einer URL loesen (ohne Schema/Userinfo/Port/Pfad)."""
    rest = u.split("://", 1)[-1]
    authority = rest.split("/", 1)[0].split("\\", 1)[0]
    authority = authority.split("@")[-1].split("?")[0].split("#")[0]
    if authority.startswith("["):      # IPv6-Literal -> keine Domain
        return None
    host = authority.split(":")[0].strip().strip(".").lower()
    return host or None


def _valid_domain(h):
    """True nur fuer plausible Domainnamen (keine bare IP, gueltige Labels/TLD)."""
    if not h or "." not in h or len(h) > 253:
        return False
    try:
        ipaddress.ip_address(h)        # bare IPv4/IPv6 gehoeren nicht in die DNS-Liste
        return False
    except ValueError:
        pass
    labels = h.split(".")
    if any(not lab or len(lab) > 63 or not re.fullmatch(r"[a-z0-9-]+", lab) for lab in labels):
        return False
    tld = labels[-1]
    return tld.isalpha() and len(tld) >= 2


def parse_cowrie_domains(line):
    """Download-/Nachlade-Domains aus einer Cowrie-Zeile. Gibt eine Liste von
    Domain-Events zurueck (0..n) oder None. Ein Event:
    {ts, src_ip, url, domain, command}. uid vergibt read_new_events."""
    try:
        e = json.loads(line)
    except ValueError:
        return None
    eid = e.get("eventid")
    ip = e.get("src_ip") or ""
    ts = e.get("timestamp")
    candidates = []                    # (host_or_url, sample_url, command)
    if eid in COWRIE_DL:
        u = e.get("url")
        if u:
            candidates.append((_host_from_url(u), u, u))
    elif eid == COWRIE_CMD:
        inp = e.get("input") or ""
        for u in _URL_RE.findall(inp):
            candidates.append((_host_from_url(u), u, inp))
        for seg in _DLCMD_RE.findall(inp):
            seg = _URL_RE.sub(" ", seg)        # schon erfasste URLs rausnehmen
            for h in _HOST_RE.findall(seg):
                candidates.append((h.lower(), h, inp))
    else:
        return None
    out, seen = [], set()
    for host, sample, cmd in candidates:
        if not host or not _valid_domain(host) or host in seen:
            continue
        seen.add(host)
        out.append({"ts": ts, "src_ip": ip, "url": (sample or "")[:512],
                    "domain": host, "command": (cmd or "")[:600]})
    return out or None


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
            res = parser(text)
            if res is None:
                continue
            items = res if isinstance(res, list) else [res]
            base = uid_for(fpath, line_start)
            for idx, ev in enumerate(items):
                ev["uid"] = base if len(items) == 1 else f"{base}-{idx}"
                events.append(ev)
    return events, offset


def register(url, name, operator):
    """Self-Service-Registrierung an der Intake. Gibt (sensor_id, token) zurueck."""
    body = json.dumps({"name": name, "operator": operator}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/register", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["sensor_id"], data["token"]


def ensure_token(cfg, state):
    """Token beschaffen: aus Config, sonst aus dem State (fruehere Registrierung),
    sonst jetzt selbst registrieren. Gibt den Token zurueck oder None bei Fehler.
    Schreibt eine neue Registrierung sofort in den State (ueberlebt Neustarts)."""
    token = cfg["TOKEN"].strip()
    if token:
        return token
    saved = state.get("_sensor") if isinstance(state.get("_sensor"), dict) else None
    if saved and saved.get("token"):
        return saved["token"]
    name = cfg.get("SENSOR_ID") or socket.gethostname() or "node"
    try:
        sid, token = register(cfg["INTAKE_URL"], name, cfg.get("OPERATOR", ""))
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        log(f"Selbst-Registrierung fehlgeschlagen: {exc} - Retry naechster Lauf")
        return None
    state["_sensor"] = {"sensor_id": sid, "token": token}
    save_state(cfg["STATE_FILE"], state)
    log(f"registriert als Sensor {sid}")
    return token


def post_batch(url, token, events, endpoint="/events"):
    body = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + endpoint, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data


def heartbeat(url, token):
    """Lebenszeichen an die Intake, wenn ein Lauf nichts zu senden hatte. So
    bleibt last_seen aktuell und ein stiller (aber lebender) Node sieht im
    Dashboard nicht tot aus. Fehler sind unkritisch, nur Debug-Log."""
    req = urllib.request.Request(
        url.rstrip("/") + "/heartbeat", data=b"", method="POST",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20):
            return True
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"Heartbeat fehlgeschlagen: {exc}")
        return False


def ship_file(fpath, state, parser, url, token, batch, endpoint="/events", state_suffix=""):
    """Alle neuen Events einer Datei (ein Stream) senden. Offset erst nach Erfolg
    schreiben. state_suffix trennt mehrere Streams derselben Datei (z.B. Login- und
    Domain-Events aus cowrie.json) mit je eigenem Offset. Gibt (gesendet, ok)."""
    base = file_key(fpath)
    if base is None:
        return 0, True
    key = base + state_suffix
    start = int(state.get(key, {}).get("offset", 0)) if isinstance(state.get(key), dict) else 0
    events, new_offset = read_new_events(fpath, start, parser)
    if not events:
        state[key] = {"path": fpath, "offset": new_offset}
        return 0, True
    sent = 0
    for i in range(0, len(events), batch):
        chunk = events[i:i + batch]
        try:
            res = post_batch(url, token, chunk, endpoint)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log(f"POST fehlgeschlagen ({os.path.basename(fpath)}{state_suffix}): {exc} - Offset bleibt, Retry naechster Lauf")
            return sent, False
        sent += res.get("accepted", 0) + res.get("duplicate", 0)
    state[key] = {"path": fpath, "offset": new_offset}
    return sent, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("SHIPPER_CONFIG", "/etc/justdns-shipper.conf"))
    args = ap.parse_args()

    cfg = load_config(args.config)
    if not cfg["INTAKE_URL"]:
        log("INTAKE_URL erforderlich (Env oder --config).")
        return 2

    batch = max(1, int(cfg["BATCH"]))
    state = load_state(cfg["STATE_FILE"])

    token = ensure_token(cfg, state)
    if not token:
        save_state(cfg["STATE_FILE"], state)
        return 1

    total = 0
    all_ok = True

    # Login-/Credential-Events (IP-zentrisch) -> /events, wie bisher.
    # Nachlade-Domains aus denselben cowrie.json (eigener Offset :dom) -> /domain-events.
    jobs = [
        (cfg["COWRIE_LOG"], parse_cowrie, "/events", ""),
        (cfg["OC_LOG"], parse_opencanary, "/events", ""),
        (cfg["WEBDECOY_LOG"], parse_webdecoy, "/events", ""),
        (cfg["COWRIE_LOG"], parse_cowrie_domains, "/domain-events", ":dom"),
    ]
    for pattern, parser, endpoint, suffix in jobs:
        for fpath in sorted(glob.glob(pattern)):
            sent, ok = ship_file(fpath, state, parser, cfg["INTAKE_URL"], token,
                                 batch, endpoint, suffix)
            total += sent
            all_ok = all_ok and ok
            if not ok:
                break
        if not all_ok:
            break

    save_state(cfg["STATE_FILE"], state)
    # Nichts gesendet, aber Lauf ok -> Lebenszeichen, damit das Dashboard den
    # stillen Node nicht als tot anzeigt. Bei Events setzt /events last_seen schon.
    if all_ok and total == 0:
        heartbeat(cfg["INTAKE_URL"], token)
    log(f"gesendet/bestaetigt: {total} Event(s)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
