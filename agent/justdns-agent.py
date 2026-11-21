#!/usr/bin/env python3
"""JustDNS Fleet-Agent (Sensor-Seite, eigene LXCs/VMs).

Tailt die Logs einer unterstuetzten Anwendung (nginx, Caddy, Node64, NPM, Apache,
HAProxy, sshd, fail2ban), filtert Ablehnungen (abgelehnte/blockierte Zugriffe)
heraus, normalisiert sie zu Events und POSTet sie mit Submission-Token an die
Intake-API (/agent/events). At-least-once wie der Shipper: Byte-Offsets je Logdatei
werden erst nach erfolgreichem POST fortgeschrieben; schlaegt der POST fehl, bleibt
der Offset stehen und wird naechsten Lauf erneut gesendet. Dedup macht die Zentrale
ueber (sensor_id, event_uid).

Private Quell-IPs (RFC1918, CGNAT, loopback, link-local) werden ueberhaupt nur
lokal gemeldet und von der Intake markiert - sie landen nie auf der oeffentlichen
Liste. Der Agent sendet sie trotzdem (fuers lokale SOC-Bild), filtert aber nichts
Globales weg.

Token kommt aus der Config (die der UI-generierte Install-Befehl setzt). App-Profil
und Logpfad ebenso. Nur Standardbibliothek. Als systemd-Timer/Service ausrollbar.

Config (Env ODER Datei via --config, KEY=VALUE je Zeile):
  INTAKE_URL     Pflicht, z.B. https://intake.justdns.justfuture.at
  TOKEN          Pflicht. Von /agent/register (UI) ausgegeben.
  APP            Pflicht. nginx|caddy|node64|npm|apache|haproxy|sshd|fail2ban
  HOST           optional, Label fuers Dashboard (LXC/VM-Name).
  LOG_GLOB       optional. Leer -> App-Default (siehe PROFILES).
  REJECT_STATUS  optional, HTTP-Status die als Ablehnung zaehlen.
                 Default 401,403,404,405,429,444
  STATE_FILE     Default /var/lib/justdns-agent/state.json
  BATCH          Events je POST-Request, Default 500
"""

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

DEFAULTS = {
    "INTAKE_URL": "https://intake.justdns.justfuture.at",
    "TOKEN": "",
    "APP": "",
    "HOST": "",
    "LOG_GLOB": "",
    "REJECT_STATUS": "401,403,404,405,429,444",
    "STATE_FILE": "/var/lib/justdns-agent/state.json",
    "BATCH": "500",
}

# Default-Logpfade je App-Profil. Ueberschreibbar via LOG_GLOB.
DEFAULT_GLOBS = {
    "nginx": "/var/log/nginx/access.log*",
    "apache": "/var/log/apache2/access.log*",
    "caddy": "/var/log/caddy/access.log*",
    "node64": "/var/log/node64/access.log*",
    "npm": "/data/logs/proxy-host-*_access.log*",
    "haproxy": "/var/log/haproxy.log*",
    "sshd": "/var/log/auth.log*",
    "fail2ban": "/var/log/fail2ban.log*",
}


def log(msg):
    print(f"[agent] {msg}", file=sys.stderr)


# --- Config / State (identisch zur Shipper-Mechanik) -------------------------

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
    try:
        st = os.stat(fpath)
        return f"{st.st_dev}:{st.st_ino}"
    except OSError:
        return None


def uid_for(fpath, offset):
    key = file_key(fpath) or os.path.basename(fpath)
    return hashlib.sha1(f"{key}:{offset}".encode("utf-8")).hexdigest()


# --- Parser je App-Profil ----------------------------------------------------
#
# Jeder Parser bekommt (line, ctx) und gibt ein Event-dict zurueck
# ({src_ip, reason, path, status_code, app}) oder None (keine Ablehnung / nicht
# parsebar). ctx traegt reject_status (Menge der als Ablehnung zaehlenden HTTP-
# Codes). Non-Matches liefern None, damit unbekannte Formate nie crashen.

# Combined Log Format: addr - user [time] "METHOD path proto" status ...
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>[^" ]*)[^"]*" (?P<status>\d{3})'
)
# Nginx Proxy Manager: Format variiert je Version. Robust: drei Einzel-Treffer
# (Status nach dem Zeitstempel, Pfad in Quotes, Client-IP in [Client ...]).
_NPM_STATUS_RE = re.compile(r'\]\s+(?:-\s+)?(?P<status>[1-5]\d\d)\b')
_NPM_PATH_RE = re.compile(r'"(?P<path>/[^"]*)"')
_NPM_CLIENT_RE = re.compile(r'\[Client (?P<ip>[0-9a-fA-F:.]+)\]')
# HAProxy httplog: "<client_ip>:<port> [<accept-date>] frontend be/srv t/t/t/t/t
# <status> <bytes> ... "METHOD path proto"". Anker auf ":<port> [<DD/Mon/YYYY>",
# damit nicht die Syslog-Uhrzeit als IP gegriffen wird.
_HAPROXY_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+):\d+ \[\d{2}/\w{3}/\d{4}[^\]]*\]'
    r'.*? (?P<status>\d{3}) \d+ .*?"(?P<method>[A-Z]+) (?P<path>\S+)'
)
_SSH_FAIL_RE = re.compile(
    r'(?:Failed password|Invalid user|authentication failure).*?from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)'
)
_SSH_USER_RE = re.compile(r'for (?:invalid user )?(?P<user>\S+) from')
_F2B_BAN_RE = re.compile(r'\bBan (?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)')


def _parse_combined(line, ctx, app):
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    status = int(m.group("status"))
    if status not in ctx["reject_status"]:
        return None
    return {"src_ip": m.group("ip"), "reason": f"http_{status}",
            "path": m.group("path"), "status_code": status, "app": app}


def _parse_json_access(line, ctx, app):
    """Caddy/Node64: JSON-Zeile. remote_ip/remote_addr + status + uri/path."""
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        e = json.loads(line)
    except ValueError:
        return None
    req = e.get("request") if isinstance(e.get("request"), dict) else {}
    ip = req.get("remote_ip") or req.get("client_ip") or e.get("remote_ip") or e.get("src_ip")
    if not ip and isinstance(req.get("remote_addr"), str):
        ip = req["remote_addr"].rsplit(":", 1)[0]   # ip:port
    status = e.get("status") or e.get("status_code")
    try:
        status = int(status)
    except (TypeError, ValueError):
        return None
    if not ip or status not in ctx["reject_status"]:
        return None
    path = req.get("uri") or req.get("path") or e.get("uri")
    return {"src_ip": str(ip), "reason": f"http_{status}",
            "path": path, "status_code": status, "app": app}


def _parse_npm(line, ctx, app):
    cm = _NPM_CLIENT_RE.search(line)
    sm = _NPM_STATUS_RE.search(line)
    if not cm or not sm:
        return None
    status = int(sm.group("status"))
    if status not in ctx["reject_status"]:
        return None
    pm = _NPM_PATH_RE.search(line)
    return {"src_ip": cm.group("ip"), "reason": f"http_{status}",
            "path": pm.group("path") if pm else None, "status_code": status, "app": app}


def _parse_haproxy(line, ctx, app):
    m = _HAPROXY_RE.search(line)
    if not m:
        return None
    status = int(m.group("status"))
    if status not in ctx["reject_status"]:
        return None
    return {"src_ip": m.group("ip"), "reason": f"http_{status}",
            "path": m.group("path"), "status_code": status, "app": app}


def _parse_sshd(line, ctx, app):
    m = _SSH_FAIL_RE.search(line)
    if not m:
        return None
    um = _SSH_USER_RE.search(line)
    path = f"user={um.group('user')}" if um else None
    return {"src_ip": m.group("ip"), "reason": "auth_fail",
            "path": path, "status_code": None, "app": app}


def _parse_fail2ban(line, ctx, app):
    m = _F2B_BAN_RE.search(line)
    if not m:
        return None
    return {"src_ip": m.group("ip"), "reason": "fw_ban",
            "path": None, "status_code": None, "app": app}


PROFILES = {
    "nginx": _parse_combined,
    "apache": _parse_combined,
    "caddy": _parse_json_access,
    "node64": _parse_json_access,
    "npm": _parse_npm,
    "haproxy": _parse_haproxy,
    "sshd": _parse_sshd,
    "fail2ban": _parse_fail2ban,
}


def read_new_events(fpath, start_offset, parse, ctx, app):
    """Ab start_offset lesen, (events, new_offset). Truncation -> ab 0."""
    events = []
    try:
        size = os.path.getsize(fpath)
    except OSError:
        return events, start_offset
    offset = start_offset
    if size < offset:
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
                offset = line_start
                return events, offset
            text = raw.decode("utf-8", "replace").strip()
            offset = fh.tell()
            if not text:
                continue
            ev = parse(text, ctx, app)
            if ev is None:
                continue
            ev["ts"] = None
            ev["uid"] = uid_for(fpath, line_start)
            events.append(ev)
    return events, offset


def post_batch(url, token, events):
    body = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/agent/events", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ship_file(fpath, state, parse, ctx, app, url, token, batch):
    key = file_key(fpath)
    if key is None:
        return 0, True
    start = int(state.get(key, {}).get("offset", 0)) if isinstance(state.get(key), dict) else 0
    events, new_offset = read_new_events(fpath, start, parse, ctx, app)
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


def parse_reject_status(raw):
    out = set()
    for tok in str(raw).split(","):
        tok = tok.strip()
        if tok.isdigit():
            out.add(int(tok))
    return out or {401, 403, 404, 405, 429, 444}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("AGENT_CONFIG", "/etc/justdns-agent.conf"))
    args = ap.parse_args()

    cfg = load_config(args.config)
    if not cfg["INTAKE_URL"]:
        log("INTAKE_URL erforderlich (Env oder --config).")
        return 2
    if not cfg["TOKEN"].strip():
        log("TOKEN erforderlich - aus der UI ('Agent hinzufuegen') beziehen.")
        return 2
    app = cfg["APP"].strip().lower()
    parse = PROFILES.get(app)
    if parse is None:
        log(f"unbekannte APP {app!r}. Erlaubt: {', '.join(sorted(PROFILES))}")
        return 2

    glob_pat = cfg["LOG_GLOB"].strip() or DEFAULT_GLOBS.get(app, "")
    if not glob_pat:
        log("LOG_GLOB erforderlich (kein Default fuer diese App).")
        return 2

    ctx = {"reject_status": parse_reject_status(cfg["REJECT_STATUS"])}
    batch = max(1, int(cfg["BATCH"]))
    state = load_state(cfg["STATE_FILE"])

    total = 0
    all_ok = True
    for fpath in sorted(glob.glob(glob_pat)):
        sent, ok = ship_file(fpath, state, parse, ctx, app,
                              cfg["INTAKE_URL"], cfg["TOKEN"].strip(), batch)
        total += sent
        all_ok = all_ok and ok
        if not ok:
            break

    save_state(cfg["STATE_FILE"], state)
    log(f"gesendet/bestaetigt: {total} Ablehnung(en) [{app}]")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
