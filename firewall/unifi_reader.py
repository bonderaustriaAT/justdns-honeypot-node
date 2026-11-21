#!/usr/bin/env python3
"""JustDNS Firewall-Reader fuer Unifi (nur lesen).

Zieht von einem Unifi-Controller (UniFi OS: UDM/UDM-Pro/UDR/Cloud Key) die
IPS/IDS-Alarme und - falls geloggt - Firewall-Drops, extrahiert die Quell-IP und
meldet sie als Firewall-Sensor (kind='firewall') an die Intake (POST /agent/events).
NUR lesend: der Reader aendert nichts am Controller.

Auth, zwei Wege:
  - API-Key (UniFi OS, empfohlen): Header X-API-KEY. UNIFI_API_KEY setzen.
  - Lokales Konto: UNIFI_USER/UNIFI_PASS -> Cookie-Login (/api/auth/login bzw.
    /api/login), CSRF-Token wird mitgefuehrt.

Dedupe ueber die Alarm-/Event-_id als event_uid (die Zentrale dedupt). Private
Quell-IPs markiert die Intake und veroeffentlicht sie nie. At-least-once ueber
STATE_FILE (zuletzt gesehener Zeitstempel). Nur Standardbibliothek.

Config (Env ODER Datei via --config, KEY=VALUE je Zeile):
  INTAKE_URL     Pflicht, Intake-Endpunkt.
  TOKEN          Pflicht. Firewall-Sensor-Token (UI oder Selbst-Registrierung).
  UNIFI_URL      Pflicht, z.B. https://192.168.1.1
  UNIFI_API_KEY  API-Key (bevorzugt) ODER UNIFI_USER + UNIFI_PASS.
  UNIFI_USER     Lokales Konto (nur lesen reicht).
  UNIFI_PASS
  UNIFI_SITE     Default 'default'
  VERIFY_TLS     '1' (Default) prueft das Controller-Zertifikat, '0' nicht
                 (selbstsigniert). '0' nur im vertrauten LAN.
  NAME           Anzeige-Name der FW im Dashboard (Default UNIFI_URL-Host).
  STATE_FILE     Default /var/lib/justdns-firewall/unifi-state.json
  LOOKBACK_MIN   Erstlauf: so viele Minuten rueckwirkend lesen (Default 60).
"""

import argparse
import datetime
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULTS = {
    "INTAKE_URL": "https://intake.justdns.justfuture.at",
    "TOKEN": "",
    "UNIFI_URL": "",
    "UNIFI_API_KEY": "",
    "UNIFI_USER": "",
    "UNIFI_PASS": "",
    "UNIFI_SITE": "default",
    "VERIFY_TLS": "1",
    "NAME": "",
    "STATE_FILE": "/var/lib/justdns-firewall/unifi-state.json",
    "LOOKBACK_MIN": "60",
}


def log(msg):
    print(f"[unifi] {msg}", file=sys.stderr)


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


class Unifi:
    """Duennner Read-Client. Deckt UniFi OS (/proxy/network/...) und den
    klassischen Controller (/api/...) ab; probiert beide Pfade."""

    def __init__(self, base, site, verify_tls, opener_ctx):
        self.base = base.rstrip("/")
        self.site = site
        self.ctx = opener_ctx
        self.cookies = {}
        self.csrf = None
        self.api_key = None

    def _request(self, method, path, body=None, extra_headers=None):
        url = self.base + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        resp = urllib.request.urlopen(req, timeout=20, context=self.ctx)
        # Set-Cookie + CSRF fuers Login merken.
        for key, val in resp.getheaders():
            kl = key.lower()
            if kl == "set-cookie":
                c = val.split(";", 1)[0]
                if "=" in c:
                    ck, cv = c.split("=", 1)
                    self.cookies[ck] = cv
            elif kl == "x-csrf-token":
                self.csrf = val
        raw = resp.read().decode("utf-8", "replace")
        return resp.status, raw

    def login_apikey(self, key):
        self.api_key = key

    def login_password(self, user, pw):
        """UniFi OS zuerst (/api/auth/login), dann klassisch (/api/login)."""
        for path in ("/api/auth/login", "/api/login"):
            try:
                status, _ = self._request("POST", path, {"username": user, "password": pw})
                if status in (200, 204):
                    return True
            except urllib.error.HTTPError as exc:
                if exc.code in (400, 401):
                    continue
            except (urllib.error.URLError, OSError):
                raise
        return False

    def fetch_alarms(self):
        """IPS/IDS-Alarme. UniFi OS: /proxy/network/api/s/<site>/stat/alarm,
        klassisch: /api/s/<site>/stat/alarm. Gibt die Liste der data-Objekte."""
        paths = (
            f"/proxy/network/api/s/{self.site}/stat/alarm",
            f"/api/s/{self.site}/stat/alarm",
        )
        for p in paths:
            try:
                status, raw = self._request("GET", p)
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403, 404):
                    continue
                raise
            if status == 200:
                try:
                    return json.loads(raw).get("data", [])
                except ValueError:
                    return []
        return []

    def fetch_system_log(self, category="all", pages=6, page_size=100):
        """UniFi-OS System-Log (POST, paginiert). Deckt alle geblockten Zugriffe
        ab (ext->int / ext->Gateway), nicht nur IPS. Gibt die Zeilen der ersten
        `pages` Seiten oder None, wenn der Endpunkt fehlt (klassischer Controller)."""
        path = f"/proxy/network/v2/api/site/{self.site}/system-log/{category}"
        rows = []
        for pg in range(pages):
            try:
                status, raw = self._request(
                    "POST", path, {"pageNumber": pg, "pageSize": page_size})
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    return None
                raise
            if status != 200:
                break
            try:
                data = json.loads(raw)
            except ValueError:
                break
            page = data.get("data", []) if isinstance(data, dict) else data
            if not isinstance(page, list):
                break
            rows.extend(page)
            if len(page) < page_size:
                break
        return rows


def alarm_to_event(a):
    """Unifi-Alarm -> (uid, event-dict) oder None. src_ip ist Pflicht."""
    ip = a.get("src_ip") or a.get("srcip") or a.get("srcIP")
    if not ip:
        return None
    uid = a.get("_id") or a.get("id")
    if not uid:
        return None
    sig = (a.get("inner_alert_signature") or a.get("signature")
           or a.get("catname") or a.get("key") or "")
    reason = "ips_alert" if sig else "fw_drop"
    ts = a.get("datetime") or a.get("timestamp") or a.get("time")
    return str(uid), {
        "uid": f"unifi:{uid}",
        "ts": ts if isinstance(ts, str) else None,
        "src_ip": str(ip),
        "app": "unifi",
        "reason": reason,
        "path": str(sig)[:200] if sig else None,
        "status_code": None,
    }


def syslog_to_event(row):
    """UniFi-OS-System-Log-Zeile (nur SECURITY) -> (uid, event) oder None.
    Erfasst jeden geblockten externen Zugriff; src_ip steckt in parameters.SRC_IP."""
    if row.get("category") != "SECURITY":
        return None
    params = row.get("parameters") or {}
    src = params.get("SRC_IP")
    ip = (src.get("name") or src.get("id")) if isinstance(src, dict) else src
    uid = row.get("id")
    if not ip or not uid:
        return None
    sub = row.get("subcategory") or ""
    reason = "ips_alert" if "INTRUSION" in sub else "fw_drop"
    sig = row.get("key") or sub
    ts = row.get("timestamp")
    if isinstance(ts, (int, float)):
        ts = datetime.datetime.utcfromtimestamp(ts / 1000.0).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        ts = None
    return str(uid), {
        "uid": f"unifi:{uid}",
        "ts": ts,
        "src_ip": str(ip),
        "app": "unifi",
        "reason": reason,
        "path": str(sig)[:200] if sig else None,
        "status_code": None,
    }


def ensure_token(cfg):
    """Firewall-Sensor-Token: aus Config, sonst selbst registrieren (kind=firewall)."""
    token = cfg["TOKEN"].strip()
    if token:
        return token, None
    name = cfg.get("NAME") or urllib.parse.urlparse(cfg["UNIFI_URL"]).hostname or "unifi"
    body = json.dumps({"host": name, "app": "unifi", "kind": "firewall"}).encode("utf-8")
    req = urllib.request.Request(
        cfg["INTAKE_URL"].rstrip("/") + "/agent/register", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["token"], data["sensor_id"]
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        log(f"Selbst-Registrierung fehlgeschlagen: {exc}")
        return None, None


def post_events(url, token, events):
    body = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/agent/events", data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.environ.get("UNIFI_CONFIG", "/etc/justdns-unifi.conf"))
    args = ap.parse_args()

    cfg = load_config(args.config)
    for req_key in ("INTAKE_URL", "UNIFI_URL"):
        if not cfg[req_key]:
            log(f"{req_key} erforderlich.")
            return 2
    if not cfg["UNIFI_API_KEY"] and not (cfg["UNIFI_USER"] and cfg["UNIFI_PASS"]):
        log("Auth fehlt: UNIFI_API_KEY ODER UNIFI_USER+UNIFI_PASS setzen.")
        return 2

    token, sid = ensure_token(cfg)
    if not token:
        return 1
    if sid:
        log(f"registriert als Firewall-Sensor {sid} (wartet auf Freigabe in der Zentrale)")

    ctx = None
    if cfg["VERIFY_TLS"] == "0":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    uni = Unifi(cfg["UNIFI_URL"], cfg["UNIFI_SITE"], cfg["VERIFY_TLS"], ctx)
    try:
        if cfg["UNIFI_API_KEY"]:
            uni.login_apikey(cfg["UNIFI_API_KEY"])
        elif not uni.login_password(cfg["UNIFI_USER"], cfg["UNIFI_PASS"]):
            log("Login am Controller fehlgeschlagen.")
            return 1
        sys_rows = uni.fetch_system_log("all")   # UniFi OS: alle Block-Logs
        alarms = uni.fetch_alarms()              # klassisch: IPS/IDS
    except (urllib.error.URLError, OSError) as exc:
        log(f"Controller nicht erreichbar: {exc}")
        return 1

    parsed = []
    for row in (sys_rows or []):
        p = syslog_to_event(row)
        if p is not None:
            parsed.append(p)
    for a in alarms:
        p = alarm_to_event(a)
        if p is not None:
            parsed.append(p)
    scanned = len(sys_rows or []) + len(alarms)

    state = load_state(cfg["STATE_FILE"])
    seen = set(state.get("seen_ids", []))
    events, new_ids, batch = [], [], set()
    for raw_id, ev in parsed:
        if raw_id in seen or raw_id in batch:
            continue
        batch.add(raw_id)
        events.append(ev)
        new_ids.append(raw_id)

    if not events:
        log(f"keine neuen Blocks (gescannt: {scanned})")
        return 0

    try:
        res = post_events(cfg["INTAKE_URL"], token, events)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"POST fehlgeschlagen: {exc} - Retry naechster Lauf")
        return 1

    # Nur nach erfolgreichem POST als gesehen merken (letzte 5000 behalten).
    seen.update(new_ids)
    state["seen_ids"] = list(seen)[-5000:]
    save_state(cfg["STATE_FILE"], state)
    log(f"gesendet: {len(events)} Block(s) (accepted={res.get('accepted')}, "
        f"duplicate={res.get('duplicate')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
