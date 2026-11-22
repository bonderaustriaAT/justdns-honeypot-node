#!/usr/bin/env python3
"""JustDNS node64-Reader (nur lesen).

Zieht aus der node64-REST-API (PROXY64/CDN64-Zugriffslog) die abgelehnten
Requests, extrahiert die Quell-IP und meldet sie als Sensor (kind='firewall')
an die Node (POST /agent/events). Die Node leitet unter ihrer Identitaet an die
Intake weiter; private Quell-IPs werden dort markiert und nie veroeffentlicht.

WICHTIG - keine Zirkularitaet: rejected_reason='blocklist' wird NICHT gemeldet.
Das sind Treffer gegen unsere eigene (und fremde) Blockliste - sie zurueck in die
Liste zu geben braechte nichts. Gemeldet werden nur die EIGENEN Policy-Blocks von
node64, die neue Intel liefern:
  exploit     -> waf_block   (WAF: Exploit-/Sensibler-Pfad-Versuch)   high
  honeypot    -> waf_block   (honeypot_instant_block hat die IP gebannt) high
  acl         -> http_403    (Access-List-Deny; Pfad/Volumen entscheidet im Review)
  rate_limit  -> http_429    (Rate-Ban; Volumen entscheidet)
Nichts wird automatisch gelistet - alles landet als Kandidat in der Review-Queue.

Auth: node64-API-Key (Settings > API keys, Prefix node64_) als Bearer-Token. Der
MCP-Key (mcp64_) wird von /api NICHT akzeptiert. Dedupe ueber die Log-Zeilen-id.
At-least-once ueber STATE_FILE (hoechste gesehene id). Nur Standardbibliothek.

Config (Env ODER Datei via --config, KEY=VALUE je Zeile):
  INTAKE_URL      Pflicht, Ziel (die Node, z.B. http://127.0.0.1:8090).
  TOKEN           Pflicht. Sensor-Token (UI oder Selbst-Registrierung).
  NODE64_URL      Pflicht, z.B. https://node64.lan oder http://192.168.20.x:8080
  NODE64_API_KEY  Pflicht, node64_...
  NODE64_LOG_PATH Optional. REST-Pfad des Zugriffslogs. Leer -> Kandidaten probieren.
  NAME            Anzeige-Name im Protokoll (Default NODE64_URL-Host).
  VERIFY_TLS      '1' (Default) prueft das Zertifikat, '0' nicht (selbstsigniert).
  PAGES           Seiten je Lauf (Default 20, je 100 Zeilen).
  STATE_FILE      Default /var/lib/justdns-firewall/node64-state.json
"""

import argparse
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
    "NODE64_URL": "",
    "NODE64_API_KEY": "",
    "NODE64_LOG_PATH": "",
    "NAME": "",
    "VERIFY_TLS": "1",
    "PAGES": "20",
    "STATE_FILE": "/var/lib/justdns-firewall/node64-state.json",
}

# Kandidaten-Pfade fuers Zugriffslog, falls NODE64_LOG_PATH nicht gesetzt ist.
LOG_PATH_CANDIDATES = (
    "/api/cdn64/access-log",
    "/api/cdn64/accesslog",
    "/api/cdn64/requests",
    "/api/proxy/access-log",
)

# node64-Grund -> (Agent-reason, status_code-Fallback). blocklist fehlt bewusst.
REASON_MAP = {
    "exploit": "waf_block",
    "honeypot": "waf_block",
    "acl": "http_403",
    "rate_limit": "http_429",
}


def log(msg):
    print(f"[node64] {msg}", file=sys.stderr)


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


class Node64:
    """Duenner Read-Client fuer die node64-REST-API."""

    def __init__(self, base, api_key, ctx):
        self.base = base.rstrip("/")
        self.api_key = api_key
        self.ctx = ctx

    def _get(self, path, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET", headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}"})
        resp = urllib.request.urlopen(req, timeout=20, context=self.ctx)
        return resp.status, resp.read().decode("utf-8", "replace")

    def resolve_log_path(self, override):
        """Den funktionierenden Log-Pfad finden: override zuerst, sonst Kandidaten.
        Ein Pfad gilt, wenn er 200 + ein Objekt mit 'rows' liefert."""
        for p in ([override] if override else list(LOG_PATH_CANDIDATES)):
            try:
                status, raw = self._get(p, {"status": "rejected", "limit": 1})
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    raise
                continue
            except (urllib.error.URLError, OSError):
                raise
            if status == 200:
                try:
                    if isinstance(json.loads(raw).get("rows"), list):
                        return p
                except (ValueError, AttributeError):
                    continue
        return None

    def fetch_rejected(self, path, pages, page_size, stop_after_id):
        """Abgelehnte Zeilen (neueste zuerst) holen, bis stop_after_id erreicht ist.
        Paging ueber 'next_before'. Gibt (rows, max_id)."""
        rows, max_id, before = [], stop_after_id, None
        for _ in range(max(1, pages)):
            params = {"status": "rejected", "limit": page_size}
            if before is not None:
                params["before"] = before
            status, raw = self._get(path, params)
            if status != 200:
                break
            try:
                data = json.loads(raw)
            except ValueError:
                break
            page = data.get("rows") or []
            if not page:
                break
            done = False
            for row in page:
                rid = row.get("id")
                if isinstance(rid, int) and rid > max_id:
                    max_id = rid
                if isinstance(rid, int) and rid <= stop_after_id:
                    done = True
                    continue
                rows.append(row)
            before = data.get("next_before")
            if done or before is None:
                break
        return rows, max_id


def row_to_event(row):
    """node64-Logzeile -> (id, event-dict) oder None. blocklist wird verworfen
    (Zirkularitaet). src_ip = client; Pfad/UA stehen in 'untrusted' (nur Daten)."""
    reason_raw = row.get("rejected_reason") or ""
    mapped = REASON_MAP.get(reason_raw)
    if mapped is None:                      # blocklist oder unbekannt -> raus
        return None
    ip = row.get("client")
    rid = row.get("id")
    if not ip or not isinstance(rid, int):
        return None
    unt = row.get("untrusted") or {}
    path = unt.get("path") if isinstance(unt, dict) else None
    status = row.get("status")
    status = status if isinstance(status, int) and 100 <= status <= 599 else None
    return rid, {
        "uid": f"node64:{rid}",
        "ts": row.get("time") if isinstance(row.get("time"), str) else None,
        "src_ip": str(ip),
        "app": "node64",
        "reason": mapped,
        "path": str(path)[:200] if path else None,
        "status_code": status,
    }


def ensure_token(cfg):
    """Sensor-Token: aus Config, sonst selbst an der Node registrieren."""
    token = cfg["TOKEN"].strip()
    if token:
        return token, None
    name = cfg.get("NAME") or urllib.parse.urlparse(cfg["NODE64_URL"]).hostname or "node64"
    body = json.dumps({"host": name, "app": "node64", "kind": "firewall"}).encode("utf-8")
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
    ap.add_argument("--config", default=os.environ.get("NODE64_CONFIG", "/etc/justdns-node64.conf"))
    args = ap.parse_args()

    cfg = load_config(args.config)
    if not cfg["NODE64_URL"] or not cfg["NODE64_API_KEY"]:
        log("node64 nicht angebunden (URL/API-Key fehlen) - nichts zu tun.")
        return 0
    if not cfg["INTAKE_URL"]:
        log("INTAKE_URL erforderlich.")
        return 2

    token, sid = ensure_token(cfg)
    if not token:
        return 1
    if sid:
        log(f"registriert als Sensor {sid} (wartet auf Freigabe in der Zentrale)")

    ctx = None
    if cfg["VERIFY_TLS"] == "0":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    n64 = Node64(cfg["NODE64_URL"], cfg["NODE64_API_KEY"], ctx)
    try:
        path = n64.resolve_log_path(cfg["NODE64_LOG_PATH"].strip())
    except urllib.error.HTTPError as exc:
        log(f"Auth am node64 fehlgeschlagen (HTTP {exc.code}) - API-Key pruefen.")
        return 1
    except (urllib.error.URLError, OSError) as exc:
        log(f"node64 nicht erreichbar: {exc}")
        return 1
    if not path:
        log("Zugriffslog-Endpunkt nicht gefunden - NODE64_LOG_PATH setzen.")
        return 2

    state = load_state(cfg["STATE_FILE"])
    last_id = int(state.get("last_id", 0))
    try:
        rows, max_id = n64.fetch_rejected(path, int(cfg["PAGES"]), 100, last_id)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"Log nicht lesbar: {exc}")
        return 1

    events, seen = [], set()
    for row in rows:
        parsed = row_to_event(row)
        if parsed is None:
            continue
        rid, ev = parsed
        if rid in seen:
            continue
        seen.add(rid)
        events.append(ev)

    if not events:
        log(f"keine neuen Policy-Blocks (gescannt: {len(rows)}, Pfad: {path})")
        if max_id > last_id:
            state["last_id"] = max_id
            save_state(cfg["STATE_FILE"], state)
        return 0

    try:
        res = post_events(cfg["INTAKE_URL"], token, events)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"POST fehlgeschlagen: {exc} - Retry naechster Lauf")
        return 1

    state["last_id"] = max_id
    save_state(cfg["STATE_FILE"], state)
    log(f"gesendet: {len(events)} Block(s) (accepted={res.get('accepted')}, "
        f"duplicate={res.get('duplicate')})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
