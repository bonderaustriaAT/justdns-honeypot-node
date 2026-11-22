#!/usr/bin/env python3
"""JustDNS Node-UI (lokal, fuer den Betreiber des Honeypots).

Kleine Live-Ansicht der Angriffe auf DEINEN eigenen Node. Liest dieselben
lokalen Logs wie der Shipper (cowrie.json + opencanary.log), parst die
Login-Versuche und zeigt sie als Liste inklusive der probierten Zugangsdaten
plus die aktivsten Quell-IPs. Nur Standardbibliothek, keine Abhaengigkeiten.

Default-Bind 0.0.0.0 -> aus dem internen Netz erreichbar unter der LAN-Adresse
des Nodes. WICHTIG: Die Seite zeigt Angreifer-Zugangsdaten. Im internen Netz
halten, nicht aus dem WAN weiterleiten. Soll sie doch von aussen erreichbar
sein, NODEUI_TOKEN setzen und einen Reverse-Proxy mit TLS davor haengen.

OOM-sicher: nur ein begrenzter Ring aktueller Events im Speicher (NODEUI_FEED),
die Quell-IP-Zaehler sind gedeckelt (NODEUI_MAX_IPS). Beim ersten Lesen wird
nur das Ende der Logs angetippt, nie die ganze Datei geladen.

Oberflaeche: SOC-Console (dark). KPI-Leiste, Live-Angriffe mit Status (Shell /
Probe), Shell-Aktivitaet als Terminal-Stream, Nachlade-Versuche und Top-Quellen.
Klick auf eine IP filtert alle Panels auf diese Quelle. Leer-Start gilt nur fuer
die Live View im Intake-Dashboard, nicht hier.

Config (Env):
  NODEUI_BIND   Default 0.0.0.0 (aus dem internen Netz erreichbar)
  NODEUI_PORT   Default 8090 (8080 ist ein Angreifer-Port des Web-Decoys)
  NODEUI_TOKEN  optional, Bearer-Token (leer = kein Token)
  COWRIE_LOG    Glob, Default /home/cowrie/cowrie/var/log/cowrie/cowrie.json*
  OC_LOG        Glob, Default /var/tmp/opencanary.log*
  WEBDECOY_LOG  Glob, Default /var/tmp/webdecoy.log*
  NODEUI_FEED   Groesse des Live-Rings, Default 500
  NODEUI_MAX_IPS Deckel der IP-Zaehler, Default 20000
"""

import collections
import datetime
import glob
import ipaddress
import json
import os
import re
import secrets
import ssl
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = os.environ.get("NODEUI_BIND", "0.0.0.0")
PORT = int(os.environ.get("NODEUI_PORT", "8090"))
TOKEN = os.environ.get("NODEUI_TOKEN", "")
COWRIE_LOG = os.environ.get("COWRIE_LOG", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*")
OC_LOG = os.environ.get("OC_LOG", "/var/tmp/opencanary.log*")
WEBDECOY_LOG = os.environ.get("WEBDECOY_LOG", "/var/tmp/webdecoy.log*")
FEED_MAX = int(os.environ.get("NODEUI_FEED", "500"))
MAX_IPS = int(os.environ.get("NODEUI_MAX_IPS", "20000"))
TAIL_BYTES = 256 * 1024   # beim ersten Lesen nur das Ende antippen
# Zentrale Intake, an die diese Node die gesammelten Meldungen weiterleitet.
INTAKE_URL = os.environ.get("NODEUI_INTAKE_URL", "https://intake.justdns.justfuture.at").rstrip("/")
# Ausgelieferte Sensor-Dateien (install.sh, agent.py, unifi_reader.py).
DIST = os.environ.get("NODEUI_DIST", "/opt/justdns-nodeui/dist")
# Firewall-Direktanbindung: von der Node selbst abgefragt. Config liegt in einem
# fuer den nodeui-Benutzer schreibbaren Verzeichnis (kein root zur Laufzeit noetig);
# der periodische Timer wird einmal beim Deploy eingerichtet.
FW_DIR = os.environ.get("NODEUI_FW_DIR", "/var/lib/justdns-firewall")
UNIFI_CONFIG = os.environ.get("NODEUI_UNIFI_CONFIG", os.path.join(FW_DIR, "unifi.conf"))
UNIFI_READER = os.environ.get("NODEUI_UNIFI_READER", "/opt/justdns-firewall/unifi_reader.py")
FW_STATE = os.environ.get("NODEUI_FW_STATE", os.path.join(FW_DIR, "connect.json"))
# node64-Direktanbindung (PROXY64/CDN64-Zugriffslog, nur lesen): gleiche Mechanik
# wie die Firewall - Config im nodeui-schreibbaren Verzeichnis, Timer beim Deploy.
NODE64_CONFIG = os.environ.get("NODEUI_NODE64_CONFIG", os.path.join(FW_DIR, "node64.conf"))
NODE64_READER = os.environ.get("NODEUI_NODE64_READER", "/opt/justdns-firewall/node64_reader.py")
NODE64_STATE = os.environ.get("NODEUI_NODE64_STATE", os.path.join(FW_DIR, "node64-connect.json"))
# Identitaet DIESER Honeypot-Node an der Intake (aus der Shipper-Config): Agents und
# Firewall melden lokal an die Node, ihre IPs gehen unter dieser Node-Identitaet raus.
SHIPPER_CONFIG = os.environ.get("NODEUI_SHIPPER_CONFIG", "/etc/justdns-shipper.conf")

COWRIE_FAILED = "cowrie.login.failed"
COWRIE_SUCCESS = "cowrie.login.success"
COWRIE_LOGIN = (COWRIE_FAILED, COWRIE_SUCCESS)
PORT_SVC = {21: "FTP", 23: "TELNET", 80: "HTTP", 3306: "MYSQL",
            3389: "RDP", 5900: "VNC", 2222: "SSH", 22: "SSH"}


def parse_cowrie(line):
    try:
        e = json.loads(line)
    except ValueError:
        return None
    eid = e.get("eventid")
    if eid not in COWRIE_LOGIN:
        return None
    ip = e.get("src_ip")
    if not ip:
        return None
    svc = "TELNET" if e.get("protocol") == "telnet" else "SSH"
    return {"ts": e.get("timestamp"), "src_ip": ip, "service": svc,
            "dst_port": e.get("dst_port"), "username": e.get("username", ""),
            "password": e.get("password", ""),
            "outcome": "ok" if eid == COWRIE_SUCCESS else "fail"}


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
    return {"ts": e.get("utc_time"), "src_ip": ip,
            "service": PORT_SVC.get(port, str(port) if port is not None else None),
            "dst_port": port, "username": d.get("USERNAME", ""),
            "password": d.get("PASSWORD", "")}


def parse_webdecoy(line):
    try:
        e = json.loads(line)
    except ValueError:
        return None
    ip = e.get("src_ip")
    if not ip:
        return None
    return {"ts": e.get("ts"), "src_ip": ip, "service": e.get("service") or "HTTP",
            "dst_port": e.get("dst_port"), "username": e.get("username", ""),
            "password": e.get("password", "")}


_NL_URL = re.compile(r"(?:https?|ftps?|tftp)://[^\s'\"`;|&>)<]+", re.I)
_NL_DLCMD = re.compile(r"\b(?:wget|curl|tftp|ftpget|lwp-download|fetch)\b", re.I)


def _nl_host(u):
    rest = u.split("://", 1)[-1]
    auth = rest.split("/", 1)[0].split("@")[-1].split("?")[0].split("#")[0]
    if auth.startswith("["):
        return None
    h = auth.split(":")[0].strip().strip(".").lower()
    return h or None


def _nl_is_domain(h):
    if not h or "." not in h:
        return False
    try:
        ipaddress.ip_address(h)
        return False
    except ValueError:
        return True


def parse_cowrie_nachlade(line):
    """Nachlade-Versuche (wget/curl/Download) aus einer Cowrie-Zeile:
    {ts, src_ip, kind, command, domains}. Zeigt, was der Angreifer ziehen wuerde."""
    try:
        e = json.loads(line)
    except ValueError:
        return None
    eid = e.get("eventid")
    ip = e.get("src_ip")
    ts = e.get("timestamp")
    if not ip:
        return None
    if eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        u = e.get("url") or ""
        if not u:
            return None
        h = _nl_host(u)
        return {"ts": ts, "src_ip": ip, "kind": "download", "command": u[:400],
                "domains": [h] if _nl_is_domain(h) else []}
    if eid == "cowrie.command.input":
        inp = e.get("input") or ""
        if not (_NL_URL.search(inp) or _NL_DLCMD.search(inp)):
            return None
        doms = []
        for u in _NL_URL.findall(inp):
            h = _nl_host(u)
            if _nl_is_domain(h) and h not in doms:
                doms.append(h)
        return {"ts": ts, "src_ip": ip, "kind": "cmd", "command": inp[:400], "domains": doms}
    return None


def parse_cowrie_shell(line):
    """Alles was ein eingeloggter Angreifer tippt: jede cowrie.command.input-Zeile.
    {ts, src_ip, proto, command}. Zeigt die komplette Shell-Aktivitaet nach Login."""
    try:
        e = json.loads(line)
    except ValueError:
        return None
    if e.get("eventid") != "cowrie.command.input":
        return None
    ip = e.get("src_ip")
    inp = e.get("input")
    if not ip or not inp:
        return None
    proto = "TELNET" if e.get("protocol") == "telnet" else "SSH"
    return {"ts": e.get("timestamp"), "src_ip": ip, "proto": proto, "command": inp[:600]}


class State:
    """Geteilter Zustand, unter einem Lock aktualisiert."""

    def __init__(self):
        self.lock = threading.Lock()
        self.offsets = {}                         # tag:path -> byte-offset
        self.feed = collections.deque(maxlen=FEED_MAX)
        self.nachlade = collections.deque(maxlen=200)   # Download-/wget-Versuche
        self.shell = collections.deque(maxlen=400)      # alle Shell-Eingaben nach Login
        self.ip_counts = {}                       # ip -> [count, last_ts]
        self.events_total = 0
        self.since = None

    def _read_file(self, fpath, parser, sink, tag):
        key = tag + ":" + fpath
        try:
            size = os.path.getsize(fpath)
        except OSError:
            return
        first = key not in self.offsets
        # Erstes Lesen: nur das Ende antippen (lean, keine Riesendatei laden).
        offset = self.offsets.get(key, max(0, size - TAIL_BYTES))
        if size < offset:        # Rotation/Truncation -> von vorne, ohne Ausrichten
            offset, first = 0, False
        if size == offset:
            self.offsets[key] = offset
            return
        try:
            with open(fpath, "rb") as fh:
                fh.seek(offset)
                if first and offset > 0:
                    fh.readline()            # nur beim Antippen mitten in der Datei ausrichten
                    offset = fh.tell()
                for raw in fh:
                    if not raw.endswith(b"\n"):
                        break               # unvollstaendige letzte Zeile: spaeter
                    text = raw.decode("utf-8", "replace").strip()
                    offset = fh.tell()
                    if not text:
                        continue
                    ev = parser(text)
                    if ev is not None:
                        sink(ev)
            self.offsets[key] = offset
        except OSError:
            return

    def _add_nachlade(self, ev):
        self.nachlade.append(ev)

    def _add_shell(self, ev):
        self.shell.append(ev)

    def _add(self, ev):
        self.events_total += 1
        ev["seq"] = self.events_total     # monotone Sequenz, fuer "nur neue ab Oeffnen"
        self.feed.append(ev)
        if self.since is None and ev.get("ts"):
            self.since = ev["ts"]
        ip = ev["src_ip"]
        c = self.ip_counts.get(ip)
        if c is None:
            if len(self.ip_counts) >= MAX_IPS:
                return                       # Deckel: keine neuen IPs mehr zaehlen
            self.ip_counts[ip] = [1, ev.get("ts")]
        else:
            c[0] += 1
            c[1] = ev.get("ts") or c[1]

    def poll(self):
        with self.lock:
            for pattern, parser in ((COWRIE_LOG, parse_cowrie), (OC_LOG, parse_opencanary),
                                    (WEBDECOY_LOG, parse_webdecoy)):
                for fpath in sorted(glob.glob(pattern)):
                    self._read_file(fpath, parser, self._add, "atk")
            for fpath in sorted(glob.glob(COWRIE_LOG)):
                self._read_file(fpath, parse_cowrie_nachlade, self._add_nachlade, "nl")
            for fpath in sorted(glob.glob(COWRIE_LOG)):
                self._read_file(fpath, parse_cowrie_shell, self._add_shell, "sh")
            top = sorted(self.ip_counts.items(), key=lambda kv: kv[1][0], reverse=True)[:20]
            return {
                "since": self.since,
                "events_total": self.events_total,
                "ips_total": len(self.ip_counts),
                "ips_capped": len(self.ip_counts) >= MAX_IPS,
                "feed": list(self.feed)[-200:][::-1],   # neueste zuerst
                "nachlade": list(self.nachlade)[-100:][::-1],
                "shell": list(self.shell)[-150:][::-1],
                "top": [{"ip": ip, "count": v[0], "last_ts": v[1]} for ip, v in top],
            }


STATE = State()


def _http(url, data=None, headers=None, method=None, timeout=20, ctx=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.status, resp.read()


_NODE = {"url": INTAKE_URL, "token": os.environ.get("NODEUI_NODE_TOKEN", "")}


def node_target():
    """Intake-URL + Node-Token (own-honeypot-131) aus der Shipper-Config. Agent-
    und Firewall-IPs melden unter DIESER Honeypot-Node-Identitaet, nicht einzeln."""
    if _NODE["token"]:
        return _NODE["url"], _NODE["token"]
    try:
        with open(SHIPPER_CONFIG, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "TOKEN":
                    _NODE["token"] = v
                elif k == "INTAKE_URL":
                    _NODE["url"] = v.rstrip("/")
    except OSError:
        pass
    return _NODE["url"], _NODE["token"]


def forward_events(events):
    """Gesammelte Agent-/Firewall-IPs unter der Node-Identitaet an die Intake melden."""
    url, token = node_target()
    if not token:
        raise OSError("kein Node-Token (Shipper-Config fehlt)")
    body = json.dumps({"events": events}).encode("utf-8")
    return _http(url + "/agent/events", data=body, method="POST",
                 headers={"Content-Type": "application/json",
                          "Authorization": f"Bearer {token}"})


def mint_local(host, app, kind):
    """Lokales Sensor-Token: der Sensor gehoert zur Node, nicht zur Intake."""
    base = (app or kind or "sensor")[:12]
    return {"sensor_id": f"{base}-{secrets.token_hex(4)}",
            "token": "loc_" + secrets.token_hex(16)}


def register_firewall(name, app="unifi"):
    """Firewall-Sensor LOKAL anlegen (kein Intake-Sensor); Token + ID zurueck."""
    reg = mint_local(name, app, "firewall")
    return reg["token"], reg["sensor_id"]


def controller_probe(url, site, key, verify):
    """System-Log des Controllers einmal antippen: prueft Erreichbarkeit + Key."""
    ctx = None
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    probe = f"{url}/proxy/network/v2/api/site/{site}/system-log/all"
    body = json.dumps({"pageNumber": 0, "pageSize": 1}).encode("utf-8")
    _http(probe, data=body, method="POST", ctx=ctx,
          headers={"Content-Type": "application/json", "Accept": "application/json",
                   "X-API-KEY": key})


def _now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


class SensorLog:
    """Protokoll der an dieser Node angebundenen Agents/Firewalls und ihrer
    Meldungen. Schreibt mit, was die Node an die Intake weiterreicht. Begrenzt
    (OOM-sicher); die Sensor-Liste wird fuer Neustarts persistiert."""

    def __init__(self, path):
        self.lock = threading.Lock()
        self.path = path
        self.sensors = {}                        # sensor_id -> info
        self.by_token = {}                       # token -> sensor_id
        self.feed = collections.deque(maxlen=500)
        self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            self.sensors = d.get("sensors", {})
            self.by_token = d.get("by_token", {})
        except (OSError, ValueError):
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"sensors": self.sensors, "by_token": self.by_token}, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def register(self, req, resp):
        sid = resp.get("sensor_id")
        if not sid:
            return
        now = _now()
        with self.lock:
            s = self.sensors.get(sid) or {"sensor_id": sid, "first_ts": now, "count": 0}
            s["kind"] = req.get("kind") or s.get("kind") or "agent"
            s["app"] = req.get("app") or s.get("app") or ""
            s["host"] = req.get("host") or s.get("host") or ""
            s["last_ts"] = now
            self.sensors[sid] = s
            tok = resp.get("token")
            if tok:
                self.by_token[tok] = sid
            if len(self.sensors) > 500:
                old = min(self.sensors.values(), key=lambda x: x.get("last_ts", ""))
                self.sensors.pop(old["sensor_id"], None)
            self._save()

    def events(self, token, events):
        if not events:
            return
        now = _now()
        with self.lock:
            sid = self.by_token.get(token or "")
            s = self.sensors.get(sid) if sid else None
            label = (s.get("host") or s.get("app")) if s else "?"
            kind = s.get("kind") if s else "agent"
            for ev in events:
                self.feed.append({"ts": ev.get("ts") or now, "sensor": label, "kind": kind,
                                  "src_ip": ev.get("src_ip"), "reason": ev.get("reason"),
                                  "app": ev.get("app")})
            if s:
                s["last_ts"] = now
                s["count"] = s.get("count", 0) + len(events)
                self._save()

    def remove(self, sid):
        """Sensor manuell aus dem Protokoll loeschen: Eintrag + zugehoerige Tokens
        raus. Die Feed-Historie bleibt (laeuft von selbst aus dem Ringpuffer)."""
        with self.lock:
            if sid not in self.sensors:
                return False
            self.sensors.pop(sid, None)
            for tok in [t for t, s in self.by_token.items() if s == sid]:
                self.by_token.pop(tok, None)
            self._save()
            return True

    def view(self):
        with self.lock:
            sensors = sorted(self.sensors.values(),
                             key=lambda x: x.get("last_ts", ""), reverse=True)
            return {"sensors": sensors, "feed": list(self.feed)[-200:][::-1]}


SENSORS = SensorLog(os.path.join(FW_DIR, "sensors.json"))


def teardown_firewall(sid):
    """Gehoert die geloeschte Sensor-ID zu einer Firewall-/node64-Direktanbindung,
    deren Config + Status entfernen, damit der Timer nichts mehr abfragt."""
    pairs = (
        (UNIFI_CONFIG, FW_STATE, os.path.join(FW_DIR, "unifi-state.json")),
        (NODE64_CONFIG, NODE64_STATE, os.path.join(FW_DIR, "node64-state.json")),
    )
    removed = False
    for conf, state, reader_state in pairs:
        try:
            with open(state, encoding="utf-8") as fh:
                if json.load(fh).get("sensor_id") != sid:
                    continue
        except (OSError, ValueError):
            continue
        for fpath in (conf, state, reader_state):
            try:
                os.remove(fpath)
            except OSError:
                pass
        removed = True
    return removed


class Handler(BaseHTTPRequestHandler):
    server_version = "justdns-nodeui"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _auth_ok(self):
        if not TOKEN:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {TOKEN}"

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth_ok():
            self._send(401, {"error": "unauthorized"})
            return
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, ctype="text/html; charset=utf-8")
            return
        if path == "/setup":
            self._send(200, SETUP_HTML, ctype="text/html; charset=utf-8")
            return
        if path == "/sensors":
            self._send(200, SENSORS_HTML, ctype="text/html; charset=utf-8")
            return
        if path == "/api/sensors":
            self._send(200, SENSORS.view())
            return
        if path == "/agent/install":
            self._serve_asset("install.sh", rewrite=True,
                              ctype="text/x-shellscript; charset=utf-8")
            return
        if path == "/agent/agent.py":
            self._serve_asset("justdns-agent.py", ctype="text/x-python; charset=utf-8")
            return
        if path == "/api/overview":
            self._send(200, STATE.poll())
            return
        if path == "/api/firewall/status":
            self._send(200, self._fw_status())
            return
        if path == "/api/node64/status":
            self._send(200, self._n64_status())
            return
        if path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        if not self._auth_ok():
            self._send(401, {"error": "unauthorized"})
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/agent/register":
            self._agent_register()
            return
        if path == "/agent/events":
            self._agent_events()
            return
        if path == "/api/firewall/connect":
            self._fw_connect()
            return
        if path == "/api/node64/connect":
            self._n64_connect()
            return
        if path == "/api/sensors/remove":
            self._sensor_remove()
            return
        self._send(404, {"error": "not_found"})

    # -- Assets + Relay + Firewall ------------------------------------------

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = 0
        return self.rfile.read(n) if n > 0 else b""

    def _node_base(self):
        host = self.headers.get("Host") or f"127.0.0.1:{PORT}"
        return "http://" + host

    def _serve_asset(self, fname, rewrite=False, ctype="application/octet-stream"):
        try:
            with open(os.path.join(DIST, fname), encoding="utf-8") as fh:
                txt = fh.read()
        except OSError:
            self._send(404, {"error": "asset_not_found", "file": fname})
            return
        if rewrite:
            # Agents laden von DIESER Node und melden an DIESE Node.
            txt = txt.replace("https://intake.justdns.justfuture.at", self._node_base())
        self._send(200, txt, ctype=ctype)

    def _agent_register(self):
        """Agent/Firewall LOKAL registrieren: der Sensor gehoert zur Node, nicht
        zur Intake. Node vergibt Token selbst, kein Intake-Sensor pro Agent."""
        try:
            d = json.loads(self._body() or b"{}")
        except ValueError:
            d = {}
        reg = mint_local(d.get("host", ""), d.get("app", ""), d.get("kind", "agent"))
        SENSORS.register(d, reg)
        self._send(200, {"token": reg["token"], "sensor_id": reg["sensor_id"],
                         "status": "local"})

    def _agent_events(self):
        """Meldung lokal protokollieren und die IPs unter der Node-Identitaet
        (own-honeypot-131) an die zentrale Intake weiterleiten."""
        body = self._body()
        auth = self.headers.get("Authorization", "")
        tok = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            events = json.loads(body or b"{}").get("events", [])
        except ValueError:
            events = []
        SENSORS.events(tok, events)
        try:
            status, raw = forward_events(events)
            self._send(status, raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            self._send(exc.code, exc.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError) as exc:
            self._send(502, {"error": "intake_unreachable", "detail": str(exc)[:200]})

    def _fw_status(self):
        info = {"connected": os.path.exists(UNIFI_CONFIG)}
        try:
            with open(FW_STATE, encoding="utf-8") as fh:
                info.update(json.load(fh))
        except (OSError, ValueError):
            pass
        return info

    def _fw_connect(self):
        try:
            d = json.loads(self._body() or b"{}")
        except ValueError:
            self._send(400, {"ok": False, "message": "Ungueltige Anfrage."})
            return
        url = (d.get("unifi_url") or "").strip().rstrip("/")
        site = (d.get("site") or "default").strip() or "default"
        key = (d.get("api_key") or "").strip()
        verify = bool(d.get("verify_tls", True))
        if not url or not key:
            self._send(400, {"ok": False, "message": "Controller-URL und API-Key noetig."})
            return
        try:
            controller_probe(url, site, key, verify)
        except urllib.error.HTTPError as exc:
            auth = exc.code in (401, 403)
            msg = "API-Key abgelehnt." if auth else f"Controller antwortet mit {exc.code}."
            self._send(200, {"ok": False, "message": msg})
            return
        except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
            self._send(200, {"ok": False,
                             "message": f"Controller nicht erreichbar: {str(exc)[:160]}"})
            return
        name = urllib.parse.urlparse(url).hostname or "unifi"
        try:
            token, sid = register_firewall(name)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self._send(200, {"ok": False,
                             "message": f"Anmeldung an der Intake fehlgeschlagen: {str(exc)[:160]}"})
            return
        if not token:
            self._send(200, {"ok": False, "message": "Intake lieferte kein Token."})
            return
        SENSORS.register({"host": name, "app": "unifi", "kind": "firewall"},
                         {"token": token, "sensor_id": sid})
        try:
            detail = self._fw_install(url, site, key, verify, name, token, sid)
        except (OSError, subprocess.SubprocessError) as exc:
            self._send(200, {"ok": False, "message": f"Einrichtung fehlgeschlagen: {str(exc)[:200]}"})
            return
        msg = ("Firewall verbunden. Block-Logs werden jede Minute abgeholt und an die "
               "Intake gemeldet.")
        if detail:
            msg += " " + detail
        self._send(200, {"ok": True, "sensor_id": sid, "controller": url, "site": site,
                         "message": msg})

    def _fw_install(self, url, site, key, verify, name, token, sid):
        """Config schreiben und den Reader einmal sofort laufen lassen. Kein root:
        der periodische Timer (als nodeui-Benutzer) ist beim Deploy eingerichtet."""
        state_file = os.path.join(FW_DIR, "unifi-state.json")
        os.makedirs(FW_DIR, exist_ok=True)
        conf = (
            f"INTAKE_URL=http://127.0.0.1:{PORT}\n"
            f"TOKEN={token}\n"
            f"UNIFI_URL={url}\n"
            f"UNIFI_API_KEY={key}\n"
            "UNIFI_USER=\nUNIFI_PASS=\n"
            f"UNIFI_SITE={site}\n"
            f"VERIFY_TLS={'1' if verify else '0'}\n"
            f"NAME={name}\n"
            f"STATE_FILE={state_file}\n"
            "LOOKBACK_MIN=60\n"
        )
        fd = os.open(UNIFI_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(conf)
        with open(FW_STATE, "w", encoding="utf-8") as fh:
            json.dump({"controller": url, "site": site, "sensor_id": sid,
                       "verify_tls": verify,
                       "connected_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}, fh)
        detail = ""
        if os.path.exists(UNIFI_READER):
            env = dict(os.environ, UNIFI_CONFIG=UNIFI_CONFIG)
            try:
                run = subprocess.run(["/usr/bin/python3", UNIFI_READER], env=env,
                                     capture_output=True, text=True, timeout=90)
                lines = [ln for ln in (run.stderr or "").splitlines() if ln.strip()]
                if lines:
                    detail = lines[-1].replace("[unifi] ", "")
            except subprocess.SubprocessError as exc:
                detail = str(exc)[:160]
        return detail

    def _n64_status(self):
        info = {"connected": os.path.exists(NODE64_CONFIG)}
        try:
            with open(NODE64_STATE, encoding="utf-8") as fh:
                info.update(json.load(fh))
        except (OSError, ValueError):
            pass
        return info

    def _n64_connect(self):
        try:
            d = json.loads(self._body() or b"{}")
        except ValueError:
            self._send(400, {"ok": False, "message": "Ungueltige Anfrage."})
            return
        url = (d.get("node64_url") or "").strip().rstrip("/")
        key = (d.get("api_key") or "").strip()
        verify = bool(d.get("verify_tls", True))
        log_path = (d.get("log_path") or "").strip()
        if not url or not key:
            self._send(400, {"ok": False, "message": "node64-URL und API-Key noetig."})
            return
        name = urllib.parse.urlparse(url).hostname or "node64"
        try:
            token, sid = register_firewall(name, app="node64")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self._send(200, {"ok": False,
                             "message": f"Anmeldung an der Intake fehlgeschlagen: {str(exc)[:160]}"})
            return
        if not token:
            self._send(200, {"ok": False, "message": "Intake lieferte kein Token."})
            return
        SENSORS.register({"host": name, "app": "node64", "kind": "firewall"},
                         {"token": token, "sensor_id": sid})
        try:
            detail = self._n64_install(url, key, verify, log_path, name, token, sid)
        except (OSError, subprocess.SubprocessError) as exc:
            self._send(200, {"ok": False, "message": f"Einrichtung fehlgeschlagen: {str(exc)[:200]}"})
            return
        # Der Reader meldet im Fehlerfall klartext (Auth/Endpunkt). Das als Status zeigen.
        low = (detail or "").lower()
        if "fehlgeschlagen" in low or "nicht gefunden" in low or "nicht erreichbar" in low:
            self._send(200, {"ok": False, "message": detail or "node64 nicht erreichbar."})
            return
        msg = "node64 verbunden. Policy-Blocks (ohne Blocklist) gehen jede Minute in die Review-Queue."
        if detail:
            msg += " " + detail
        self._send(200, {"ok": True, "sensor_id": sid, "node64": url, "message": msg})

    def _n64_install(self, url, key, verify, log_path, name, token, sid):
        """Config schreiben und den Reader einmal sofort laufen lassen (kein root)."""
        state_file = os.path.join(FW_DIR, "node64-state.json")
        os.makedirs(FW_DIR, exist_ok=True)
        conf = (
            f"INTAKE_URL=http://127.0.0.1:{PORT}\n"
            f"TOKEN={token}\n"
            f"NODE64_URL={url}\n"
            f"NODE64_API_KEY={key}\n"
            f"NODE64_LOG_PATH={log_path}\n"
            f"VERIFY_TLS={'1' if verify else '0'}\n"
            f"NAME={name}\n"
            f"STATE_FILE={state_file}\n"
            "PAGES=20\n"
        )
        fd = os.open(NODE64_CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(conf)
        with open(NODE64_STATE, "w", encoding="utf-8") as fh:
            json.dump({"node64": url, "sensor_id": sid, "verify_tls": verify,
                       "connected_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")}, fh)
        detail = ""
        if os.path.exists(NODE64_READER):
            env = dict(os.environ, NODE64_CONFIG=NODE64_CONFIG)
            try:
                run = subprocess.run(["/usr/bin/python3", NODE64_READER], env=env,
                                     capture_output=True, text=True, timeout=90)
                lines = [ln for ln in (run.stderr or "").splitlines() if ln.strip()]
                if lines:
                    detail = lines[-1].replace("[node64] ", "")
            except subprocess.SubprocessError as exc:
                detail = str(exc)[:160]
        return detail

    def _sensor_remove(self):
        """Sensor aus dem Protokoll loeschen. Bei einer Firewall-/node64-Direkt-
        anbindung zusaetzlich deren Config + Status abschalten."""
        try:
            d = json.loads(self._body() or b"{}")
        except ValueError:
            self._send(400, {"ok": False, "message": "Ungueltige Anfrage."})
            return
        sid = (d.get("sensor_id") or "").strip()
        if not sid:
            self._send(400, {"ok": False, "message": "Sensor-ID fehlt."})
            return
        ok = SENSORS.remove(sid)
        fw = teardown_firewall(sid)
        if not ok and not fw:
            self._send(404, {"ok": False, "message": "Sensor nicht gefunden."})
            return
        msg = "Sensor entfernt."
        if fw:
            msg += " Direktanbindung abgeschaltet, der Timer fragt nichts mehr ab."
        self._send(200, {"ok": True, "message": msg})


INDEX_HTML = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JustDNS Honeypot Node</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0d12; --panel:#10151d; --panel2:#0d1219; --line:#1e2733; --line2:#2a3542;
  --ink:#dfe6ef; --mut:#8695a8; --dim:#7e8ca0;
  --red:#ff5d6c; --redbg:#2a1217; --amber:#f5b445; --amberbg:#2a2111; --green:#5fdd97; --greenbg:#102418; --blue:#6cc7ff;
  --mono:"IBM Plex Mono",ui-monospace,monospace; --sans:"IBM Plex Sans",system-ui,sans-serif;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--ink);font:14px/1.45 var(--sans);display:flex;flex-direction:column;overflow:hidden}
::selection{background:#24415a;color:#fff}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:#223040;border-radius:6px}::-webkit-scrollbar-thumb:hover{background:#2c3e50}::-webkit-scrollbar-track{background:transparent}
a,button{color:inherit}
:focus-visible{outline:2px solid var(--blue);outline-offset:2px;border-radius:4px}
.tnum{font-variant-numeric:tabular-nums}
.mono{font-family:var(--mono)}
/* brand + status im Topbar */
.brand{display:flex;align-items:center;gap:9px;flex:0 0 auto}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px var(--greenbg);flex:0 0 auto}
.brand b{font-size:15px;letter-spacing:-.01em}.brand span{color:var(--dim);font:12px/1.2 var(--mono);display:block}
.status{color:var(--dim);font:12px/1.5 var(--mono);flex:0 0 auto;padding-left:16px;border-left:1px solid var(--line)}
.status b{color:var(--green);font-weight:500}
.navlink{flex:0 0 auto;color:var(--blue);font:12px/1 var(--mono);text-decoration:none;padding:7px 11px;border:1px solid var(--line2);border-radius:8px;background:var(--panel)}
.navlink:hover{border-color:var(--blue)}
/* main */
main{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden}
.top{display:flex;align-items:center;gap:16px;padding:12px 20px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#0e141c,#0a0d12)}
.kpi{display:flex;gap:10px;margin-left:auto;flex-wrap:wrap}
.k{min-width:96px;padding:7px 12px;border:1px solid var(--line);border-radius:9px;background:var(--panel)}
.k .n{font:600 20px/1 var(--mono);letter-spacing:-.02em}.k .l{color:var(--mut);font-size:12px;margin-top:3px;text-transform:uppercase;letter-spacing:.06em}
.k.red .n{color:var(--red)}.k.amber .n{color:var(--amber)}.k.green .n{color:var(--green)}
.grid{flex:1;display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr);grid-template-rows:minmax(0,1.5fr) minmax(0,1fr);gap:12px;padding:12px 20px 20px;min-height:0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column;min-height:0;overflow:hidden}
.ch{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--line);flex:0 0 auto}
.ch h2{font-size:12px;letter-spacing:.07em;text-transform:uppercase;color:var(--mut);margin:0;font-weight:600}
.ch .sub{color:var(--dim);font:12px/1 var(--mono)}
.ch .live{margin-left:auto;display:flex;align-items:center;gap:6px;color:var(--green);font:12px/1 var(--mono)}
.ch .live i{width:6px;height:6px;border-radius:50%;background:var(--green);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.scroll{overflow:auto;min-height:0}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{position:sticky;top:0;background:#0f1620;color:var(--dim);text-align:left;font-weight:600;font-size:12px;letter-spacing:.05em;text-transform:uppercase;padding:7px 14px;border-bottom:1px solid var(--line);z-index:1}
tbody td{padding:7px 14px;border-bottom:1px solid #161e28;white-space:nowrap;vertical-align:top}
tbody tr:hover td{background:#121a24}
.ip{color:var(--blue);font-family:var(--mono);cursor:pointer}
.ip:hover{text-decoration:underline}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;font:500 12px/1.5 var(--mono)}
.tag.ssh{background:#10263a;color:#7fc5ff}.tag.tel{background:#2a1f33;color:#d39bff}
.tag.http{background:#13303a;color:#7fe0de}.tag.oth{background:#1d2530;color:var(--mut)}
.st{display:inline-flex;align-items:center;gap:6px;font-size:12px}
.st i{width:7px;height:7px;border-radius:50%;flex:0 0 auto}
.st.breach i{background:var(--red);box-shadow:0 0 0 3px var(--redbg)}.st.breach{color:var(--red)}
.st.probe i{background:var(--amber)}.st.probe{color:var(--amber)}
.cred{color:var(--ink);font-family:var(--mono)}.cred .pw{color:var(--mut)}
.muted{color:var(--dim)}
/* shell terminal */
.term{background:#070a0e;font-family:var(--mono);font-size:13px;line-height:1.7;padding:10px 14px;overflow:auto;min-height:0}
.term .ln{display:flex;gap:10px;white-space:pre-wrap;word-break:break-all}
.term .t{color:var(--dim);flex:0 0 auto}.term .who{color:var(--blue)}.term .pr{color:var(--green);flex:0 0 auto}.term .cmd{color:#e7edf4}
.term .cmd .bb{color:var(--amber)}.term .cmd .dl{color:var(--red)}
.term .cursor{display:inline-block;width:7px;height:14px;background:var(--green);vertical-align:-2px;animation:pulse 1.1s steps(2) infinite}
.dom{display:inline-block;padding:0 6px;border-radius:6px;background:var(--amberbg);color:var(--amber);font-family:var(--mono);font-size:12px;margin:1px 4px 1px 0}
td.cmd{white-space:pre-wrap;word-break:break-all;color:#c9d1dc;font-family:var(--mono);max-width:560px}
td.cmd .bb{color:var(--amber)}td.cmd .dl{color:var(--red)}
/* bars */
.bars{padding:12px 14px;display:flex;flex-direction:column;gap:12px;overflow:auto;min-height:0}
.brow .hd{display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px}
.brow .hd .c{font-family:var(--mono);color:var(--mut)}
.bar{height:6px;border-radius:4px;background:#17202b;overflow:hidden}.bar i{display:block;height:100%;background:linear-gradient(90deg,#ff5d6c,#f5b445)}
.chip{font:500 12px/1 var(--mono);color:var(--amber);background:var(--amberbg);border:1px solid #3a2e14;border-radius:999px;padding:4px 9px;display:inline-flex;align-items:center;gap:7px;cursor:pointer}
.chip b{color:var(--ink);font-weight:500}.chip .x{color:var(--mut)}
.empty{padding:22px 14px;color:var(--dim);font-size:13px}
@media(max-width:1100px){.grid{grid-template-columns:1fr;grid-auto-rows:minmax(220px,38vh);grid-template-rows:none}}
@media(max-width:860px){.status{display:none}}
@media(max-width:720px){.top{flex-wrap:wrap}.kpi{margin-left:0;width:100%}.kpi .l{display:none}.k{flex:1;min-width:0;padding:6px 10px}}
</style></head>
<body>
<!-- DIRECTION A: SOC CONSOLE (impeccable, operate mode)
 THESIS: a security operations console; every attacker event prioritized and status-coded so the operator scans, not reads. Refuses the four-equal-tables scroll of the old page.
 OWN-WORLD: near-black cockpit, cool slate panels, one signal palette (red Shell / amber Probe / green listed), IBM Plex Sans + Plex Mono for all data, hairline grid, sticky heads, themed scrollbars + selection.
 STORY: operator scans the KPI rail, sees who breached, drills the live shell stream, clicks any IP to filter every panel to one source.
 FIRST VIEWPORT: top bar = brand + status + KPI strip; full-width grid = Live-Angriffe (left) + Shell-Aktivitaet terminal (right), Nachlade + Top-Quellen below.
 FORM: ops console. code-led, data-driven from /api/overview.
 FINISH: shipped nodeui UI. -->
<main>
  <div class="top">
    <div class="brand"><span class="dot"></span><div><b>JustDNS</b><span>honeypot&nbsp;node</span></div></div>
    <div class="status">srv-web-01 &middot; egress&nbsp;<b>locked</b> &middot; live&nbsp;3s</div>
    <a class="navlink" href="/sensors">Sensoren</a>
    <a class="navlink" href="/setup">+ Sensor anbinden</a>
    <div class="kpi">
      <div class="k red"><div class="n tnum" id="kp-shell">0</div><div class="l">in Shell</div></div>
      <div class="k amber"><div class="n tnum" id="kp-ev">0</div><div class="l">Logins</div></div>
      <div class="k"><div class="n tnum" id="kp-ip">0</div><div class="l">Quellen</div></div>
      <div class="k green"><div class="n tnum" id="kp-nl">0</div><div class="l">Nachlade</div></div>
    </div>
  </div>
  <div class="grid">
    <section class="card" id="c-feed">
      <div class="ch"><h2>Live-Angriffe</h2><span id="filt"></span><span class="live"><i></i>live</span></div>
      <div class="scroll"><table>
        <thead><tr><th>Zeit (Wien)</th><th>Status</th><th>Source IP</th><th>Dienst</th><th>Port</th><th>Credentials</th></tr></thead>
        <tbody id="feed"></tbody></table></div>
    </section>
    <section class="card" id="c-shell">
      <div class="ch"><h2>Shell-Aktivitaet</h2><span class="sub" id="shell-sub">&middot; alle Quellen</span><span class="live"><i></i>live</span></div>
      <div class="term scroll" id="shell"></div>
    </section>
    <section class="card" id="c-nl">
      <div class="ch"><h2>Nachlade-Versuche</h2><span class="sub">wget / curl / Download</span></div>
      <div class="scroll"><table>
        <thead><tr><th>Zeit (Wien)</th><th>Source IP</th><th>Ziel</th><th>Command</th></tr></thead>
        <tbody id="nl"></tbody></table></div>
    </section>
    <section class="card" id="c-top">
      <div class="ch"><h2>Top-Quellen</h2></div>
      <div class="bars" id="top"></div>
    </section>
  </div>
</main>
<script>
const $ = id => document.getElementById(id);
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let filter = null;

// Alle ts kommen als UTC (cowrie "...Z", opencanary "YYYY-MM-DD HH:MM:SS").
// DST-korrekt in Wien-Zeit anzeigen, unabhaengig von der Browser-Zeitzone.
const VIENNA = new Intl.DateTimeFormat('de-AT', {timeZone:'Europe/Vienna',
  year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
function shortTs(t){
  if(!t) return '';
  let s = String(t).trim();
  if(/^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}/.test(s)) s = s.replace(' ','T');
  if(!/[Zz]|[+\\-]\\d{2}:?\\d{2}$/.test(s)) s += 'Z';   // ohne Zone -> als UTC lesen
  const d = new Date(s);
  return isNaN(d) ? String(t) : VIENNA.format(d).replace(',', '');
}
function svcClass(s){ s=(s||'').toUpperCase(); if(s==='SSH')return 'ssh'; if(s==='TELNET')return 'tel'; if(s==='HTTP')return 'http'; return 'oth'; }
function hl(cmd){
  let c = esc(cmd);
  c = c.replace(/(wget|curl|tftp|ftpget|lwp-download|fetch)/gi,'<span class="dl">$1</span>');
  c = c.replace(/(busybox)/gi,'<span class="bb">$1</span>');
  return c;
}
function setFilter(ip){ filter = (filter===ip)?null:ip; tick(); }
function clearFilter(){ filter = null; tick(); }

async function tick(){
  let d;
  try { d = await (await fetch('/api/overview')).json(); } catch(e){ return; }
  const F = r => !filter || r.src_ip === filter;

  // KPIs
  const inShell = new Set((d.shell||[]).map(r=>r.src_ip)).size;
  $('kp-shell').textContent = inShell;
  $('kp-ev').textContent = d.events_total;
  $('kp-ip').textContent = d.ips_total;
  $('kp-nl').textContent = (d.nachlade||[]).length;

  // Filter-Chip
  $('filt').innerHTML = filter
    ? `<span class="chip" onclick="clearFilter()" title="Filter aufheben"><b>${esc(filter)}</b><span class="x">&times;</span></span>`
    : '';

  // Live-Angriffe
  let h = '';
  for(const r of (d.feed||[]).filter(F)){
    const ok = r.outcome === 'ok';
    const st = ok ? '<span class="st breach"><i></i>Shell</span>' : '<span class="st probe"><i></i>Probe</span>';
    h += `<tr><td class="muted mono">${esc(shortTs(r.ts))}</td>`
       + `<td>${st}</td>`
       + `<td class="ip" onclick="setFilter('${esc(r.src_ip)}')">${esc(r.src_ip)}</td>`
       + `<td><span class="tag ${svcClass(r.service)}">${esc(r.service||'?')}</span></td>`
       + `<td class="muted mono">${esc(r.dst_port==null?'':r.dst_port)}</td>`
       + `<td class="cred">${esc(r.username)||'<span class="pw">-</span>'}<span class="pw"> / ${esc(r.password)||'-'}</span></td></tr>`;
  }
  $('feed').innerHTML = h || '<tr><td colspan="6" class="empty">Noch keine Angriffe&hellip;</td></tr>';

  // Shell-Aktivitaet (Terminal)
  const sh = (d.shell||[]).filter(F);
  $('shell-sub').innerHTML = filter ? ('&middot; '+esc(filter)) : '&middot; alle Quellen';
  let sx = '';
  sh.forEach((r,idx)=>{
    const who = filter ? '' : `<span class="who">${esc(r.src_ip)}</span>`;
    const cur = idx===0 ? '<span class="cursor"></span>' : '';
    sx += `<div class="ln"><span class="t">${esc(shortTs(r.ts))}</span>${who}<span class="pr">$</span><span class="cmd">${hl(r.command)} ${cur}</span></div>`;
  });
  $('shell').innerHTML = sx || '<div class="empty">Noch keine Shell-Eingaben&hellip; (erscheinen, sobald ein Angreifer eingeloggt ist)</div>';

  // Nachlade
  let nh = '';
  for(const r of (d.nachlade||[]).filter(F)){
    const doms = (r.domains||[]).map(x=>`<span class="dom">${esc(x)}</span>`).join('') || '<span class="muted">-</span>';
    nh += `<tr><td class="muted mono">${esc(shortTs(r.ts))}</td>`
       + `<td class="ip" onclick="setFilter('${esc(r.src_ip)}')">${esc(r.src_ip)}</td>`
       + `<td>${doms}</td><td class="cmd">${hl(r.command)}</td></tr>`;
  }
  $('nl').innerHTML = nh || '<tr><td colspan="4" class="empty">Noch keine Nachlade-Versuche&hellip;</td></tr>';

  // Top-Quellen (Balken)
  const top = d.top || [];
  const max = top.length ? top[0].count : 1;
  let t = '';
  for(const r of top){
    const w = Math.max(3, Math.round(100*r.count/max));
    const act = (filter===r.ip) ? ' style="color:var(--ink)"' : '';
    t += `<div class="brow"><div class="hd"><span class="ip"${act} onclick="setFilter('${esc(r.ip)}')">${esc(r.ip)}</span>`
       + `<span class="c tnum">${r.count}</span></div><div class="bar"><i style="width:${w}%"></i></div></div>`;
  }
  $('top').innerHTML = t || '<div class="empty">-</div>';
}
tick();
setInterval(tick, 3000);
</script>
</body></html>"""


SETUP_HTML = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JustDNS Node - Sensoren anbinden</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0d12;--panel:#10151d;--line:#1e2733;--line2:#2a3542;--ink:#dfe6ef;--mut:#8695a8;--dim:#7e8ca0;
--blue:#6cc7ff;--green:#5fdd97;--amber:#f5b445;--mono:"IBM Plex Mono",ui-monospace,monospace;--sans:"IBM Plex Sans",system-ui,sans-serif;color-scheme:dark;}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);min-height:100vh}
a{color:var(--blue)}
.wrap{max-width:860px;margin:0 auto;padding:22px 16px 64px}
.top{display:flex;align-items:center;gap:12px;padding:4px 0 18px;border-bottom:1px solid var(--line);margin-bottom:22px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px #102418}
.top b{font-size:15px}.top span{color:var(--dim);font:12px/1 var(--mono)}
.back{margin-left:auto;color:var(--blue);font:12px/1 var(--mono);text-decoration:none;padding:7px 11px;border:1px solid var(--line2);border-radius:8px}
.back:hover{border-color:var(--blue)}
.lead{color:var(--mut);margin:0 0 22px;max-width:62ch}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-bottom:18px}
.card h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:0 0 4px}
.card p.d{color:var(--dim);margin:0 0 14px;font-size:13px}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.f{flex:1;min-width:150px}.f.sm{flex:0 0 120px}
label{display:block;font-size:12px;color:var(--mut);margin-bottom:4px}
input,select{width:100%;font:inherit;background:#0d1117;color:var(--ink);border:1px solid var(--line2);border-radius:8px;padding:8px 10px}
input:focus,select:focus{outline:2px solid var(--blue);outline-offset:1px}
.chk{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mut);margin:2px 0 12px}.chk input{width:auto}
.cmd{display:flex;gap:10px;align-items:flex-start;background:#070a0e;border:1px solid var(--line2);border-radius:9px;padding:11px 12px}
.cmd code{font-family:var(--mono);font-size:13px;color:#e7edf4;white-space:pre-wrap;word-break:break-all;flex:1}
.cmd .dl{color:var(--amber)}
.copy{flex:0 0 auto;font:500 12px/1 var(--mono);color:var(--bg);background:var(--blue);border:0;border-radius:7px;padding:8px 12px;cursor:pointer}
.copy.ok{background:var(--green)}
.note{color:var(--dim);font-size:12px;margin:10px 0 0}
.note b{color:var(--amber);font-weight:500}
.btn{font:600 13px/1 var(--sans);color:var(--bg);background:var(--blue);border:0;border-radius:8px;padding:10px 16px;cursor:pointer}
.btn:disabled{opacity:.55;cursor:default}
.btn:hover:not(:disabled){filter:brightness(1.08)}
.result{margin-top:12px;padding:10px 12px;border-radius:8px;font-size:13px;display:none}
.result.show{display:block}
.result.ok{background:#102418;border:1px solid #1e4d33;color:var(--green)}
.result.err{background:#2a1217;border:1px solid #4d1e24;color:var(--red)}
.result.wait{background:#11202a;border:1px solid #1e3a4d;color:var(--blue)}
</style></head>
<body><div class="wrap">
  <div class="top"><span class="dot"></span><div><b>JustDNS</b> <span>honeypot node</span></div>
    <a class="back" href="/">&larr; Konsole</a></div>
  <p class="lead">Sensoren an diese Node anbinden. Agent und Firewall melden an <b>diese
  Node</b>; sie sammelt und leitet an die zentrale Intake weiter, wo IPs manuell fuer die
  Blockliste freigegeben werden. Private IPs werden nie veroeffentlicht.</p>

  <div class="card">
    <h2>Agent ausrollen</h2>
    <p class="d">Liest App-Ablehnungen (nginx, Caddy, Node64, NPM, Apache, HAProxy, sshd,
    fail2ban) und meldet die Quell-IPs an diese Node. Befehl auf dem Ziel-Host als root
    ausfuehren.</p>
    <div class="row">
      <div class="f"><label>Host-Name (LXC / VM)</label><input id="ag_name" placeholder="web-02" oninput="buildAgent()"></div>
      <div class="f sm"><label>Anwendung</label><select id="ag_app" onchange="buildAgent()">
        <option>nginx</option><option>apache</option><option>caddy</option>
        <option>npm</option><option>haproxy</option><option>sshd</option><option>fail2ban</option></select></div>
    </div>
    <div class="cmd"><code id="ag_cmd"></code><button class="copy" onclick="cp('ag_cmd',this)">Kopieren</button></div>
  </div>

  <div class="card">
    <h2>Firewall anbinden (Unifi, nur lesen)</h2>
    <p class="d">Diese Node fragt den Unifi-Controller direkt ab und holt <b>alle</b> geblockten
    externen Zugriffe (ext&rarr;intern / ext&rarr;Gateway), nicht nur IPS/IDS. Nur lesend, keine
    Aenderung am Controller.</p>
    <div class="row">
      <div class="f"><label>Controller-URL</label><input id="fw_url" placeholder="https://192.168.1.1"></div>
      <div class="f sm"><label>Site</label><input id="fw_site" value="default"></div>
    </div>
    <div class="row">
      <div class="f"><label>Read-only API-Key</label><input id="fw_key" type="password" autocomplete="off" placeholder="X-API-KEY"></div>
    </div>
    <label class="chk"><input type="checkbox" id="fw_tls" checked> Selbstsigniertes Controller-Zertifikat (TLS-Pruefung aus)</label>
    <button class="btn" id="fw_btn" onclick="connectFw()">Firewall verbinden</button>
    <div class="result" id="fw_res"></div>
    <p class="note">Den read-only API-Key bekommst du im Controller unter <b>Settings &rarr;
    Control Plane &rarr; Integrations</b> (am besten unter einem Viewer-Admin). Der Key bleibt
    auf dieser Node und wird nicht an die Intake gesendet.</p>
  </div>

  <div class="card">
    <h2>node64 anbinden (PROXY64, nur lesen)</h2>
    <p class="d">Diese Node liest das node64-Zugriffslog und holt die <b>eigenen</b> Policy-Blocks
    (Exploit-/WAF-Treffer, Access-List, Rate-Limit, honeypot_instant_block). Blocklist-Treffer
    werden bewusst ausgelassen (die stehen schon auf der Liste). Nur lesend.</p>
    <div class="row">
      <div class="f"><label>node64-URL</label><input id="n6_url" placeholder="https://node64.lan"></div>
    </div>
    <div class="row">
      <div class="f"><label>API-Key (node64_...)</label><input id="n6_key" type="password" autocomplete="off" placeholder="node64_..."></div>
    </div>
    <label class="chk"><input type="checkbox" id="n6_tls" checked> Selbstsigniertes Zertifikat (TLS-Pruefung aus)</label>
    <button class="btn" id="n6_btn" onclick="connectN6()">node64 verbinden</button>
    <div class="result" id="n6_res"></div>
    <p class="note">Den API-Key bekommst du in node64 unter <b>Einstellungen &rarr; API-Keys</b>
    (Prefix <code>node64_</code>, nur lesen reicht). Der Key bleibt auf dieser Node.</p>
  </div>
</div>
<script>
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const dl = '<span class="dl">curl</span>';
const $ = id => document.getElementById(id);
function buildAgent(){
  const name = ($('ag_name').value || 'mein-host').trim();
  const app = $('ag_app').value;
  const c = `curl -fsSL ${location.origin}/agent/install | sudo bash -s -- --name ${esc(name)} --app ${esc(app)}`;
  $('ag_cmd').innerHTML = c.replace('curl', dl);
}
function cp(id,btn){
  navigator.clipboard.writeText($(id).textContent).then(()=>{ btn.textContent='Kopiert'; btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='Kopieren';btn.classList.remove('ok');},1400); });
}
function res(cls,msg){ const r=$('fw_res'); r.className='result show '+cls; r.innerHTML=msg; }
async function connectFw(){
  const url=($('fw_url').value||'').trim();
  const site=($('fw_site').value||'default').trim();
  const key=($('fw_key').value||'').trim();
  const verify=!$('fw_tls').checked;
  if(!url||!key){ res('err','Controller-URL und API-Key noetig.'); return; }
  const btn=$('fw_btn'); btn.disabled=true; btn.textContent='Verbinde...';
  res('wait','Controller wird getestet und die Firewall angemeldet...');
  try{
    const r=await fetch('/api/firewall/connect',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({unifi_url:url,site:site,api_key:key,verify_tls:verify})});
    const d=await r.json();
    if(d.ok){ res('ok','&#10003; '+esc(d.message)); $('fw_key').value=''; }
    else res('err','&#10007; '+esc(d.message||'Fehlgeschlagen.'));
  }catch(e){ res('err','Netzwerkfehler: '+esc(String(e))); }
  btn.disabled=false; btn.textContent='Firewall verbinden';
}
function res6(cls,msg){ const r=$('n6_res'); r.className='result show '+cls; r.innerHTML=msg; }
async function connectN6(){
  const url=($('n6_url').value||'').trim();
  const key=($('n6_key').value||'').trim();
  const verify=!$('n6_tls').checked;
  if(!url||!key){ res6('err','node64-URL und API-Key noetig.'); return; }
  const btn=$('n6_btn'); btn.disabled=true; btn.textContent='Verbinde...';
  res6('wait','node64 wird getestet und angemeldet...');
  try{
    const r=await fetch('/api/node64/connect',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({node64_url:url,api_key:key,verify_tls:verify})});
    const d=await r.json();
    if(d.ok){ res6('ok','&#10003; '+esc(d.message)); $('n6_key').value=''; }
    else res6('err','&#10007; '+esc(d.message||'Fehlgeschlagen.'));
  }catch(e){ res6('err','Netzwerkfehler: '+esc(String(e))); }
  btn.disabled=false; btn.textContent='node64 verbinden';
}
buildAgent();
</script>
</body></html>"""


SENSORS_HTML = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JustDNS Node - Sensor-Protokoll</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0d12;--panel:#10151d;--line:#1e2733;--line2:#2a3542;--ink:#dfe6ef;--mut:#8695a8;--dim:#7e8ca0;
--blue:#6cc7ff;--green:#5fdd97;--amber:#f5b445;--red:#ff5d6c;--mono:"IBM Plex Mono",ui-monospace,monospace;--sans:"IBM Plex Sans",system-ui,sans-serif;color-scheme:dark;}
*{box-sizing:border-box}html,body{margin:0}body{background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);min-height:100vh}
a{color:var(--blue);text-decoration:none}
.wrap{max-width:1040px;margin:0 auto;padding:22px 16px 64px}
.top{display:flex;align-items:center;gap:12px;padding:4px 0 18px;border-bottom:1px solid var(--line);margin-bottom:22px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 0 3px #102418}
.top b{font-size:15px}.top .sub{color:var(--dim);font:12px/1 var(--mono)}
.nav{margin-left:auto;display:flex;gap:8px}
.nav a{font:12px/1 var(--mono);padding:7px 11px;border:1px solid var(--line2);border-radius:8px}
.nav a:hover{border-color:var(--blue)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:18px;overflow:hidden}
.ch{display:flex;align-items:center;gap:8px;padding:11px 15px;border-bottom:1px solid var(--line)}
.ch h2{font-size:12px;letter-spacing:.07em;text-transform:uppercase;color:var(--mut);margin:0;font-weight:600}
.ch .live{margin-left:auto;color:var(--green);font:12px/1 var(--mono)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{position:sticky;top:0;background:#0f1620;color:var(--dim);text-align:left;font-weight:600;font-size:12px;letter-spacing:.05em;text-transform:uppercase;padding:8px 15px;border-bottom:1px solid var(--line)}
tbody td{padding:8px 15px;border-bottom:1px solid #161e28;white-space:nowrap}
tbody tr:hover td{background:#121a24}
.scroll{max-height:46vh;overflow:auto}
.ip{color:var(--blue);font-family:var(--mono)}
.mono{font-family:var(--mono)}.muted{color:var(--dim)}
.k{display:inline-block;padding:1px 8px;border-radius:999px;font:500 12px/1.6 var(--mono)}
.k.agent{background:#10263a;color:#7fc5ff}.k.firewall{background:#2a2111;color:var(--amber)}
.r{display:inline-block;padding:1px 8px;border-radius:999px;font:500 12px/1.6 var(--mono);background:#1d2530;color:var(--mut)}
.r.ips_alert{background:#2a1217;color:var(--red)}.r.fw_drop{background:#2a2111;color:var(--amber)}
.empty{padding:22px 15px;color:var(--dim);font-size:13px}
td.act{text-align:right;padding-right:15px}
.del{font:500 12px/1 var(--mono);color:var(--mut);background:transparent;border:1px solid var(--line2);border-radius:7px;padding:5px 10px;cursor:pointer}
.del:hover{border-color:var(--red);color:var(--red)}
.del:disabled{opacity:.5;cursor:default}
</style></head>
<body><div class="wrap">
  <div class="top"><span class="dot"></span><div><b>JustDNS</b> <span class="sub">honeypot node</span></div>
    <div class="nav"><a href="/">&larr; Konsole</a><a href="/setup">+ Sensor anbinden</a></div></div>

  <div class="card">
    <div class="ch"><h2>Angebundene Sensoren</h2><span class="live" id="sc"></span></div>
    <div class="scroll"><table>
      <thead><tr><th>Typ</th><th>Host / Quelle</th><th>App</th><th>Sensor-ID</th><th>Meldungen</th><th>Zuletzt (Wien)</th><th></th></tr></thead>
      <tbody id="sensors"></tbody></table></div>
  </div>

  <div class="card">
    <div class="ch"><h2>Gemeldete Zugriffe</h2><span class="live"><span id="fc"></span> &middot; live</span></div>
    <div class="scroll"><table>
      <thead><tr><th>Zeit (Wien)</th><th>Sensor</th><th>Typ</th><th>Quell-IP</th><th>Grund</th></tr></thead>
      <tbody id="feed"></tbody></table></div>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const VIENNA = new Intl.DateTimeFormat('de-AT',{timeZone:'Europe/Vienna',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
function ts(t){ if(!t)return ''; let s=String(t).trim(); if(/^\\d{4}-\\d{2}-\\d{2} /.test(s))s=s.replace(' ','T'); if(!/[Zz]|[+\\-]\\d{2}:?\\d{2}$/.test(s))s+='Z'; const d=new Date(s); return isNaN(d)?String(t):VIENNA.format(d).replace(',',''); }
async function tick(){
  let d; try{ d=await (await fetch('/api/sensors')).json(); }catch(e){ return; }
  const sens=d.sensors||[];
  $('sc').textContent = sens.length ? (sens.length+' Sensor'+(sens.length===1?'':'en')) : '';
  let h='';
  for(const s of sens){
    const kind=(s.kind==='firewall')?'firewall':'agent';
    const kl=(s.kind==='firewall')?'Firewall':'Agent';
    h+=`<tr><td><span class="k ${kind}">${kl}</span></td>`
      +`<td class="mono">${esc(s.host)||'<span class="muted">-</span>'}</td>`
      +`<td class="mono">${esc(s.app)||'<span class="muted">-</span>'}</td>`
      +`<td class="mono muted">${esc(s.sensor_id)}</td>`
      +`<td class="mono">${s.count||0}</td>`
      +`<td class="mono muted">${esc(ts(s.last_ts))}</td>`
      +`<td class="act"><button class="del" data-sid="${esc(s.sensor_id)}" data-host="${esc(s.host||s.app||s.sensor_id)}">Entfernen</button></td></tr>`;
  }
  $('sensors').innerHTML = h || '<tr><td colspan="7" class="empty">Noch keine Sensoren angebunden. Unter &bdquo;+ Sensor anbinden&ldquo; einen Agent ausrollen oder die Firewall verbinden.</td></tr>';
  const feed=d.feed||[];
  $('fc').textContent = feed.length ? (feed.length+' Meldungen') : '';
  let f='';
  for(const r of feed){
    const rl=esc(r.reason||'');
    f+=`<tr><td class="mono muted">${esc(ts(r.ts))}</td>`
      +`<td class="mono">${esc(r.sensor)||'?'}</td>`
      +`<td><span class="k ${r.kind==='firewall'?'firewall':'agent'}">${r.kind==='firewall'?'Firewall':'Agent'}</span></td>`
      +`<td class="ip">${esc(r.src_ip)}</td>`
      +`<td><span class="r ${rl}">${rl||'-'}</span></td></tr>`;
  }
  $('feed').innerHTML = f || '<tr><td colspan="5" class="empty">Noch keine gemeldeten Zugriffe.</td></tr>';
}
let busy=false;
$('sensors').addEventListener('click', async e=>{
  const b=e.target.closest('.del'); if(!b||busy) return;
  const sid=b.dataset.sid, host=b.dataset.host||sid;
  if(!confirm('Sensor „'+host+'“ entfernen? Eine verbundene Firewall-/node64-Direktanbindung wird dabei abgeschaltet.')) return;
  busy=true; b.disabled=true; b.textContent='…';
  try{
    const r=await fetch('/api/sensors/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sensor_id:sid})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok||!j.ok){ alert(j.message||'Entfernen fehlgeschlagen.'); b.disabled=false; b.textContent='Entfernen'; }
  }catch(err){ alert('Entfernen fehlgeschlagen: '+err); b.disabled=false; b.textContent='Entfernen'; }
  busy=false; tick();
});
tick(); setInterval(tick,3000);
</script>
</body></html>"""


def reconcile_firewall():
    """Eine schon eingerichtete Firewall-Anbindung ins Protokoll uebernehmen,
    damit sie auch nach einem Neustart oder nach einem Update sichtbar ist."""
    try:
        with open(UNIFI_CONFIG, encoding="utf-8") as fh:
            conf = {}
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    conf[k.strip()] = v.strip()
    except OSError:
        return
    token = conf.get("TOKEN", "")
    try:
        with open(FW_STATE, encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        st = {}
    sid = st.get("sensor_id")
    if not token or not sid:
        return
    name = conf.get("NAME") or st.get("controller") or "unifi"
    SENSORS.register({"host": name, "app": "unifi", "kind": "firewall"},
                     {"token": token, "sensor_id": sid})
    try:
        with open(os.path.join(FW_DIR, "unifi-state.json"), encoding="utf-8") as fh:
            cnt = len(json.load(fh).get("seen_ids", []))
    except (OSError, ValueError):
        cnt = 0
    with SENSORS.lock:
        s = SENSORS.sensors.get(sid)
        if s and not s.get("count"):
            s["count"] = cnt
            SENSORS._save()


def reconcile_node64():
    """Eine schon eingerichtete node64-Anbindung ins Protokoll uebernehmen."""
    try:
        with open(NODE64_CONFIG, encoding="utf-8") as fh:
            conf = {}
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    conf[k.strip()] = v.strip()
    except OSError:
        return
    token = conf.get("TOKEN", "")
    try:
        with open(NODE64_STATE, encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        st = {}
    sid = st.get("sensor_id")
    if not token or not sid:
        return
    name = conf.get("NAME") or st.get("node64") or "node64"
    SENSORS.register({"host": name, "app": "node64", "kind": "firewall"},
                     {"token": token, "sensor_id": sid})


def main():
    reconcile_firewall()
    reconcile_node64()
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[nodeui] lauscht auf {BIND}:{PORT}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
