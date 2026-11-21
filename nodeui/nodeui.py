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
import threading
import urllib.parse
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
# Intake, an die ausgerollte Agents und die Firewall-Anbindung melden.
INTAKE_URL = os.environ.get("NODEUI_INTAKE_URL", "https://intake.justdns.justfuture.at").rstrip("/")

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
            self._send(200, SETUP_HTML.replace("__INTAKE_URL__", INTAKE_URL),
                       ctype="text/html; charset=utf-8")
            return
        if path == "/api/overview":
            self._send(200, STATE.poll())
            return
        if path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"error": "not_found"})


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
</style></head>
<body><div class="wrap">
  <div class="top"><span class="dot"></span><div><b>JustDNS</b> <span>honeypot node</span></div>
    <a class="back" href="/">&larr; Konsole</a></div>
  <p class="lead">Sensoren an diese Node anbinden. Beide melden abgelehnte Zugriffe an die
  zentrale Intake; dort werden IPs manuell geprueft und erst dann fuer die Blockliste
  freigegeben. Private IPs werden nie veroeffentlicht.</p>

  <div class="card">
    <h2>Agent ausrollen</h2>
    <p class="d">Liest App-Ablehnungen (nginx, Caddy, Node64, NPM, Apache, HAProxy, sshd,
    fail2ban) und meldet die Quell-IPs. Befehl auf dem Ziel-Host als root ausfuehren.</p>
    <div class="row">
      <div class="f"><label>Host-Name (LXC / VM)</label><input id="ag_name" placeholder="web-02" oninput="buildAgent()"></div>
      <div class="f sm"><label>Anwendung</label><select id="ag_app" onchange="buildAgent()">
        <option>nginx</option><option>apache</option><option>caddy</option><option>node64</option>
        <option>npm</option><option>haproxy</option><option>sshd</option><option>fail2ban</option></select></div>
    </div>
    <div class="cmd"><code id="ag_cmd"></code><button class="copy" onclick="cp('ag_cmd',this)">Kopieren</button></div>
    <p class="note">Der Agent erscheint danach in der Intake als <b>ausstehend</b> - erst nach
    deiner Freigabe fliessen seine oeffentlichen IPs weiter.</p>
  </div>

  <div class="card">
    <h2>Firewall anbinden (Unifi, nur lesen)</h2>
    <p class="d">Liest IPS/IDS-Alarme und Firewall-Drops vom Unifi-Controller. Befehl auf
    einem Host mit Zugriff auf den Controller als root ausfuehren; er fragt den API-Key
    sicher ab (nicht im Befehl).</p>
    <div class="row">
      <div class="f"><label>Controller-URL</label><input id="fw_url" placeholder="https://192.168.1.1" oninput="buildFw()"></div>
      <div class="f sm"><label>Site</label><input id="fw_site" value="default" oninput="buildFw()"></div>
    </div>
    <label class="chk"><input type="checkbox" id="fw_tls" onchange="buildFw()"> Selbstsigniertes Controller-Zertifikat (TLS-Pruefung aus)</label>
    <div class="cmd"><code id="fw_cmd"></code><button class="copy" onclick="cp('fw_cmd',this)">Kopieren</button></div>
    <p class="note">Den read-only API-Key bekommst du im Controller unter <b>Settings &rarr;
    Control Plane &rarr; Integrations</b> (am besten unter einem Viewer-Admin). Der Reader
    registriert sich selbst und erscheint in der Intake als ausstehend.</p>
  </div>
</div>
<script>
const INTAKE = "__INTAKE_URL__";
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const dl = '<span class="dl">curl</span>';
function shq(s){ return "'" + String(s).replace(/'/g,"'\\\\''") + "'"; }
function buildAgent(){
  const name = (document.getElementById('ag_name').value || 'mein-host').trim();
  const app = document.getElementById('ag_app').value;
  const c = `curl -fsSL ${INTAKE}/agent/install | sudo bash -s -- --name ${esc(name)} --app ${esc(app)}`;
  document.getElementById('ag_cmd').innerHTML = c.replace('curl', dl);
}
function buildFw(){
  const url = (document.getElementById('fw_url').value || 'https://192.168.1.1').trim();
  const site = (document.getElementById('fw_site').value || 'default').trim();
  const insec = document.getElementById('fw_tls').checked ? ' --insecure' : '';
  const c = `curl -fsSL ${INTAKE}/firewall/install | sudo bash -s -- --unifi-url ${esc(url)} --site ${esc(site)}${insec}`;
  document.getElementById('fw_cmd').innerHTML = c.replace('curl', dl);
}
function cp(id,btn){
  const t = document.getElementById(id).textContent;
  navigator.clipboard.writeText(t).then(()=>{ btn.textContent='Kopiert'; btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='Kopieren';btn.classList.remove('ok');},1400); });
}
buildAgent(); buildFw();
</script>
</body></html>"""


def main():
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
