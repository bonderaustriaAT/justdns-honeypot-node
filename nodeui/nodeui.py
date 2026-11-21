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

Die Seite zeigt alle Angriffe im Ring (neueste zuerst) plus die Nachlade-Versuche
(wget/curl/Download) mit Kommando und Ziel-Domains. Leer-Start gilt nur fuer die
Live View im Intake-Dashboard, nicht hier.

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

COWRIE_FAILED = "cowrie.login.failed"
PORT_SVC = {21: "FTP", 23: "TELNET", 80: "HTTP", 3306: "MYSQL",
            3389: "RDP", 5900: "VNC", 2222: "SSH", 22: "SSH"}


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
    return {"ts": e.get("timestamp"), "src_ip": ip, "service": "SSH",
            "dst_port": e.get("dst_port"), "username": e.get("username", ""),
            "password": e.get("password", "")}


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


class State:
    """Geteilter Zustand, unter einem Lock aktualisiert."""

    def __init__(self):
        self.lock = threading.Lock()
        self.offsets = {}                         # tag:path -> byte-offset
        self.feed = collections.deque(maxlen=FEED_MAX)
        self.nachlade = collections.deque(maxlen=200)   # Download-/wget-Versuche
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
            top = sorted(self.ip_counts.items(), key=lambda kv: kv[1][0], reverse=True)[:20]
            return {
                "since": self.since,
                "events_total": self.events_total,
                "ips_total": len(self.ip_counts),
                "ips_capped": len(self.ip_counts) >= MAX_IPS,
                "feed": list(self.feed)[-200:][::-1],   # neueste zuerst
                "nachlade": list(self.nachlade)[-100:][::-1],
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
        if path == "/api/overview":
            self._send(200, STATE.poll())
            return
        if path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"error": "not_found"})


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JustDNS Honeypot Node</title>
<style>
  :root { color-scheme: dark; }
  body { font: 14px/1.5 system-ui, sans-serif; margin:0; background:#0f1115; color:#d7dce3; }
  header { padding:14px 18px; background:#161a21; border-bottom:1px solid #262c36;
           display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  h1 { font-size:16px; margin:0; }
  .stat { color:#8893a4; font-size:13px; }
  .stat b { color:#d7dce3; }
  main { padding:18px; display:grid; gap:18px; grid-template-columns: 1fr; max-width:1200px; }
  @media (min-width:900px){ main { grid-template-columns: 2fr 1fr; } }
  h2 { font-size:14px; color:#8893a4; margin:0 0 8px; font-weight:600; }
  table { border-collapse:collapse; width:100%; }
  th, td { text-align:left; padding:5px 9px; border-bottom:1px solid #222832; vertical-align:top; }
  th { color:#8893a4; font-weight:600; }
  tr:hover td { background:#171c24; }
  .mono { font-family: ui-monospace, monospace; font-size:13px; }
  .svc { padding:1px 7px; border-radius:10px; font-size:12px; background:#11405a; color:#8cd3ff; }
  .muted { color:#6b7585; }
  .ip { color:#8cd3ff; cursor:pointer; }
  .flag { float:right; font-size:12px; color:#6b7585; }
  .dom { display:inline-block; padding:1px 6px; border-radius:8px; font-size:12px;
         background:#3a2a12; color:#ffcf8c; font-family:ui-monospace,monospace; margin:1px 2px; }
  td.cmd { white-space:pre-wrap; word-break:break-all; color:#c9d1dc; max-width:620px; }
</style></head>
<body>
<header>
  <h1>JustDNS Honeypot Node</h1>
  <span class="stat">Angriffe <b id="ev">0</b></span>
  <span class="stat">Quellen <b id="ips">0</b></span>
  <span class="stat">Letzter <b id="since">-</b></span>
  <span class="flag">live &middot; 3s</span>
</header>
<main>
  <section>
    <h2>Live attacks <span id="filt" class="muted"></span></h2>
    <table><thead><tr><th>Time (UTC)</th><th>Source IP</th><th>Service</th>
      <th>Port</th><th>Username</th><th>Password</th></tr></thead>
      <tbody id="feed"></tbody></table>
  </section>
  <section>
    <h2>Top sources</h2>
    <table><thead><tr><th>IP</th><th>Attempts</th><th>Last</th></tr></thead>
      <tbody id="top"></tbody></table>
  </section>
  <section style="grid-column:1/-1">
    <h2>Nachlade-Versuche <span class="muted">wget / curl / Download</span></h2>
    <table><thead><tr><th>Time (UTC)</th><th>Source IP</th><th>Domains</th><th>Command</th></tr></thead>
      <tbody id="nl"></tbody></table>
  </section>
</main>
<script>
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let filter = null;
function shortTs(t){ if(!t) return ''; return String(t).replace('T',' ').replace(/\\.\\d+/,'').replace('Z',''); }

// Node-UI zeigt IMMER alle Angriffe (der komplette Feed, neueste zuerst). Das
// Leer-Starten gilt nur fuer die Live View im Intake-Dashboard, nicht hier.
async function tick(){
  let d;
  try { d = await (await fetch('/api/overview')).json(); } catch(e){ return; }

  const counts = {}, last = {};
  for(const r of d.feed){
    counts[r.src_ip] = (counts[r.src_ip]||0) + 1;
    if(!last[r.src_ip]) last[r.src_ip] = r.ts;   // feed ist neueste zuerst
  }
  document.getElementById('ev').textContent = d.events_total;
  document.getElementById('ips').textContent = Object.keys(counts).length;
  document.getElementById('since').textContent = d.feed.length ? shortTs(d.feed[0].ts) : '-';

  let rows = d.feed;
  if(filter) rows = rows.filter(r => r.src_ip === filter);
  document.getElementById('filt').textContent = filter ? ('filtered: '+filter+' (click to clear)') : '';
  let h = '';
  for(const r of rows){
    h += `<tr><td class="muted mono">${esc(shortTs(r.ts))}</td>`
       + `<td class="mono ip" onclick="setFilter('${esc(r.src_ip)}')">${esc(r.src_ip)}</td>`
       + `<td><span class="svc">${esc(r.service||'?')}</span></td>`
       + `<td class="muted">${esc(r.dst_port)}</td>`
       + `<td class="mono">${esc(r.username)}</td><td class="mono">${esc(r.password)}</td></tr>`;
  }
  document.getElementById('feed').innerHTML = h || '<tr><td colspan="6" class="muted">Noch keine Angriffe&hellip;</td></tr>';

  let nl = d.nachlade || [];
  if(filter) nl = nl.filter(r => r.src_ip === filter);
  let nh = '';
  for(const r of nl){
    const doms = (r.domains||[]).map(x=>`<span class="dom">${esc(x)}</span>`).join('') || '<span class="muted">-</span>';
    nh += `<tr><td class="muted mono">${esc(shortTs(r.ts))}</td>`
       + `<td class="mono ip" onclick="setFilter('${esc(r.src_ip)}')">${esc(r.src_ip)}</td>`
       + `<td>${doms}</td><td class="mono cmd">${esc(r.command)}</td></tr>`;
  }
  document.getElementById('nl').innerHTML = nh || '<tr><td colspan="4" class="muted">Noch keine Nachlade-Versuche&hellip;</td></tr>';

  const top = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,20);
  let t = '';
  for(const [ip,count] of top){
    t += `<tr><td class="mono ip" onclick="setFilter('${esc(ip)}')">${esc(ip)}</td>`
       + `<td>${count}</td><td class="muted mono">${esc(shortTs(last[ip]))}</td></tr>`;
  }
  document.getElementById('top').innerHTML = t || '<tr><td colspan="3" class="muted">-</td></tr>';
}
function setFilter(ip){ filter = (filter===ip)?null:ip; tick(); }
document.getElementById('filt').onclick = ()=>{ filter=null; tick(); };
tick();
setInterval(tick, 3000);
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
