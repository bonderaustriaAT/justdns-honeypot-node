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
import hmac
import ipaddress
import json
import os
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import nodeauth

BIND = os.environ.get("NODEUI_BIND", "0.0.0.0")
PORT = int(os.environ.get("NODEUI_PORT", "8090"))
TOKEN = os.environ.get("NODEUI_TOKEN", "")   # Legacy-Bearer (optional, nur API-Reads)
# Secure-Cookie nur erzwingen, wenn ueber TLS ausgeliefert wird (Reverse-Proxy):
SECURE_COOKIE_ENV = os.environ.get("NODEUI_SECURE_COOKIE", "") == "1"
COWRIE_LOG = os.environ.get("COWRIE_LOG", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json*")
OC_LOG = os.environ.get("OC_LOG", "/var/tmp/opencanary.log*")
WEBDECOY_LOG = os.environ.get("WEBDECOY_LOG", "/var/tmp/webdecoy.log*")
FEED_MAX = int(os.environ.get("NODEUI_FEED", "500"))
MAX_IPS = int(os.environ.get("NODEUI_MAX_IPS", "20000"))
SESS_MAX = int(os.environ.get("NODEUI_SESS", "300"))   # Deckel verfolgter Shell-Sessions
TAIL_BYTES = 256 * 1024   # beim ersten Lesen nur das Ende antippen

COWRIE_FAILED = "cowrie.login.failed"
COWRIE_SUCCESS = "cowrie.login.success"
COWRIE_LOGIN = (COWRIE_FAILED, COWRIE_SUCCESS)
COWRIE_CLOSED = "cowrie.session.closed"
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
                "domains": [h] if _nl_is_domain(h) else [],
                "hosts": [h] if h else []}
    if eid == "cowrie.command.input":
        inp = e.get("input") or ""
        if not (_NL_URL.search(inp) or _NL_DLCMD.search(inp)):
            return None
        doms = []
        hosts = []
        for u in _NL_URL.findall(inp):
            h = _nl_host(u)
            if not h:
                continue
            if h not in hosts:
                hosts.append(h)
            if _nl_is_domain(h) and h not in doms:
                doms.append(h)
        return {"ts": ts, "src_ip": ip, "kind": "cmd", "command": inp[:400],
                "domains": doms, "hosts": hosts}
    return None


def parse_cowrie_shell(line):
    """Alles was ein eingeloggter Angreifer tippt: jede cowrie.command.input-Zeile.
    {ts, src_ip, proto, command, sid}. Zeigt die komplette Shell-Aktivitaet nach Login."""
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
    return {"ts": e.get("timestamp"), "src_ip": ip, "proto": proto,
            "command": inp[:600], "sid": (e.get("session") or "")[:12]}


def parse_cowrie_session(line):
    """Sitzungs-Lebenszyklus fuer die Shell-Session-Tabelle: wer ist gerade drin,
    seit wann, wie viele Befehle, aktiv oder geschlossen. Nutzt die cowrie-session-id.
    Liefert {kind, sid, ...}: login (erfolgreiche Anmeldung), cmd (Befehl), closed."""
    try:
        e = json.loads(line)
    except ValueError:
        return None
    sid = e.get("session")
    if not sid:
        return None
    sid = str(sid)[:12]
    eid = e.get("eventid")
    ts = e.get("timestamp")
    if eid == COWRIE_SUCCESS:
        return {"kind": "login", "sid": sid, "ip": e.get("src_ip"),
                "user": e.get("username", ""), "pw": e.get("password", ""), "ts": ts,
                "proto": "TELNET" if e.get("protocol") == "telnet" else "SSH"}
    if eid == "cowrie.command.input":
        return {"kind": "cmd", "sid": sid, "ts": ts}
    if eid == COWRIE_CLOSED:
        return {"kind": "closed", "sid": sid, "ts": ts}
    return None


class State:
    """Geteilter Zustand, unter einem Lock aktualisiert."""

    def __init__(self):
        self.lock = threading.Lock()
        self.offsets = {}                         # tag:path -> byte-offset
        self.feed = collections.deque(maxlen=FEED_MAX)
        self.nachlade = collections.deque(maxlen=200)   # Download-/wget-Versuche
        self.shell = collections.deque(maxlen=400)      # alle Shell-Eingaben nach Login
        self.sessions = collections.OrderedDict()       # sid -> Shell-Session-Dict
        self.logins = collections.deque(maxlen=200)     # erfolgreiche Anmeldungen (mit Passwort)
        self.logins_ok = 0                        # erfolgreiche Anmeldungen gesamt
        self.commands_total = 0                   # abgesetzte Befehle gesamt
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

    def _add_session(self, ev):
        sid = ev["sid"]
        kind = ev["kind"]
        if kind == "login":
            s = self.sessions.get(sid)
            if s is None:
                if len(self.sessions) >= SESS_MAX:
                    self.sessions.popitem(last=False)   # aelteste Session faellt raus
                self.sessions[sid] = {"ip": ev.get("ip"), "user": ev.get("user", ""),
                                      "pw": ev.get("pw", ""),
                                      "proto": ev.get("proto"), "start_ts": ev.get("ts"),
                                      "last_ts": ev.get("ts"), "cmds": 0, "active": True}
            else:
                s["user"] = ev.get("user") or s["user"]
                s["pw"] = ev.get("pw") or s.get("pw", "")
                s["active"] = True
                s["last_ts"] = ev.get("ts") or s["last_ts"]
            self.logins.append({"ts": ev.get("ts"), "src_ip": ev.get("ip"),
                                "username": ev.get("user", ""), "password": ev.get("pw", ""),
                                "proto": ev.get("proto")})
            self.logins_ok += 1
        elif kind == "cmd":
            self.commands_total += 1
            s = self.sessions.get(sid)
            if s is not None:
                s["cmds"] += 1
                s["last_ts"] = ev.get("ts") or s["last_ts"]
        elif kind == "closed":
            s = self.sessions.get(sid)
            if s is not None:
                s["active"] = False
                s["last_ts"] = ev.get("ts") or s["last_ts"]

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
            for fpath in sorted(glob.glob(COWRIE_LOG)):
                self._read_file(fpath, parse_cowrie_session, self._add_session, "se")
            top = sorted(self.ip_counts.items(), key=lambda kv: kv[1][0], reverse=True)[:20]
            sess = [{"sid": sid, "ip": s["ip"], "user": s["user"], "pw": s.get("pw", ""),
                     "proto": s["proto"], "start_ts": s["start_ts"], "last_ts": s["last_ts"],
                     "cmds": s["cmds"], "active": s["active"]}
                    for sid, s in self.sessions.items()]
            # aktive zuerst, dann nach letzter Aktivitaet absteigend
            sess.sort(key=lambda x: (x["active"], x["last_ts"] or ""), reverse=True)
            active_n = sum(1 for s in sess if s["active"])
            mal = set()
            for r in self.nachlade:
                for d in (r.get("hosts") or r.get("domains") or []):
                    mal.add(d)
            return {
                "since": self.since,
                "events_total": self.events_total,
                "ips_total": len(self.ip_counts),
                "ips_capped": len(self.ip_counts) >= MAX_IPS,
                "logins_ok": self.logins_ok,
                "commands_total": self.commands_total,
                "active_sessions": active_n,
                "malware_hosts": len(mal),
                "feed": list(self.feed)[-200:][::-1],   # neueste zuerst
                "nachlade": list(self.nachlade)[-100:][::-1],
                "shell": list(self.shell)[-150:][::-1],
                "sessions": sess[:40],
                "logins": list(self.logins)[-80:][::-1],
                "top": [{"ip": ip, "count": v[0], "last_ts": v[1]} for ip, v in top],
            }


STATE = State()


class Handler(BaseHTTPRequestHandler):
    server_version = "justdns-nodeui"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---- Request-Helfer ----
    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    def _secure(self):
        if SECURE_COOKIE_ENV:
            return True
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _read_json(self):
        if getattr(self, "_json_cache", None) is not None:
            return self._json_cache
        try:
            n = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            n = 0
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            data = {}
        self._json_cache = data if isinstance(data, dict) else {}
        return self._json_cache

    def _send(self, code, body, ctype="application/json", cookie=None, location=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        elif body is None:
            body = b""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _redirect(self, location, cookie=None):
        self._send(302, b"", ctype="text/plain", cookie=cookie, location=location)

    # ---- Auth-Aufloesung ----
    def _resolve(self, conn):
        """(user, session, via). session=None bei Token/Legacy.
        user=None (via 'none'/'pending') = nicht voll angemeldet."""
        raw = nodeauth.read_cookie(self.headers.get("Cookie", ""))
        if raw:
            sess = nodeauth.get_session(conn, raw)
            if sess is not None:
                if sess["mfa_pending"]:
                    return None, sess, "pending"
                user = nodeauth.get_user(conn, sess["user_id"])
                if user and not user["disabled"]:
                    return user, sess, "session"
        authz = self.headers.get("Authorization", "")
        if authz.startswith("Bearer "):
            tok = authz[7:].strip()
            if tok.startswith(nodeauth.TOKEN_PREFIX):
                user = nodeauth.user_for_api_token(conn, tok)
                if user:
                    return user, None, "token"
            elif TOKEN and hmac.compare_digest(tok, TOKEN):
                return "legacy", None, "legacy"
        return None, None, "none"

    def _state_dict(self, conn, user, sess):
        needs_setup = nodeauth.user_count(conn) == 0
        d = {"needs_setup": needs_setup, "authenticated": False, "issuer": nodeauth.ISSUER}
        if user and user != "legacy":
            d["authenticated"] = True
            d["user"] = {"id": user["id"], "username": user["username"],
                         "role": user["role"], "is_owner": bool(user["is_owner"]),
                         "mfa": bool(user["mfa_secret"]),
                         "must_enroll": nodeauth.must_enroll_mfa(conn, user)}
            if sess is not None:
                d["csrf"] = sess["csrf"]
            d["global_mfa"] = nodeauth.global_mfa_enforced(conn)
        return d

    # ---- Gates ----
    def _gate_get(self, conn, path):
        user, sess, via = self._resolve(conn)
        api = path.startswith("/api/")
        if nodeauth.user_count(conn) == 0:
            self._send(401, {"error": "needs_setup"}) if api else self._redirect("/setup")
            return None
        if via == "legacy":
            if path == "/api/overview":
                return "legacy"
            self._send(403, {"error": "forbidden"})
            return None
        if user is None or user == "legacy":
            self._send(401, {"error": "unauthenticated"}) if api else self._redirect("/login")
            return None
        if nodeauth.must_enroll_mfa(conn, user) and path != "/account":
            if api:
                self._send(403, {"error": "mfa_enrollment_required"})
            else:
                self._redirect("/account")
            return None
        return user

    def _gate_post(self, conn, path):
        user, sess, via = self._resolve(conn)
        if user is None or user == "legacy" or sess is None:
            self._send(401, {"error": "unauthenticated"})
            return None, None
        if self.headers.get("X-CSRF-Token", "") != (sess["csrf"] or ""):
            self._send(403, {"error": "bad_csrf"})
            return None, None
        if nodeauth.must_enroll_mfa(conn, user) and not path.startswith("/api/account/"):
            self._send(403, {"error": "mfa_enrollment_required"})
            return None, None
        return user, sess

    # ---- GET ----
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        conn = nodeauth.connect()
        try:
            if path == "/healthz":
                self._send(200, {"status": "ok"}); return
            if path == "/api/auth/state":
                user, sess, _ = self._resolve(conn)
                self._send(200, self._state_dict(conn, user, sess)); return
            if path == "/login":
                self._send(200, LOGIN_HTML, ctype="text/html; charset=utf-8"); return
            if path == "/setup":
                if nodeauth.user_count(conn) == 0:
                    self._send(200, SETUP_HTML, ctype="text/html; charset=utf-8")
                else:
                    self._redirect("/login")
                return
            user = self._gate_get(conn, path)
            if user is None:
                return
            if path in ("/", "/index.html"):
                self._send(200, INDEX_HTML, ctype="text/html; charset=utf-8"); return
            if path == "/account":
                self._send(200, ACCOUNT_HTML, ctype="text/html; charset=utf-8"); return
            if path == "/api/overview":
                self._send(200, STATE.poll()); return
            if path == "/api/account/tokens":
                rows = [dict(r) for r in nodeauth.list_api_tokens(conn, user["id"])]
                self._send(200, {"tokens": rows}); return
            if path == "/api/admin/users":
                if user["role"] != "admin":
                    self._send(403, {"error": "forbidden"}); return
                self._send(200, {"users": [dict(r) for r in nodeauth.list_users(conn)],
                                 "global_mfa": nodeauth.global_mfa_enforced(conn)}); return
            if path == "/api/admin/audit":
                if user["role"] != "admin":
                    self._send(403, {"error": "forbidden"}); return
                self._send(200, {"audit": [dict(r) for r in nodeauth.list_audit(conn)]}); return
            self._send(404, {"error": "not_found"})
        finally:
            conn.close()

    # ---- POST ----
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        body = self._read_json()           # Body IMMER lesen (Connection: close)
        conn = nodeauth.connect()
        try:
            if path == "/setup":
                self._do_setup(conn, body); return
            if path == "/login":
                self._do_login(conn, body); return
            if path == "/login/mfa":
                self._do_login_mfa(conn, body); return
            if path == "/logout":
                self._do_logout(conn); return
            user, sess = self._gate_post(conn, path)
            if user is None:
                return
            if path == "/api/account/password":
                self._acc_password(conn, user, body); return
            if path == "/api/account/mfa/begin":
                self._acc_mfa_begin(conn, user); return
            if path == "/api/account/mfa/enable":
                self._acc_mfa_enable(conn, user, body); return
            if path == "/api/account/mfa/disable":
                self._acc_mfa_disable(conn, user, body); return
            if path == "/api/account/tokens":
                self._acc_token_create(conn, user, body); return
            if path == "/api/account/token/revoke":
                self._acc_token_revoke(conn, user, body); return
            if path.startswith("/api/admin/"):
                if user["role"] != "admin":
                    self._send(403, {"error": "forbidden"}); return
                if path == "/api/admin/users":
                    self._adm_user_create(conn, user, body); return
                if path == "/api/admin/user/update":
                    self._adm_user_update(conn, user, body); return
                if path == "/api/admin/user/reset_mfa":
                    self._adm_user_reset_mfa(conn, user, body); return
                if path == "/api/admin/mfa_global":
                    self._adm_mfa_global(conn, user, body); return
            self._send(404, {"error": "not_found"})
        finally:
            conn.close()

    # ---- Auth-Aktionen ----
    def _do_setup(self, conn, body):
        if nodeauth.user_count(conn) != 0:
            self._send(409, {"error": "already_setup"}); return
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        if not re.match(r"^[A-Za-z0-9_.\-]{2,32}$", username):
            self._send(400, {"error": "bad_username"}); return
        prob = nodeauth.password_problem(password)
        if prob:
            self._send(400, {"error": "weak_password", "detail": prob}); return
        user = nodeauth.create_user(conn, username, password, role="admin", is_owner=True)
        nodeauth.touch_login(conn, user["id"])
        raw, csrf = nodeauth.create_session(conn, user["id"], ip=self._client_ip(),
                                            ua=self.headers.get("User-Agent", ""))
        nodeauth.audit(conn, username, self._client_ip(), "setup_owner")
        self._send(201, {"ok": True, "csrf": csrf},
                   cookie=nodeauth.build_cookie(raw, self._secure()))

    def _do_login(self, conn, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        ip = self._client_ip()
        wait = nodeauth.throttle_blocked(ip, username)
        if wait:
            self._send(429, {"error": "throttled", "retry_s": wait}); return
        user = nodeauth.get_user_by_name(conn, username)
        if not user or user["disabled"] or not nodeauth.verify_password(password, user["pw_hash"]):
            nodeauth.throttle_fail(ip, username)
            nodeauth.audit(conn, username, ip, "login_fail")
            self._send(401, {"error": "bad_credentials"}); return
        nodeauth.throttle_reset(ip, username)
        pending = bool(user["mfa_secret"])
        raw, csrf = nodeauth.create_session(conn, user["id"], ip=ip,
                                            ua=self.headers.get("User-Agent", ""),
                                            mfa_pending=pending)
        cookie = nodeauth.build_cookie(raw, self._secure())
        if pending:
            self._send(200, {"ok": True, "mfa_required": True}, cookie=cookie)
        else:
            nodeauth.touch_login(conn, user["id"])
            nodeauth.audit(conn, username, ip, "login_ok")
            self._send(200, {"ok": True, "mfa_required": False, "csrf": csrf,
                             "must_enroll": nodeauth.must_enroll_mfa(conn, user)}, cookie=cookie)

    def _do_login_mfa(self, conn, body):
        raw = nodeauth.read_cookie(self.headers.get("Cookie", ""))
        sess = nodeauth.get_session(conn, raw) if raw else None
        if not sess or not sess["mfa_pending"]:
            self._send(401, {"error": "no_pending"}); return
        user = nodeauth.get_user(conn, sess["user_id"])
        if not user or not user["mfa_secret"]:
            self._send(401, {"error": "no_pending"}); return
        code = (body.get("code") or "").strip()
        ip = self._client_ip()
        ok = nodeauth.totp_verify(conn, user["id"], user["mfa_secret"], code)
        if not ok and nodeauth.consume_recovery(conn, user["id"], code):
            ok = True
        if not ok:
            nodeauth.throttle_fail(ip, user["username"])
            nodeauth.audit(conn, user["username"], ip, "mfa_fail")
            self._send(401, {"error": "bad_code"}); return
        nodeauth.promote_session(conn, raw)
        nodeauth.touch_login(conn, user["id"])
        nodeauth.throttle_reset(ip, user["username"])
        nodeauth.audit(conn, user["username"], ip, "login_ok_mfa")
        sess2 = nodeauth.get_session(conn, raw)
        self._send(200, {"ok": True, "csrf": sess2["csrf"] if sess2 else ""})

    def _do_logout(self, conn):
        raw = nodeauth.read_cookie(self.headers.get("Cookie", ""))
        if raw:
            nodeauth.destroy_session(conn, raw)
        self._send(200, {"ok": True}, cookie=nodeauth.clear_cookie(self._secure()))

    # ---- Konto ----
    def _acc_password(self, conn, user, body):
        if not nodeauth.verify_password(body.get("current") or "", user["pw_hash"]):
            self._send(400, {"error": "bad_current"}); return
        prob = nodeauth.password_problem(body.get("new") or "")
        if prob:
            self._send(400, {"error": "weak_password", "detail": prob}); return
        nodeauth.set_password(conn, user["id"], body.get("new"))
        nodeauth.destroy_user_sessions(conn, user["id"])
        nodeauth.audit(conn, user["username"], self._client_ip(), "password_change")
        self._send(200, {"ok": True, "relogin": True},
                   cookie=nodeauth.clear_cookie(self._secure()))

    def _acc_mfa_begin(self, conn, user):
        secret = nodeauth.new_totp_secret()
        self._send(200, {"secret": secret,
                         "uri": nodeauth.totp_uri(user["username"], secret)})

    def _acc_mfa_enable(self, conn, user, body):
        secret = (body.get("secret") or "").strip()
        code = (body.get("code") or "").strip()
        if not secret or not nodeauth.totp_verify(conn, user["id"], secret, code, record=False):
            self._send(400, {"error": "bad_code"}); return
        conn.execute("UPDATE auth_users SET mfa_secret=? WHERE id=?", (secret, user["id"]))
        conn.commit()
        codes = nodeauth.gen_recovery_codes(conn, user["id"])
        nodeauth.audit(conn, user["username"], self._client_ip(), "mfa_enable")
        self._send(200, {"ok": True, "recovery": codes})

    def _acc_mfa_disable(self, conn, user, body):
        enforced = bool(user["mfa_enforced"]) or nodeauth.global_mfa_enforced(conn)
        if enforced:
            self._send(403, {"error": "mfa_enforced"}); return
        if not nodeauth.verify_password(body.get("password") or "", user["pw_hash"]):
            self._send(400, {"error": "bad_current"}); return
        conn.execute("UPDATE auth_users SET mfa_secret=NULL WHERE id=?", (user["id"],))
        conn.execute("DELETE FROM auth_recovery WHERE user_id=?", (user["id"],))
        conn.commit()
        nodeauth.audit(conn, user["username"], self._client_ip(), "mfa_disable")
        self._send(200, {"ok": True})

    def _acc_token_create(self, conn, user, body):
        raw = nodeauth.create_api_token(conn, user["id"], (body.get("label") or "")[:64])
        nodeauth.audit(conn, user["username"], self._client_ip(), "token_create")
        self._send(201, {"ok": True, "token": raw})

    def _acc_token_revoke(self, conn, user, body):
        try:
            tid = int(body.get("id"))
        except (TypeError, ValueError):
            self._send(400, {"error": "bad_id"}); return
        ok = nodeauth.revoke_api_token(conn, user["id"], tid)
        self._send(200 if ok else 404, {"ok": ok})

    # ---- Admin ----
    def _adm_user_create(self, conn, actor, body):
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        role = body.get("role") or "viewer"
        if role not in ("admin", "viewer"):
            self._send(400, {"error": "bad_role"}); return
        if not re.match(r"^[A-Za-z0-9_.\-]{2,32}$", username):
            self._send(400, {"error": "bad_username"}); return
        if nodeauth.get_user_by_name(conn, username):
            self._send(409, {"error": "exists"}); return
        prob = nodeauth.password_problem(password)
        if prob:
            self._send(400, {"error": "weak_password", "detail": prob}); return
        u = nodeauth.create_user(conn, username, password, role=role,
                                 mfa_enforced=bool(body.get("mfa_enforced")),
                                 created_by=actor["id"])
        nodeauth.audit(conn, actor["username"], self._client_ip(), "user_create", username)
        self._send(201, {"ok": True, "id": u["id"]})

    def _adm_user_update(self, conn, actor, body):
        try:
            uid = int(body.get("id"))
        except (TypeError, ValueError):
            self._send(400, {"error": "bad_id"}); return
        target = nodeauth.get_user(conn, uid)
        if not target:
            self._send(404, {"error": "no_user"}); return
        if target["is_owner"] and (body.get("role") == "viewer" or body.get("disabled")):
            self._send(403, {"error": "owner_protected"}); return
        fields, params = [], []
        if body.get("role") in ("admin", "viewer"):
            fields.append("role=?"); params.append(body["role"])
        if "disabled" in body:
            fields.append("disabled=?"); params.append(1 if body["disabled"] else 0)
        if "mfa_enforced" in body:
            fields.append("mfa_enforced=?"); params.append(1 if body["mfa_enforced"] else 0)
        if not fields:
            self._send(400, {"error": "nothing"}); return
        params.append(uid)
        conn.execute("UPDATE auth_users SET " + ",".join(fields) + " WHERE id=?", params)
        conn.commit()
        if body.get("disabled"):
            nodeauth.destroy_user_sessions(conn, uid)
        nodeauth.audit(conn, actor["username"], self._client_ip(), "user_update", target["username"])
        self._send(200, {"ok": True})

    def _adm_user_reset_mfa(self, conn, actor, body):
        try:
            uid = int(body.get("id"))
        except (TypeError, ValueError):
            self._send(400, {"error": "bad_id"}); return
        target = nodeauth.get_user(conn, uid)
        if not target:
            self._send(404, {"error": "no_user"}); return
        conn.execute("UPDATE auth_users SET mfa_secret=NULL WHERE id=?", (uid,))
        conn.execute("DELETE FROM auth_recovery WHERE user_id=?", (uid,))
        conn.execute("DELETE FROM auth_totp_used WHERE user_id=?", (uid,))
        conn.commit()
        nodeauth.destroy_user_sessions(conn, uid)
        nodeauth.audit(conn, actor["username"], self._client_ip(), "user_reset_mfa", target["username"])
        self._send(200, {"ok": True})

    def _adm_mfa_global(self, conn, actor, body):
        nodeauth.set_global_mfa(conn, bool(body.get("enforced")))
        nodeauth.audit(conn, actor["username"], self._client_ip(), "mfa_global",
                       "on" if body.get("enforced") else "off")
        self._send(200, {"ok": True, "global_mfa": nodeauth.global_mfa_enforced(conn)})


INDEX_HTML = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>JustDNS Honeypot Node</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0b0f17; --panel1:#121829; --panel2:#0d1320; --line:#1e2940; --line2:#28344f;
  --ink:#e7ecf5; --mut:#8a98b5; --dim:#7d8aa8;
  --green:#3ddc84; --green2:#6cffa6; --greenln:#1d5236; --greenbg:#0f2a1a;
  --amber:#f5a524; --red:#ff5964; --blue:#5b9bff; --violet:#8b7dff; --teal:#36d1c4;
  --sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{margin:0}
body{font-family:var(--sans);font-size:14px;line-height:1.45;-webkit-font-smoothing:antialiased;background:var(--bg);color:var(--ink)}
::selection{background:#24415a;color:#fff}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:#223040;border-radius:6px}::-webkit-scrollbar-thumb:hover{background:#2c3e50}::-webkit-scrollbar-track{background:transparent}
a,button{color:inherit;font:inherit}
:focus-visible{outline:2px solid var(--blue);outline-offset:2px;border-radius:6px}
.tnum{font-variant-numeric:tabular-nums}
.mono{font-family:var(--mono)}
.wrap{max-width:1180px;margin:0 auto;padding:16px 18px 28px}
/* topbar */
.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.brand{display:flex;align-items:center;gap:11px;font-weight:800}
.logo{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;background:linear-gradient(140deg,var(--blue),var(--violet));color:#07101a;font-weight:800;font-size:17px}
.brand b{font-size:15px;letter-spacing:-.01em;line-height:1.1}
.brand small{display:block;color:var(--mut);font-weight:600;font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;margin-top:2px}
.spacer{flex:1}
.user{display:flex;align-items:center;gap:10px}
.badge{font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:3px 7px;border-radius:999px;border:1px solid}
.b-mfa{color:var(--green);border-color:rgba(61,220,132,.4);background:rgba(61,220,132,.08)}
.av{width:32px;height:32px;border-radius:50%;background:conic-gradient(from 210deg,var(--blue),var(--violet),var(--teal),var(--blue));display:grid;place-items:center;font-weight:700;color:#07101a;font-size:11px}
.ux b{font-size:13px}.ux small{display:block;color:var(--mut);font-size:11px}
.lg{appearance:none;border:1px solid var(--line2);background:#121a2c;color:var(--mut);border-radius:9px;padding:7px 11px;font-size:12px;font-weight:600;cursor:pointer}
.lg:hover{color:var(--ink);border-color:#38486a}
/* status banner */
.status{background:linear-gradient(180deg,var(--greenbg),#0c1f14);border:1px solid var(--greenln);border-radius:16px;padding:18px 20px;margin-bottom:16px;display:flex;align-items:center;gap:15px}
.status.warn{background:linear-gradient(180deg,#2a2111,#1f1708);border-color:#5a4418}
.ring{width:42px;height:42px;border-radius:50%;border:4px solid rgba(108,255,166,.22);border-top-color:var(--green2);animation:spin 2.4s linear infinite;flex:0 0 auto}
.status.warn .ring{border-color:rgba(245,165,36,.22);border-top-color:var(--amber)}
@keyframes spin{to{transform:rotate(360deg)}}
.status .big2{font-size:20px;font-weight:800;color:var(--green2)}
.status.warn .big2{color:var(--amber)}
.status .sub{color:#8fe8b2;font-size:12.5px;margin-top:3px}
.status.warn .sub{color:#e6c88a}
/* tiles */
.big{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:16px}
.tile{background:linear-gradient(180deg,var(--panel1),var(--panel2));border:1px solid var(--line);border-radius:16px;padding:20px}
.tile .v{font-size:38px;font-weight:800;letter-spacing:-.02em;line-height:1;display:flex;align-items:center;gap:10px}
.tile .k{color:var(--mut);font-size:11.5px;text-transform:uppercase;letter-spacing:.08em;margin-top:9px;font-weight:600}
.tile.live{background:linear-gradient(180deg,var(--greenbg),#0c1f14);border-color:var(--greenln)}
.v.g{color:var(--green)}.v.a{color:var(--amber)}.v.r{color:var(--red)}
.pulse{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--green2);box-shadow:0 0 0 0 rgba(108,255,166,.6);animation:pz 1.7s infinite;flex:0 0 auto}
@keyframes pz{70%{box-shadow:0 0 0 9px rgba(108,255,166,0)}100%{box-shadow:0 0 0 0 rgba(108,255,166,0)}}
/* panels */
.panel{background:linear-gradient(180deg,var(--panel1),var(--panel2));border:1px solid var(--line);border-radius:16px;overflow:hidden}
.wide{margin-bottom:16px}
.ph{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid var(--line);color:var(--mut);font-size:12px;letter-spacing:.08em;text-transform:uppercase;font-weight:700}
.ph .live{color:var(--green2);font-size:11px;text-transform:none;letter-spacing:0;display:flex;align-items:center;gap:7px}
.ph .live .pulse{width:8px;height:8px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
table{width:100%;border-collapse:collapse}
thead th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;padding:9px 16px;border-bottom:1px solid var(--line)}
tbody td{padding:10px 16px;border-bottom:1px solid #18223a;font-size:13px;vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover td{background:#121a2c}
td.ip,.ip{font-family:var(--mono);color:#8fb6ff;cursor:pointer}
.ip:hover{text-decoration:underline}
td.n{text-align:right;font-family:var(--mono);color:var(--mut)}
.sidtag{font-family:var(--mono);font-size:10.5px;color:var(--mut);background:#121a2c;border:1px solid var(--line);border-radius:5px;padding:1px 6px}
.sdot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:1px}
td.livec{color:var(--green2)}td.closedc{color:var(--mut)}
.usr{color:var(--ink);font-weight:500}
.pw{color:var(--amber);font-family:var(--mono)}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font:700 10.5px/1.6 var(--mono);text-transform:uppercase;letter-spacing:.03em}
.t-ssh{background:rgba(54,209,196,.14);color:var(--teal)}.t-telnet{background:rgba(139,125,255,.16);color:#9b8dff}
.t-http{background:rgba(245,165,36,.16);color:var(--amber)}.t-oth{background:#1d2530;color:var(--mut)}
/* command feed */
.cmdfeed{display:flex;flex-direction:column;max-height:360px;overflow:auto}
.cmd{display:grid;grid-template-columns:66px 118px 1fr;gap:10px;align-items:baseline;padding:8px 16px;border-bottom:1px solid #18223a;font-size:12.5px}
.cmd:last-child{border-bottom:0}
.cmd .ct{color:var(--dim);font-family:var(--mono);font-size:11px}
.cmd .cip{color:#8b9bbe;font-family:var(--mono);cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cmd .cx{font-family:var(--mono);color:#8fe8b2;white-space:pre-wrap;word-break:break-all}
.cmd .cx .prompt{color:#4fe08a;margin-right:6px}
.cmd .cx .dl{color:#ffd166}.cmd .cx .dg{color:#ff7a7a}
.scrollt{max-height:360px;overflow:auto}
.empty{padding:26px 16px;color:var(--dim);font-size:13px;text-align:center}
.foot{margin:20px 2px 2px;color:var(--mut);font-size:11.5px;display:flex;gap:9px;flex-wrap:wrap;align-items:center}
.foot .d2{width:4px;height:4px;border-radius:50%;background:var(--line2)}
@media(max-width:900px){.big{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}.wide .scrollt{overflow:auto}}
@media(max-width:560px){.big{grid-template-columns:1fr 1fr}.tile .v{font-size:30px}.status{flex-wrap:wrap}}
</style></head>
<body>
<!-- Node-UI: STATUS BOARD. Honeypot-Operator-Wallboard: wer ist gerade in der Shell,
     welche Befehle laufen live, wer hat sich erfolgreich angemeldet. Alles aus /api/overview. -->
<div class="wrap">
  <div class="top">
    <div class="brand"><span class="logo">N</span><div><b>Honeypot Node</b><small id="hostlbl">honeypot&nbsp;node</small></div></div>
    <div class="spacer"></div>
    <div class="user" id="userbar" style="display:none"></div>
  </div>

  <div class="status" id="status">
    <div class="ring"></div>
    <div><div class="big2" id="st-head">Node aktiv &middot; Honeypot laeuft</div>
    <div class="sub" id="st-sub">Warte auf Events&hellip;</div></div>
  </div>

  <div class="big">
    <div class="tile live"><div class="v g"><span class="pulse"></span><span class="tnum" id="kp-active">0</span></div><div class="k">Aktive Shell-Sessions</div></div>
    <div class="tile"><div class="v tnum" id="kp-logins">0</div><div class="k">Erfolgreiche Logins</div></div>
    <div class="tile"><div class="v a tnum" id="kp-cmds">0</div><div class="k">Befehle erfasst</div></div>
    <div class="tile"><div class="v r tnum" id="kp-mal">0</div><div class="k">Malware-Hosts</div></div>
  </div>

  <div class="panel wide">
    <div class="ph"><span>Aktive Shell-Sessions &middot; wer ist gerade drin</span><span class="live"><span class="pulse"></span>live</span></div>
    <div class="scrollt">
      <table>
        <thead><tr><th>Quell-IP</th><th>User</th><th>Dienst</th><th>Session</th><th>Seit (Wien)</th><th>Dauer</th><th>Befehle</th><th>Zustand</th></tr></thead>
        <tbody id="sess"></tbody>
      </table>
    </div>
  </div>

  <div class="two">
    <div class="panel">
      <div class="ph"><span>Abgesetzte Befehle &middot; live</span><span class="live"><span class="pulse"></span>live</span></div>
      <div class="cmdfeed" id="cmd"></div>
    </div>
    <div class="panel">
      <div class="ph"><span>Erfolgreiche Anmeldungen</span></div>
      <div class="scrollt"><table><tbody id="login"></tbody></table></div>
    </div>
  </div>

  <div class="foot">
    <span>Lokale UI des Node-Betreibers</span><span class="d2"></span>
    <span>Daten bleiben lokal</span><span class="d2"></span>
    <span id="foot-since">&nbsp;</span>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

const VIENNA = new Intl.DateTimeFormat('de-AT',{timeZone:'Europe/Vienna',hour:'2-digit',minute:'2-digit',second:'2-digit'});
function toDate(t){
  if(!t) return null;
  let s = String(t).trim();
  if(/^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}/.test(s)) s = s.replace(' ','T');
  if(!/[Zz]|[+\\-]\\d{2}:?\\d{2}$/.test(s)) s += 'Z';
  const d = new Date(s); return isNaN(d) ? null : d;
}
function clockTs(t){ const d = toDate(t); return d ? VIENNA.format(d) : ''; }
function ago(t){
  const d = toDate(t); if(!d) return '';
  let sec = Math.max(0, Math.round((Date.now()-d.getTime())/1000));
  if(sec < 60) return 'vor '+sec+'s';
  if(sec < 3600) return 'vor '+Math.floor(sec/60)+'m';
  return 'vor '+Math.floor(sec/3600)+'h';
}
function dur(startTs,lastTs,active){
  const s = toDate(startTs); if(!s) return '';
  const end = active ? Date.now() : (toDate(lastTs)||s).getTime();
  let sec = Math.max(0, Math.round((end - s.getTime())/1000));
  const h=Math.floor(sec/3600); sec-=h*3600; const m=Math.floor(sec/60); const ss=sec-m*60;
  if(h) return h+'h '+String(m).padStart(2,'0')+'m';
  return m+'m '+String(ss).padStart(2,'0')+'s';
}
function svcClass(s){ s=(s||'').toUpperCase(); if(s==='SSH')return 't-ssh'; if(s==='TELNET')return 't-telnet'; if(s==='HTTP')return 't-http'; return 't-oth'; }
function hl(cmd){
  let c = esc(cmd);
  c = c.replace(/(wget|curl|tftp|ftpget|lwp-download|fetch)/gi,'<span class="dg">$1</span>');
  c = c.replace(/(busybox|chmod|\\.\\/[\\w.\\-]+)/gi,'<span class="dl">$1</span>');
  return c;
}

async function loadUser(){
  try{
    const r = await fetch('/api/auth/state',{headers:{'Accept':'application/json'}});
    if(!r.ok) return;
    const d = await r.json();
    if(!d || !d.authenticated || !d.user) return;
    const u = d.user;
    const initials = (u.username||'?').slice(0,2).toUpperCase();
    $('userbar').innerHTML =
      (u.mfa ? '<span class="badge b-mfa">MFA</span>' : '')
      + '<div class="av">'+esc(initials)+'</div>'
      + '<div class="ux"><b>'+esc(u.username)+'</b><small>'+esc(u.role==='admin'?'Admin':'Viewer')+'</small></div>'
      + '<a class="lg" href="/account">Konto</a>'
      + '<button class="lg" onclick="logout()">Abmelden</button>';
    $('userbar').style.display = 'flex';
  }catch(e){}
}
async function logout(){
  try{ await fetch('/logout',{method:'POST',headers:{'X-CSRF-Token':(window.__csrf||'')}}); }catch(e){}
  location.href = '/login';
}

async function tick(){
  let d;
  try { const r = await fetch('/api/overview'); if(r.status===401){ location.href='/login'; return; } d = await r.json(); }
  catch(e){ return; }

  $('kp-active').textContent = d.active_sessions||0;
  $('kp-logins').textContent = d.logins_ok||0;
  $('kp-cmds').textContent = d.commands_total||0;
  $('kp-mal').textContent = d.malware_hosts||0;

  // Status-Banner
  const last = (d.feed && d.feed[0] && d.feed[0].ts) || d.since;
  const act = d.active_sessions||0;
  $('status').className = 'status';
  $('st-head').textContent = 'Node gesund \u00b7 Honeypot aktiv';
  const inShell = act>0 ? (' \u00b7 '+(act===1?'1 Angreifer in der Shell':act+' Angreifer in der Shell')) : '';
  $('st-sub').textContent =
    (last ? 'Letztes Event '+ago(last) : 'Noch keine Events')
    + ' \u00b7 '+(d.events_total||0)+' Login-Versuche'+inShell;

  // Aktive Shell-Sessions
  let sh = '';
  for(const s of (d.sessions||[])){
    const liveState = s.active;
    sh += '<tr>'
      + '<td class="ip" onclick="flt(\\''+esc(s.ip)+'\\')">'+esc(s.ip)+'</td>'
      + '<td class="usr">'+esc(s.user||'-')+(s.pw?' <span class="pw">'+esc(s.pw)+'</span>':'')+'</td>'
      + '<td><span class="tag '+svcClass(s.proto)+'">'+esc(s.proto||'?')+'</span></td>'
      + '<td><span class="sidtag">'+esc(s.sid)+'</span></td>'
      + '<td class="mono" style="color:var(--mut)">'+esc(clockTs(s.start_ts))+'</td>'
      + '<td class="mono">'+esc(dur(s.start_ts,s.last_ts,s.active))+'</td>'
      + '<td class="n" style="text-align:left;color:var(--ink)">'+(s.cmds||0)+'</td>'
      + '<td class="'+(liveState?'livec':'closedc')+'"><span class="sdot" style="background:'+(liveState?'var(--green2)':'#5a6782')+'"></span>'+(liveState?'in der Shell':'geschlossen')+'</td>'
      + '</tr>';
  }
  $('sess').innerHTML = sh || '<tr><td colspan="8" class="empty">Noch keine Shell-Sessions &middot; erscheinen, sobald sich ein Angreifer erfolgreich anmeldet</td></tr>';

  // Abgesetzte Befehle (live)
  let cx = '';
  for(const r of (d.shell||[])){
    cx += '<div class="cmd"><span class="ct">'+esc(clockTs(r.ts))+'</span>'
       + '<span class="cip" onclick="flt(\\''+esc(r.src_ip)+'\\')">'+esc(r.src_ip)+'</span>'
       + '<span class="cx"><span class="prompt">$</span>'+hl(r.command)+'</span></div>';
  }
  $('cmd').innerHTML = cx || '<div class="empty">Noch keine Befehle &middot; erscheinen, sobald ein Angreifer eingeloggt ist</div>';

  // Erfolgreiche Anmeldungen (eigener Puffer, nicht aus dem Fail-lastigen Feed gefiltert)
  let lg = '';
  for(const r of (d.logins||[])){
    lg += '<tr><td class="mono" style="white-space:nowrap"><span class="sdot" style="background:var(--green2)"></span>'+esc(clockTs(r.ts))+'</td>'
       + '<td class="ip" onclick="flt(\\''+esc(r.src_ip)+'\\')">'+esc(r.src_ip)+'</td>'
       + '<td class="mono">'+esc(r.username||'-')+' : <span class="pw">'+esc(r.password||'-')+'</span></td></tr>';
    if(lg.length > 20000) break;
  }
  $('login').innerHTML = lg || '<tr><td class="empty" colspan="3">Noch keine erfolgreichen Anmeldungen</td></tr>';

  $('foot-since').textContent = d.since ? ('Feed seit '+clockTs(d.since)) : '';
}
// Klick auf eine IP: in neuem Tab die gleiche Seite (Platzhalter fuer spaeteren Filter)
function flt(ip){ /* reserviert: IP-Fokus */ }

loadUser();
tick();
setInterval(tick, 3000);
</script>
</body></html>"""


_AUTH_CSS = """
:root{--bg:#0b0f17;--panel1:#121829;--panel2:#0d1320;--line:#1e2940;--line2:#28344f;
--ink:#e7ecf5;--mut:#8a98b5;--dim:#7d8aa8;--green:#3ddc84;--green2:#6cffa6;--amber:#f5a524;
--red:#ff5964;--blue:#5b9bff;--violet:#8b7dff;--teal:#36d1c4;
--sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--mono:"IBM Plex Mono",ui-monospace,Consolas,monospace;color-scheme:dark;}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:radial-gradient(1200px 600px at 50% -10%,#101a2e,var(--bg));color:var(--ink);
font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:420px;background:linear-gradient(180deg,var(--panel1),var(--panel2));
border:1px solid var(--line);border-radius:18px;padding:30px 28px;box-shadow:0 24px 60px rgba(0,0,0,.45)}
.logo{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;
background:linear-gradient(140deg,var(--blue),var(--violet));color:#07101a;font-weight:800;font-size:22px}
h1{font-size:19px;margin:16px 0 2px;letter-spacing:-.01em}
.sub{color:var(--mut);margin:0 0 20px;font-size:13px}
label{display:block;font-size:12px;color:var(--mut);font-weight:600;margin:14px 0 6px;text-transform:uppercase;letter-spacing:.04em}
input{width:100%;background:#0b1120;border:1px solid var(--line2);border-radius:10px;color:var(--ink);
font:14px var(--sans);padding:11px 12px;outline:none}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(91,155,255,.18)}
input.mono{font-family:var(--mono);letter-spacing:.14em}
button.primary{width:100%;margin-top:20px;background:linear-gradient(140deg,var(--blue),var(--violet));
color:#07101a;font-weight:700;font-size:14px;border:0;border-radius:10px;padding:12px;cursor:pointer}
button.primary:hover{filter:brightness(1.07)}button.primary:disabled{opacity:.6;cursor:default}
.err{min-height:18px;margin-top:14px;color:#ff8a93;font-size:13px}
.hint{color:var(--dim);font-size:12px;margin-top:16px;text-align:center}
.toggle{margin-top:14px;text-align:center}.toggle a{font-size:12.5px;cursor:pointer}
"""


LOGIN_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Anmelden &middot; JustDNS Node</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<style>__AUTH_CSS__</style></head><body>
<div class="wrap"><div class="card">
<div class="logo">N</div>
<h1>Honeypot Node</h1>
<p class="sub">Anmeldung fuer den Node-Betreiber</p>

<form id="step1" onsubmit="login();return false">
  <label>Benutzername</label><input id="u" autocomplete="username" autofocus>
  <label>Passwort</label><input id="p" type="password" autocomplete="current-password">
  <button class="primary" type="submit">Anmelden</button>
</form>

<form id="step2" style="display:none" onsubmit="mfa();return false">
  <p class="sub" id="mfaHint">Zwei-Faktor-Code aus deiner Authenticator-App.</p>
  <label id="codeLabel">Code (6-stellig)</label>
  <input id="code" class="mono" inputmode="numeric" autocomplete="one-time-code">
  <button class="primary" type="submit">Bestaetigen</button>
  <div class="toggle"><a id="recoToggle" onclick="toggleReco()">Stattdessen Recovery-Code verwenden</a></div>
</form>

<div class="err" id="err"></div>
</div></div>
<script>
const $=id=>document.getElementById(id);
let recoMode=false;
async function boot(){
  try{
    const d=await (await fetch("/api/auth/state")).json();
    if(d.needs_setup){location.href="/setup";return;}
    if(d.authenticated){location.href=d.user&&d.user.must_enroll?"/account":"/";return;}
  }catch(e){}
}
async function login(){
  $("err").textContent="";
  const btn=$("step1").querySelector("button");btn.disabled=true;
  try{
    const r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:$("u").value,password:$("p").value})});
    const d=await r.json();
    if(r.status===429){$("err").textContent="Zu viele Versuche. Bitte "+(d.retry_s||60)+"s warten.";return;}
    if(!r.ok){$("err").textContent="Benutzername oder Passwort falsch.";return;}
    if(d.mfa_required){$("step1").style.display="none";$("step2").style.display="block";$("code").focus();return;}
    location.href=d.must_enroll?"/account":"/";
  }catch(e){$("err").textContent="Verbindungsfehler.";}
  finally{btn.disabled=false;}
}
function toggleReco(){
  recoMode=!recoMode;
  $("codeLabel").textContent=recoMode?"Recovery-Code":"Code (6-stellig)";
  $("mfaHint").textContent=recoMode?"Einmaliger Recovery-Code (Format XXXXX-XXXXX).":"Zwei-Faktor-Code aus deiner Authenticator-App.";
  $("code").setAttribute("inputmode",recoMode?"text":"numeric");
  $("recoToggle").textContent=recoMode?"Stattdessen Authenticator-Code verwenden":"Stattdessen Recovery-Code verwenden";
  $("code").value="";$("code").focus();
}
async function mfa(){
  $("err").textContent="";
  const btn=$("step2").querySelector("button");btn.disabled=true;
  try{
    const r=await fetch("/login/mfa",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({code:$("code").value})});
    const d=await r.json();
    if(r.ok&&d.ok){location.href="/";return;}
    $("err").textContent=recoMode?"Recovery-Code ungueltig oder schon benutzt.":"Code ungueltig. Pruefe die Uhrzeit deines Geraets oder nutze einen Recovery-Code.";
  }catch(e){$("err").textContent="Verbindungsfehler.";}
  finally{btn.disabled=false;}
}
boot();
</script>
</body></html>"""


SETUP_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Einrichtung &middot; JustDNS Node</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<style>__AUTH_CSS__</style></head><body>
<div class="wrap"><div class="card">
<div class="logo">N</div>
<h1>Node einrichten</h1>
<p class="sub">Erster Start dieser Node. Lege jetzt den Administrator an. Danach ist diese Seite dauerhaft geschlossen. Dieser Account kann weitere Nutzer anlegen und Zwei-Faktor verpflichtend machen.</p>
<form onsubmit="setup();return false">
  <label>Benutzername</label><input id="u" autocomplete="username" autofocus>
  <label>Passwort (mind. 12 Zeichen)</label><input id="p" type="password" autocomplete="new-password">
  <label>Passwort wiederholen</label><input id="p2" type="password" autocomplete="new-password">
  <button class="primary" type="submit">Administrator anlegen</button>
</form>
<div class="err" id="err"></div>
<p class="hint">Lokale UI. Zugangsdaten werden nur hier gespeichert, getrennt von jeder anderen Node.</p>
</div></div>
<script>
const $=id=>document.getElementById(id);
async function boot(){
  try{const d=await (await fetch("/api/auth/state")).json();
    if(!d.needs_setup){location.href="/login";}}catch(e){}
}
async function setup(){
  $("err").textContent="";
  if($("p").value!==$("p2").value){$("err").textContent="Passwoerter stimmen nicht ueberein.";return;}
  const btn=document.querySelector("button");btn.disabled=true;
  try{
    const r=await fetch("/setup",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:$("u").value,password:$("p").value})});
    const d=await r.json();
    if(r.status===201&&d.ok){location.href="/";return;}
    if(d.error==="weak_password"){$("err").textContent=d.detail||"Passwort zu schwach.";}
    else if(d.error==="bad_username"){$("err").textContent="Benutzername: 2-32 Zeichen, nur Buchstaben, Ziffern, . _ -";}
    else if(d.error==="already_setup"){location.href="/login";}
    else{$("err").textContent="Fehler bei der Einrichtung.";}
  }catch(e){$("err").textContent="Verbindungsfehler.";}
  finally{btn.disabled=false;}
}
boot();
</script>
</body></html>"""


ACCOUNT_HTML = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Konto &middot; JustDNS Node</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@500&display=swap" rel="stylesheet">
<style>
:root{--bg:#0b0f17;--panel1:#121829;--panel2:#0d1320;--line:#1e2940;--line2:#28344f;
--ink:#e7ecf5;--mut:#8a98b5;--dim:#7d8aa8;--green:#3ddc84;--green2:#6cffa6;--amber:#f5a524;
--red:#ff5964;--blue:#5b9bff;--violet:#8b7dff;--teal:#36d1c4;
--sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
--mono:"IBM Plex Mono",ui-monospace,Consolas,monospace;color-scheme:dark;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:760px;margin:0 auto;padding:18px 18px 40px}
.top{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.logo{width:32px;height:32px;border-radius:9px;display:grid;place-items:center;background:linear-gradient(140deg,var(--blue),var(--violet));color:#07101a;font-weight:800}
.top b{font-size:15px}.spacer{flex:1}
.btn{appearance:none;border:1px solid var(--line2);background:#121a2c;color:var(--mut);border-radius:9px;padding:8px 12px;font:600 12.5px var(--sans);cursor:pointer}
.btn:hover{color:var(--ink);border-color:#38486a}
.card{background:linear-gradient(180deg,var(--panel1),var(--panel2));border:1px solid var(--line);border-radius:16px;padding:20px 20px;margin-bottom:16px}
.card h2{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:0 0 14px;font-weight:700}
label{display:block;font-size:12px;color:var(--mut);font-weight:600;margin:12px 0 6px;text-transform:uppercase;letter-spacing:.04em}
input,select{width:100%;background:#0b1120;border:1px solid var(--line2);border-radius:10px;color:var(--ink);font:14px var(--sans);padding:10px 12px;outline:none}
input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(91,155,255,.18)}
input.mono{font-family:var(--mono);letter-spacing:.1em}
.row{display:flex;gap:10px;flex-wrap:wrap}.row>div{flex:1;min-width:150px}
button.go{margin-top:16px;background:linear-gradient(140deg,var(--blue),var(--violet));color:#07101a;font-weight:700;border:0;border-radius:10px;padding:10px 16px;cursor:pointer}
button.go:hover{filter:brightness(1.07)}button.go.red{background:linear-gradient(140deg,#ff5964,#c0303c);color:#fff}
button.go.ghost{background:#121a2c;color:var(--ink);border:1px solid var(--line2)}
.msg{font-size:13px;margin-top:10px;min-height:16px}.msg.ok{color:var(--green2)}.msg.err{color:#ff8a93}
.badge{font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;padding:3px 7px;border-radius:999px;border:1px solid}
.b-on{color:var(--green);border-color:rgba(61,220,132,.4);background:rgba(61,220,132,.08)}
.b-off{color:var(--mut);border-color:var(--line2)}
.b-admin{color:var(--amber);border-color:rgba(245,165,36,.4);background:rgba(245,165,36,.08)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em;padding:7px 8px;border-bottom:1px solid var(--line)}
td{padding:8px 8px;border-bottom:1px solid #18223a;vertical-align:middle}
.mono{font-family:var(--mono)}.mut{color:var(--mut)}
.code{font-family:var(--mono);background:#0b1120;border:1px solid var(--line2);border-radius:8px;padding:10px 12px;word-break:break-all;font-size:13px;margin-top:8px}
.reco{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
.reco span{font-family:var(--mono);background:#0b1120;border:1px solid var(--line2);border-radius:8px;padding:8px 10px;text-align:center;letter-spacing:.1em}
.banner{background:rgba(245,165,36,.1);border:1px solid rgba(245,165,36,.4);color:#f5c877;border-radius:12px;padding:12px 14px;margin-bottom:16px;font-size:13px}
.note{color:var(--dim);font-size:12px;margin-top:6px}
.hidden{display:none}
.tokline{display:flex;align-items:center;gap:8px;justify-content:space-between;padding:8px 0;border-bottom:1px solid #18223a}
</style></head><body>
<div class="wrap">
  <div class="top"><span class="logo">N</span><b>Konto</b>
    <span class="badge b-off" id="who">&nbsp;</span><div class="spacer"></div>
    <a class="btn" href="/">Zum Dashboard</a>
    <button class="btn" onclick="logout()">Abmelden</button>
  </div>

  <div id="enrollBanner" class="banner hidden">Zwei-Faktor ist fuer dein Konto verpflichtend. Bitte richte es jetzt ein, bevor du das Dashboard nutzen kannst.</div>

  <div class="card">
    <h2>Passwort aendern</h2>
    <label>Aktuelles Passwort</label><input id="pcur" type="password" autocomplete="current-password">
    <div class="row"><div><label>Neues Passwort</label><input id="pnew" type="password" autocomplete="new-password"></div>
    <div><label>Wiederholen</label><input id="pnew2" type="password" autocomplete="new-password"></div></div>
    <button class="go" onclick="changePw()">Passwort speichern</button>
    <div class="msg" id="pwMsg"></div>
  </div>

  <div class="card">
    <h2>Zwei-Faktor (MFA)</h2>
    <div id="mfaState"></div>
  </div>

  <div class="card">
    <h2>API-Tokens</h2>
    <p class="note">Fuer Automatisierung (Bearer-Token, nur Lesezugriff auf diese Node). Wird nur einmal angezeigt.</p>
    <div id="tokList"></div>
    <div class="row" style="margin-top:12px"><div><label>Bezeichnung</label><input id="tokLabel" placeholder="z.B. monitoring"></div></div>
    <button class="go ghost" onclick="createTok()">Token erzeugen</button>
    <div class="code hidden" id="tokNew"></div>
    <div class="msg" id="tokMsg"></div>
  </div>

  <div class="card hidden" id="adminCard">
    <h2>Benutzer &amp; Zugriff (Admin)</h2>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
      <label style="margin:0">Globaler MFA-Zwang</label>
      <button class="btn" id="gmfaBtn" onclick="toggleGlobalMfa()">&nbsp;</button>
      <span class="note">gilt fuer alle Nutzer dieser Node</span>
    </div>
    <table><thead><tr><th>Benutzer</th><th>Rolle</th><th>MFA</th><th>Status</th><th></th></tr></thead>
    <tbody id="userRows"></tbody></table>
    <div style="margin-top:16px;border-top:1px solid var(--line);padding-top:14px">
      <div class="row"><div><label>Neuer Benutzer</label><input id="nuUser" placeholder="name"></div>
      <div><label>Passwort</label><input id="nuPass" type="password"></div>
      <div><label>Rolle</label><select id="nuRole"><option value="viewer">Viewer</option><option value="admin">Admin</option></select></div></div>
      <label style="display:flex;align-items:center;gap:8px;text-transform:none;letter-spacing:0;margin-top:10px">
        <input type="checkbox" id="nuMfa" style="width:auto"> MFA fuer diesen Nutzer verpflichtend</label>
      <button class="go ghost" onclick="createUser()">Benutzer anlegen</button>
      <div class="msg" id="uMsg"></div>
    </div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>(s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let STATE={};
async function j(method,path,body){
  const h={"Content-Type":"application/json"};
  if(method!=="GET"&&STATE.csrf)h["X-CSRF-Token"]=STATE.csrf;
  const r=await fetch(path,{method:method,headers:h,body:body?JSON.stringify(body):undefined});
  let d={};try{d=await r.json();}catch(e){}
  if(r.status===401){location.href="/login";throw new Error("unauth");}
  return {status:r.status,d:d};
}
async function logout(){try{await j("POST","/logout");}catch(e){}location.href="/login";}

async function load(){
  const r=await fetch("/api/auth/state");const d=await r.json();
  if(!d.authenticated){location.href="/login";return;}
  STATE=d;
  $("who").textContent=d.user.username+" / "+(d.user.role==="admin"?"Admin":"Viewer");
  $("who").className="badge "+(d.user.role==="admin"?"b-admin":"b-off");
  if(d.user.must_enroll)$("enrollBanner").classList.remove("hidden");
  renderMfa();loadTokens();
  if(d.user.role==="admin"){$("adminCard").classList.remove("hidden");loadAdmin();}
}

function renderMfa(){
  const on=STATE.user.mfa;const enforced=STATE.global_mfa||STATE.user.must_enroll;
  let h="";
  if(on){
    h='<p><span class="badge b-on">aktiv</span> Zwei-Faktor ist fuer dein Konto eingeschaltet.</p>';
    if(enforced){h+='<p class="note">MFA ist verpflichtend und kann nicht deaktiviert werden.</p>';}
    else{h+='<label>Passwort zum Deaktivieren</label><input id="mfaOffPw" type="password" style="max-width:260px"><br><button class="go red" onclick="mfaDisable()">MFA deaktivieren</button>';}
  }else{
    h='<p><span class="badge b-off">aus</span> Erhoehe die Sicherheit mit einer Authenticator-App (TOTP).</p>'
     +'<button class="go" onclick="mfaBegin()">Zwei-Faktor einrichten</button>'
     +'<div id="mfaEnroll" class="hidden" style="margin-top:14px"></div>';
  }
  h+='<div class="msg" id="mfaMsg"></div>';
  $("mfaState").innerHTML=h;
}
async function mfaBegin(){
  const {d}=await j("POST","/api/account/mfa/begin");
  const box=$("mfaEnroll");box.classList.remove("hidden");
  box.innerHTML='<p class="note">1. Secret in der Authenticator-App eintragen (manuell oder per otpauth-Link):</p>'
   +'<div class="code">'+esc(d.secret)+'</div>'
   +'<p class="note" style="margin-top:8px"><a href="'+esc(d.uri)+'">otpauth-Link oeffnen</a></p>'
   +'<label>2. Aktuellen 6-stelligen Code eingeben</label><input id="mfaCode" class="mono" inputmode="numeric" style="max-width:220px">'
   +'<input type="hidden" id="mfaSecret" value="'+esc(d.secret)+'"><br>'
   +'<button class="go" onclick="mfaEnable()">Aktivieren</button>';
  $("mfaCode").focus();
}
async function mfaEnable(){
  const {status,d}=await j("POST","/api/account/mfa/enable",{secret:$("mfaSecret").value,code:$("mfaCode").value});
  if(status===200&&d.ok){
    let h='<p class="msg ok">MFA aktiviert. Bewahre diese Recovery-Codes sicher auf (jeder nur einmal nutzbar):</p><div class="reco">';
    (d.recovery||[]).forEach(c=>{h+='<span>'+esc(c)+'</span>';});
    h+='</div><button class="go" style="margin-top:14px" onclick="load()">Fertig</button>';
    $("mfaState").innerHTML=h;
  }else{$("mfaMsg").className="msg err";$("mfaMsg").textContent="Code ungueltig. Pruefe die Uhrzeit deines Geraets.";}
}
async function mfaDisable(){
  const {status,d}=await j("POST","/api/account/mfa/disable",{password:($("mfaOffPw")||{}).value||""});
  if(status===200&&d.ok){load();}
  else if(d.error==="mfa_enforced"){$("mfaMsg").className="msg err";$("mfaMsg").textContent="MFA ist verpflichtend.";}
  else{$("mfaMsg").className="msg err";$("mfaMsg").textContent="Passwort falsch.";}
}

async function changePw(){
  const m=$("pwMsg");m.textContent="";
  if($("pnew").value!==$("pnew2").value){m.className="msg err";m.textContent="Neue Passwoerter stimmen nicht ueberein.";return;}
  const {status,d}=await j("POST","/api/account/password",{current:$("pcur").value,new:$("pnew").value});
  if(status===200&&d.ok){m.className="msg ok";m.textContent="Passwort geaendert. Bitte neu anmelden.";setTimeout(()=>location.href="/login",1200);}
  else if(d.error==="weak_password"){m.className="msg err";m.textContent=d.detail||"Passwort zu schwach.";}
  else{m.className="msg err";m.textContent="Aktuelles Passwort falsch.";}
}

async function loadTokens(){
  const {d}=await j("GET","/api/account/tokens");
  let h="";
  (d.tokens||[]).forEach(t=>{
    if(t.revoked)return;
    h+='<div class="tokline"><span>'+esc(t.label||"(ohne Name)")+' <span class="mut mono">#'+t.id+'</span>'
      +(t.last_used_ts?' <span class="mut">zuletzt '+esc(t.last_used_ts)+'</span>':'')+'</span>'
      +'<button class="btn" onclick="revokeTok('+t.id+')">Widerrufen</button></div>';
  });
  $("tokList").innerHTML=h||'<p class="note">Noch keine Tokens.</p>';
}
async function createTok(){
  const {status,d}=await j("POST","/api/account/tokens",{label:$("tokLabel").value});
  if(status===201&&d.token){const box=$("tokNew");box.classList.remove("hidden");
    box.textContent=d.token;$("tokLabel").value="";$("tokMsg").className="msg ok";
    $("tokMsg").textContent="Token erzeugt. Jetzt kopieren, es wird nicht erneut angezeigt.";loadTokens();}
}
async function revokeTok(id){await j("POST","/api/account/token/revoke",{id:id});loadTokens();}

async function loadAdmin(){
  const {d}=await j("GET","/api/admin/users");
  STATE.global_mfa=d.global_mfa;
  $("gmfaBtn").textContent=d.global_mfa?"EIN":"AUS";
  $("gmfaBtn").className="btn";$("gmfaBtn").style.color=d.global_mfa?"var(--green2)":"var(--mut)";
  let h="";
  (d.users||[]).forEach(u=>{
    const self=u.id===STATE.user.id;
    h+='<tr><td>'+esc(u.username)+(u.is_owner?' <span class="badge b-admin">Owner</span>':'')+'</td>'
      +'<td>'+(u.role==="admin"?'<span class="badge b-admin">Admin</span>':'<span class="badge b-off">Viewer</span>')+'</td>'
      +'<td>'+(u.mfa_secret?'<span class="badge b-on">an</span>':(u.mfa_enforced?'<span class="badge b-off">Pflicht</span>':'<span class="badge b-off">aus</span>'))+'</td>'
      +'<td>'+(u.disabled?'<span class="mut">gesperrt</span>':'aktiv')+'</td><td style="text-align:right">';
    if(!u.is_owner&&!self){
      h+='<button class="btn" onclick="uToggleRole('+u.id+',\\''+(u.role==="admin"?"viewer":"admin")+'\\')">'+(u.role==="admin"?"zu Viewer":"zu Admin")+'</button> ';
      h+='<button class="btn" onclick="uToggleEnforce('+u.id+','+(u.mfa_enforced?0:1)+')">'+(u.mfa_enforced?"MFA-Pflicht aus":"MFA-Pflicht an")+'</button> ';
      h+='<button class="btn" onclick="uToggleDisabled('+u.id+','+(u.disabled?0:1)+')">'+(u.disabled?"entsperren":"sperren")+'</button> ';
    }
    if(!self)h+='<button class="btn" onclick="uResetMfa('+u.id+')">MFA ruecksetzen</button>';
    h+='</td></tr>';
  });
  $("userRows").innerHTML=h;
}
async function toggleGlobalMfa(){await j("POST","/api/admin/mfa_global",{enforced:!STATE.global_mfa});loadAdmin();}
async function uToggleRole(id,role){await j("POST","/api/admin/user/update",{id:id,role:role});loadAdmin();}
async function uToggleEnforce(id,v){await j("POST","/api/admin/user/update",{id:id,mfa_enforced:!!v});loadAdmin();}
async function uToggleDisabled(id,v){await j("POST","/api/admin/user/update",{id:id,disabled:!!v});loadAdmin();}
async function uResetMfa(id){await j("POST","/api/admin/user/reset_mfa",{id:id});loadAdmin();}
async function createUser(){
  const m=$("uMsg");m.textContent="";
  const {status,d}=await j("POST","/api/admin/users",{username:$("nuUser").value,password:$("nuPass").value,role:$("nuRole").value,mfa_enforced:$("nuMfa").checked});
  if(status===201&&d.ok){$("nuUser").value="";$("nuPass").value="";$("nuMfa").checked=false;m.className="msg ok";m.textContent="Benutzer angelegt.";loadAdmin();}
  else if(d.error==="weak_password"){m.className="msg err";m.textContent=d.detail||"Passwort zu schwach.";}
  else if(d.error==="exists"){m.className="msg err";m.textContent="Benutzername existiert bereits.";}
  else if(d.error==="bad_username"){m.className="msg err";m.textContent="Benutzername: 2-32 Zeichen, nur Buchstaben, Ziffern, . _ -";}
  else{m.className="msg err";m.textContent="Fehler beim Anlegen.";}
}
load();
</script>
</body></html>"""


LOGIN_HTML = LOGIN_HTML.replace("__AUTH_CSS__", _AUTH_CSS)
SETUP_HTML = SETUP_HTML.replace("__AUTH_CSS__", _AUTH_CSS)


def main():
    nodeauth.init_db()
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    _c = nodeauth.connect()
    first = nodeauth.user_count(_c) == 0
    _c.close()
    print(f"[nodeui] lauscht auf {BIND}:{PORT}", flush=True)
    print(f"[nodeui] auth-db {nodeauth.db_path()} "
          f"({'First-Boot: Admin unter /setup anlegen' if first else 'Login unter /login'})",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
