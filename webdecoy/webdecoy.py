#!/usr/bin/env python3
"""JustDNS Web-Decoy (HTTP-Familie: HTTP, Docker-API, Elasticsearch).

NUR KOEDER. Dieser Dienst oeffnet KEINE echte Schwachstelle. Er zeigt bewusst
alte, "verwundbar" aussehende Versionen und antwortet auf die Pfade, die Scanner
abklopfen, aber:

  * er fuehrt NICHTS aus (kein Shell, kein Eval, kein Upload wird gespeichert),
  * er liest NIE die Festplatte (alle Antworten stehen fest im Code, in-memory),
  * Path-Traversal laeuft ins Leere: es gibt keinen Dateizugriff, nur ein
    statisches Mapping. "/../../etc/passwd" trifft kein echtes /etc/passwd.

Er protokolliert jeden Request (IP, Port, Methode, Pfad, User-Agent, Basic-Auth
und Form-Credentials, gekappter Body) als JSON-Zeile. Der Shipper liest das Log
wie cowrie.json/opencanary.log und meldet die Angreifer-IPs an die Intake.

Mehrere Ports, je eine Persona:
  80, 8080  -> Web (zufaellige Persona je Node, siehe WEBDECOY_PERSONA)
  2375      -> Docker-API (unauth, beliebtes Ziel fuer Krypto-Miner-Deploys)
  9200      -> Elasticsearch

Config (Env):
  WEBDECOY_WEB_PORTS   Default "80,8080"
  WEBDECOY_DOCKER_PORT Default "2375" (leer = aus)
  WEBDECOY_ELASTIC_PORT Default "9200" (leer = aus)
  WEBDECOY_BIND        Default "0.0.0.0"
  WEBDECOY_PERSONA     Name der Web-Persona (sonst zufaellig je Start)
  WEBDECOY_LOG         Default "/var/tmp/webdecoy.log"
  WEBDECOY_MAXBODY     Body-Kappung fuers Log, Default 8192

Nur Standardbibliothek.
"""

import datetime
import json
import os
import random
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = os.environ.get("WEBDECOY_BIND", "0.0.0.0")
WEB_PORTS = [int(p) for p in os.environ.get("WEBDECOY_WEB_PORTS", "80,8080").split(",") if p.strip()]
DOCKER_PORT = os.environ.get("WEBDECOY_DOCKER_PORT", "2375").strip()
ELASTIC_PORT = os.environ.get("WEBDECOY_ELASTIC_PORT", "9200").strip()
LOG_PATH = os.environ.get("WEBDECOY_LOG", "/var/tmp/webdecoy.log")
MAXBODY = int(os.environ.get("WEBDECOY_MAXBODY", "8192"))
READ_CAP = 1024 * 1024   # Body hoechstens so weit lesen (Socket synchron halten)

# Fake-Secrets: bewusst wertlos/nicht funktional, nur Koeder fuer Harvester.
_FAKE_ENV = (
    "APP_ENV=production\n"
    "APP_DEBUG=false\n"
    "DB_CONNECTION=mysql\n"
    "DB_HOST=127.0.0.1\n"
    "DB_DATABASE=app\n"
    "DB_USERNAME=app\n"
    "DB_PASSWORD=Xk2!placeholder-not-real\n"
    "APP_KEY=base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
)
_FAKE_GIT = "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/app.git\n"

# Pfade, die praktisch jeder Web-Scanner abklopft. Alle Personas antworten darauf,
# damit wir immer etwas fangen. Werte sind fest und harmlos.
COMMON_WEB = {
    "/.env": (200, "text/plain", _FAKE_ENV),
    "/.git/config": (200, "text/plain", _FAKE_GIT),
    "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow:\n"),
    "/server-status": (200, "text/html", "<h1>Apache Status</h1><p>Server uptime: 12 days</p>"),
}

# Web-Personas: Server-Header mit absichtlich alter Version + Startseite + Pfade.
# Alles statisch, kein Code dahinter.
PERSONAS = {
    "apache_old": {
        "server": "Apache/2.4.49 (Unix)",
        "index": (200, "text/html", "<html><body><h1>It works!</h1></body></html>"),
        "paths": {
            "/cgi-bin/": (403, "text/html", "<h1>403 Forbidden</h1>"),
        },
    },
    "wordpress": {
        "server": "Apache/2.4.29 (Ubuntu)",
        "index": (200, "text/html",
                  "<html><head><title>My Blog</title></head><body><h1>My Blog</h1>"
                  "<p>Just another WordPress site</p></body></html>"),
        "paths": {
            "/wp-login.php": (200, "text/html",
                              "<html><body><form method='post' action='/wp-login.php'>"
                              "<input name='log'><input name='pwd' type='password'>"
                              "<input type='submit'></form></body></html>"),
            "/xmlrpc.php": (200, "text/xml", "<?xml version=\"1.0\"?><methodResponse><params>"
                            "<param><value><string>XML-RPC server accepts POST requests only.</string>"
                            "</value></param></params></methodResponse>"),
        },
    },
    "phpmyadmin": {
        "server": "nginx/1.18.0 (Ubuntu)",
        "index": (302, "text/html", ""),   # Location: /phpmyadmin/ (siehe handler)
        "paths": {
            "/phpmyadmin/": (200, "text/html",
                             "<html><body><h1>phpMyAdmin</h1><form method='post'>"
                             "<input name='pma_username'><input name='pma_password' type='password'>"
                             "<input type='submit'></form></body></html>"),
        },
    },
    "springboot": {
        "server": "nginx/1.19.0",
        "index": (200, "text/html", "<html><body>Whitelabel Error Page</body></html>"),
        "paths": {
            "/actuator": (200, "application/json",
                          json.dumps({"_links": {"health": {"href": "/actuator/health"},
                                                 "env": {"href": "/actuator/env"}}})),
            "/actuator/health": (200, "application/json", json.dumps({"status": "UP"})),
            "/actuator/env": (200, "application/json",
                              json.dumps({"activeProfiles": ["prod"],
                                          "propertySources": [{"name": "systemEnvironment",
                                                               "properties": {}}]})),
        },
    },
    "router": {
        "server": "micro_httpd",
        "index": (200, "text/html",
                  "<html><body><h2>Router Login</h2><form method='post' "
                  "action='/boaform/admin/formLogin'><input name='username'>"
                  "<input name='psd' type='password'><input type='submit'></form></body></html>"),
        "paths": {},
    },
}

DOCKER_RESPONSES = {
    "/version": (200, "application/json",
                 json.dumps({"Version": "20.10.7", "ApiVersion": "1.41",
                             "Os": "linux", "Arch": "amd64"})),
    "/info": (200, "application/json",
              json.dumps({"Containers": 0, "Images": 0, "ServerVersion": "20.10.7"})),
    "/_ping": (200, "text/plain", "OK"),
    "/containers/json": (200, "application/json", "[]"),
}
ELASTIC_INDEX = (200, "application/json", json.dumps({
    "name": "node-1", "cluster_name": "elasticsearch",
    "version": {"number": "1.4.2", "lucene_version": "4.10.2"},
    "tagline": "You Know, for Search",
}))
ELASTIC_RESPONSES = {
    "/_cat/indices": (200, "text/plain", ""),
    "/_cluster/health": (200, "application/json", json.dumps({"status": "green"})),
    "/_search": (200, "application/json", json.dumps({"hits": {"total": 0, "hits": []}})),
}

_CRED_USER_KEYS = ("username", "user", "log", "pma_username", "uname", "login", "email", "name")
_CRED_PASS_KEYS = ("password", "pass", "pwd", "psd", "pma_password", "passwd")

_log_lock = threading.Lock()


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_log(rec):
    line = json.dumps(rec, ensure_ascii=False)
    with _log_lock:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def creds_from_body(ctype, body):
    """Form-Credentials aus einem POST-Body ziehen (nur Logging). Kein Eval."""
    user = passwd = ""
    if not body:
        return user, passwd
    text = body
    try:
        if "json" in (ctype or ""):
            data = json.loads(body)
            if isinstance(data, dict):
                pairs = {str(k).lower(): str(v) for k, v in data.items()}
            else:
                pairs = {}
        else:
            parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
            pairs = {k.lower(): v[0] for k, v in parsed.items()}
    except (ValueError, TypeError):
        pairs = {}
    for k in _CRED_USER_KEYS:
        if k in pairs:
            user = pairs[k]; break
    for k in _CRED_PASS_KEYS:
        if k in pairs:
            passwd = pairs[k]; break
    return user[:256], passwd[:256]


def creds_from_auth(header):
    """Basic-Auth-Credentials (nur Logging)."""
    if not header or not header.lower().startswith("basic "):
        return "", ""
    import base64
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8", "replace")
        if ":" in raw:
            u, p = raw.split(":", 1)
            return u[:256], p[:256]
    except (ValueError, UnicodeDecodeError):
        pass
    return "", ""


class DecoyHandler(BaseHTTPRequestHandler):
    server_version = "nginx"
    protocol_version = "HTTP/1.1"
    # vom Server gesetzt:
    role = "web"
    persona = "apache_old"

    def log_message(self, *a):
        pass

    def _server_header(self):
        if self.role == "web":
            return PERSONAS.get(self.persona, PERSONAS["apache_old"])["server"]
        if self.role == "docker":
            return "Docker/20.10.7"
        return "nginx"

    def _respond(self, status, ctype, body):
        data = body.encode("utf-8") if isinstance(body, str) else (body or b"")
        # send_response_only, damit kein automatischer Server-Header von
        # BaseHTTPRequestHandler dazukommt (wir setzen die Persona selbst).
        self.send_response_only(status)
        self.send_header("Server", self._server_header())
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if status == 302 and self.role == "web" and self.persona == "phpmyadmin":
            self.send_header("Location", "/phpmyadmin/")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(data)
            except OSError:
                pass

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return ""
        if length <= 0:
            return ""
        to_read = min(length, READ_CAP)
        raw = self.rfile.read(to_read)
        # Rest wegschlucken, Socket synchron halten
        remaining = length - to_read
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        return raw.decode("utf-8", "replace")

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()[:64]
        try:
            return self.client_address[0]
        except (IndexError, TypeError):
            return "?"

    def _lookup(self, path):
        """Statische Antwort finden. KEIN Dateizugriff, nur feste Maps."""
        if self.role == "docker":
            return DOCKER_RESPONSES.get(path, (404, "application/json",
                                              json.dumps({"message": "page not found"})))
        if self.role == "elastic":
            if path == "/" or path == "":
                return ELASTIC_INDEX
            return ELASTIC_RESPONSES.get(path, (404, "application/json",
                                                json.dumps({"error": "no handler found", "status": 404})))
        # web
        p = PERSONAS.get(self.persona, PERSONAS["apache_old"])
        if path == "/" or path == "":
            return p["index"]
        if path in p["paths"]:
            return p["paths"][path]
        if path in COMMON_WEB:
            return COMMON_WEB[path]
        return (404, "text/html", "<html><head><title>404 Not Found</title></head>"
                "<body><h1>Not Found</h1></body></html>")

    def _handle(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._read_body() if self.command in ("POST", "PUT", "PATCH") else ""
        ctype = self.headers.get("Content-Type", "")
        u1, p1 = creds_from_auth(self.headers.get("Authorization", ""))
        u2, p2 = creds_from_body(ctype, body)
        try:
            dst_port = self.server.server_address[1]
        except (AttributeError, IndexError):
            dst_port = 0
        svc = {"web": "HTTP", "docker": "DOCKER", "elastic": "ELASTIC"}[self.role]
        write_log({
            "ts": now_iso(),
            "src_ip": self._client_ip(),
            "dst_port": dst_port,
            "service": svc,
            "method": self.command,
            "path": path[:512],
            "ua": self.headers.get("User-Agent", "")[:256],
            "username": u1 or u2,
            "password": p1 or p2,
            "body": body[:MAXBODY],
        })
        status, rtype, rbody = self._lookup(path)
        self._respond(status, rtype, rbody)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_OPTIONS = _handle


def make_handler(role, persona):
    return type("H", (DecoyHandler,), {"role": role, "persona": persona})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass   # einzelne kaputte Verbindungen nicht laut loggen


def serve(port, role, persona):
    httpd = Server((BIND, port), make_handler(role, persona))
    httpd.serve_forever()


def main():
    persona = os.environ.get("WEBDECOY_PERSONA") or random.choice(list(PERSONAS))
    if persona not in PERSONAS:
        persona = random.choice(list(PERSONAS))
    threads = []
    targets = []
    for port in WEB_PORTS:
        targets.append((port, "web", persona))
    if DOCKER_PORT:
        targets.append((int(DOCKER_PORT), "docker", persona))
    if ELASTIC_PORT:
        targets.append((int(ELASTIC_PORT), "elastic", persona))
    print(f"[webdecoy] Persona {persona}, Ports {[t[0] for t in targets]}, Log {LOG_PATH}", flush=True)
    for port, role, pers in targets:
        t = threading.Thread(target=serve, args=(port, role, pers), daemon=True)
        t.start()
        threads.append(t)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
