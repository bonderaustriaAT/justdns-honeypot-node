#!/usr/bin/env python3
"""JustDNS Raw-Decoy (Nicht-HTTP-Dienste: Postgres, MongoDB, Memcached, MQTT).

NUR KOEDER. Oeffnet KEINE echte Schwachstelle:
  * fuehrt NICHTS aus (kein Eval, keine echte DB, kein Broker),
  * liest NIE die Festplatte (alle Antworten stehen fest im Code),
  * speichert nichts, was ein Angreifer schickt, ausser als gekapptes Log.

Es sind die meistgescannten Nicht-HTTP-Dienste. Jede Verbindung ist ein
Angreifer -> die Quell-IP wandert ueber den Shipper in die Intake. Wo es billig
geht, werden Zugangsdaten mitgeschnitten (Postgres-Passwort, MQTT user/pass).

Protokolle und Ports:
  5432   Postgres    StartupMessage -> fragt Cleartext-Passwort -> loggt user+pass
  27017  MongoDB     minimaler isMaster-Responder (Praesenz + Logging)
  11211  Memcached   Zeilenprotokoll (version/stats/get/set), loggt Kommandos
  1883   MQTT        CONNECT parsen -> loggt user/pass -> CONNACK

Schreibt dieselben JSON-Zeilen wie das Web-Decoy (Shipper/nodeui kennen das
Format schon): {ts, src_ip, dst_port, service, method, path, ua, username,
password, body}.

Config (Env):
  RAWDECOY_PG_PORT       Default "5432"   (leer = aus)
  RAWDECOY_MONGO_PORT    Default "27017"  (leer = aus)
  RAWDECOY_MEMCACHED_PORT Default "11211" (leer = aus)
  RAWDECOY_MQTT_PORT     Default "1883"   (leer = aus)
  RAWDECOY_BIND          Default "0.0.0.0"
  RAWDECOY_LOG           Default "/var/tmp/webdecoy.log" (dieselbe Datei wie Web-Decoy)
  RAWDECOY_MAXBODY       Body-Kappung fuers Log, Default 2048

Nur Standardbibliothek.
"""

import datetime
import json
import os
import socket
import socketserver
import struct
import threading

BIND = os.environ.get("RAWDECOY_BIND", "0.0.0.0")
LOG_PATH = os.environ.get("RAWDECOY_LOG", "/var/tmp/webdecoy.log")
MAXBODY = int(os.environ.get("RAWDECOY_MAXBODY", "2048"))
CONN_TIMEOUT = 8.0
READ_CAP = 65536

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


def log_event(service, src_ip, dst_port, username="", password="", method="", body=""):
    write_log({
        "ts": now_iso(),
        "src_ip": src_ip,
        "dst_port": dst_port,
        "service": service,
        "method": method,
        "path": "",
        "ua": "",
        "username": (username or "")[:256],
        "password": (password or "")[:256],
        "body": (body or "")[:MAXBODY],
    })


def _printable(raw):
    """Bytes als gekappten, druckbaren Text fuers Log."""
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return repr(raw)[:MAXBODY]


# --------------------------------------------------------------------------
# Memcached (11211) - Zeilenprotokoll, trivial.
# --------------------------------------------------------------------------
class MemcachedHandler(socketserver.BaseRequestHandler):
    service = "MEMCACHED"
    dst_port = 11211

    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(CONN_TIMEOUT)
        seen = []
        try:
            for _ in range(20):
                line = self._readline()
                if not line:
                    break
                seen.append(line)
                cmd = line.split(" ", 1)[0].lower()
                if cmd == "version":
                    self._send(b"VERSION 1.4.15\r\n")
                elif cmd == "stats":
                    self._send(
                        b"STAT pid 2043\r\nSTAT version 1.4.15\r\n"
                        b"STAT uptime 384201\r\nSTAT curr_connections 10\r\n"
                        b"STAT cmd_get 0\r\nSTAT cmd_set 0\r\nEND\r\n")
                elif cmd in ("get", "gets"):
                    self._send(b"END\r\n")
                elif cmd in ("set", "add", "replace"):
                    # Datenzeile folgt, einmal schlucken, dann STORED.
                    self._readline()
                    self._send(b"STORED\r\n")
                elif cmd == "quit":
                    break
                else:
                    self._send(b"ERROR\r\n")
        except (OSError, socket.timeout):
            pass
        log_event(self.service, ip, self.dst_port, method="memcached",
                  body=" | ".join(seen))

    def _readline(self):
        data = b""
        while b"\n" not in data and len(data) < 4096:
            chunk = self.request.recv(256)
            if not chunk:
                break
            data += chunk
        return data.decode("utf-8", "replace").strip("\r\n")

    def _send(self, b):
        try:
            self.request.sendall(b)
        except OSError:
            pass


# --------------------------------------------------------------------------
# MQTT (1883) - CONNECT parsen (user/pass), CONNACK zurueck.
# --------------------------------------------------------------------------
class MqttHandler(socketserver.BaseRequestHandler):
    service = "MQTT"
    dst_port = 1883

    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(CONN_TIMEOUT)
        user = passwd = ""
        try:
            hdr = self._recvn(1)
            if not hdr:
                return
            ptype = (hdr[0] >> 4) & 0x0F
            rlen = self._read_remaining_length()
            payload = self._recvn(rlen) if rlen else b""
            if ptype == 1 and payload:   # CONNECT
                user, passwd = self._parse_connect(payload)
                # CONNACK: akzeptiert (0x20 0x02 0x00 0x00)
                self._send(b"\x20\x02\x00\x00")
        except (OSError, socket.timeout, struct.error, IndexError):
            pass
        log_event(self.service, ip, self.dst_port, username=user, password=passwd,
                  method="connect")

    def _parse_connect(self, p):
        try:
            i = 0
            nlen = struct.unpack(">H", p[i:i+2])[0]; i += 2
            i += nlen                       # protocol name ("MQTT"/"MQIsdp")
            i += 1                          # protocol level
            flags = p[i]; i += 1
            i += 2                          # keepalive
            # client id
            clen = struct.unpack(">H", p[i:i+2])[0]; i += 2 + clen
            if flags & 0x04:                # will flag -> will topic + message
                for _ in range(2):
                    wlen = struct.unpack(">H", p[i:i+2])[0]; i += 2 + wlen
            user = passwd = ""
            if flags & 0x80:                # username
                ulen = struct.unpack(">H", p[i:i+2])[0]; i += 2
                user = p[i:i+ulen].decode("utf-8", "replace"); i += ulen
            if flags & 0x40:                # password
                plen = struct.unpack(">H", p[i:i+2])[0]; i += 2
                passwd = p[i:i+plen].decode("utf-8", "replace"); i += plen
            return user, passwd
        except (struct.error, IndexError):
            return "", ""

    def _read_remaining_length(self):
        mult = 1
        value = 0
        for _ in range(4):
            b = self._recvn(1)
            if not b:
                break
            value += (b[0] & 0x7F) * mult
            if not (b[0] & 0x80):
                break
            mult *= 128
        return min(value, READ_CAP)

    def _recvn(self, n):
        data = b""
        while len(data) < n:
            chunk = self.request.recv(min(n - len(data), 4096))
            if not chunk:
                break
            data += chunk
        return data

    def _send(self, b):
        try:
            self.request.sendall(b)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Postgres (5432) - StartupMessage, Cleartext-Passwort erfragen, user+pass loggen.
# --------------------------------------------------------------------------
class PostgresHandler(socketserver.BaseRequestHandler):
    service = "POSTGRES"
    dst_port = 5432

    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(CONN_TIMEOUT)
        user = database = passwd = ""
        try:
            params = self._read_startup()
            if params is None:
                return
            user = params.get("user", "")
            database = params.get("database", "")
            # AuthenticationCleartextPassword: 'R' len=8 Int32=3
            self._send(b"R" + struct.pack(">II", 8, 3))
            tag = self._recvn(1)
            if tag == b"p":                 # PasswordMessage
                plen = struct.unpack(">I", self._recvn(4))[0]
                raw = self._recvn(max(0, min(plen - 4, 1024)))
                passwd = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
            # ErrorResponse: Auth fehlgeschlagen, dann Schluss.
            self._send(self._error("28P01", "password authentication failed"))
        except (OSError, socket.timeout, struct.error, IndexError):
            pass
        log_event(self.service, ip, self.dst_port, username=user, password=passwd,
                  method="startup", body=("db=" + database) if database else "")

    def _read_startup(self):
        head = self._recvn(4)
        if len(head) < 4:
            return None
        length = struct.unpack(">I", head)[0]
        body = self._recvn(max(0, min(length - 4, READ_CAP)))
        if len(body) < 4:
            return None
        code = struct.unpack(">I", body[:4])[0]
        if code == 80877103:                # SSLRequest -> 'N', dann echte Startup
            self._send(b"N")
            head = self._recvn(4)
            if len(head) < 4:
                return None
            length = struct.unpack(">I", head)[0]
            body = self._recvn(max(0, min(length - 4, READ_CAP)))
            if len(body) < 4:
                return None
        # ab Byte 4: key\0value\0 ... \0
        parts = body[4:].split(b"\x00")
        params = {}
        i = 0
        while i + 1 < len(parts):
            k = parts[i].decode("utf-8", "replace")
            v = parts[i+1].decode("utf-8", "replace")
            if not k:
                break
            params[k] = v
            i += 2
        return params

    def _error(self, code, msg):
        body = b"S" + b"FATAL\x00" + b"C" + code.encode() + b"\x00" + b"M" + msg.encode() + b"\x00" + b"\x00"
        return b"E" + struct.pack(">I", len(body) + 4) + body

    def _recvn(self, n):
        data = b""
        while len(data) < n:
            chunk = self.request.recv(min(n - len(data), 4096))
            if not chunk:
                break
            data += chunk
        return data

    def _send(self, b):
        try:
            self.request.sendall(b)
        except OSError:
            pass


# --------------------------------------------------------------------------
# MongoDB (27017) - minimaler isMaster/hello-Responder (Praesenz + Logging).
# Kein Cred-Capture (SCRAM ist aufwaendig); die Verbindung allein reicht fuer
# die Blockliste.
# --------------------------------------------------------------------------
class MongoHandler(socketserver.BaseRequestHandler):
    service = "MONGODB"
    dst_port = 27017

    def handle(self):
        ip = self.client_address[0]
        self.request.settimeout(CONN_TIMEOUT)
        try:
            head = self._recvn(4)
            if len(head) == 4:
                mlen = struct.unpack("<I", head)[0]
                self._recvn(max(0, min(mlen - 4, READ_CAP)))  # Rest schlucken
                self._send(self._ismaster_reply())
        except (OSError, socket.timeout, struct.error):
            pass
        log_event(self.service, ip, self.dst_port, method="ismaster")

    def _ismaster_reply(self):
        # Minimales OP_MSG mit kleinem BSON-Dokument {ismaster:true, ok:1.0}.
        doc = self._bson({"ismaster": True, "maxWireVersion": 6, "ok": 1.0})
        section = b"\x00" + doc                 # kind 0 body
        flags = struct.pack("<I", 0)
        body = flags + section
        # msg header: messageLength, requestID, responseTo, opCode(2013=OP_MSG)
        header = struct.pack("<IIII", 16 + len(body), 1, 1, 2013)
        return header + body

    def _bson(self, d):
        out = b""
        for k, v in d.items():
            key = k.encode() + b"\x00"
            if isinstance(v, bool):
                out += b"\x08" + key + (b"\x01" if v else b"\x00")
            elif isinstance(v, float):
                out += b"\x01" + key + struct.pack("<d", v)
            elif isinstance(v, int):
                out += b"\x10" + key + struct.pack("<i", v)
        out += b"\x00"
        return struct.pack("<i", len(out) + 4) + out

    def _recvn(self, n):
        data = b""
        while len(data) < n:
            chunk = self.request.recv(min(n - len(data), 4096))
            if not chunk:
                break
            data += chunk
        return data

    def _send(self, b):
        try:
            self.request.sendall(b)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


def serve(port, handler):
    srv = Server((BIND, port), handler)
    srv.serve_forever()


def main():
    jobs = [
        (os.environ.get("RAWDECOY_PG_PORT", "5432").strip(), PostgresHandler),
        (os.environ.get("RAWDECOY_MONGO_PORT", "27017").strip(), MongoHandler),
        (os.environ.get("RAWDECOY_MEMCACHED_PORT", "11211").strip(), MemcachedHandler),
        (os.environ.get("RAWDECOY_MQTT_PORT", "1883").strip(), MqttHandler),
    ]
    threads = []
    active = []
    for port_s, handler in jobs:
        if not port_s:
            continue
        port = int(port_s)
        t = threading.Thread(target=serve, args=(port, handler), daemon=True)
        t.start()
        threads.append(t)
        active.append((handler.service, port))
    print(f"[rawdecoy] aktiv: {active}, Log {LOG_PATH}", flush=True)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
