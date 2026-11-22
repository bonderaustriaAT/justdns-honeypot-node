#!/usr/bin/env python3
"""Authentifizierung fuer die JustDNS Node-UI (nur Standardbibliothek).

EIGENSTAENDIG fuer DIESE Node. Bewusst NICHT gekoppelt an die Intake-Node oder an
andere Honeypot-Nodes: eigener Store (eigene SQLite-Datei), eigene Sessions, eigene
Secrets, eigenes Cookie, eigenes Token-Praefix. Es gibt keinen gemeinsamen Login,
keinen gemeinsamen Store und kein geteiltes Secret mit irgendeiner anderen Node.

Bausteine (identische Bauart wie anderswo, aber getrennte Daten):
  - Passwort-Hash via scrypt (hashlib), timing-safe Vergleich.
  - Sessions ueber Cookie (nur sha256 des Tokens in der DB), Idle- + Absolut-Timeout.
  - CSRF-Token je Session (Double-Submit ueber Header).
  - TOTP (RFC 6238) fuer optionales MFA, mit Replay-Schutz und Recovery-Codes.
  - Login-Throttle pro IP und pro Benutzer (in-memory).
  - API-Tokens pro Benutzer.
  - Audit-Log.

First-Boot: der erste Admin wird direkt in der UI unter /setup angelegt (kein
Env-Pfad). MFA ist optional; verpflichtend machen (global oder pro Benutzer) kann
nur ein Admin (der erste Admin oder ein von ihm befoerderter).

DB-Pfad: NODEUI_AUTH_DB (Env), sonst /var/lib/justdns-nodeui/auth.db, sonst
~/.justdns-nodeui-auth.db, sonst ./nodeui_auth.db (erste schreibbare Variante).
"""

import base64
import datetime
import hashlib
import hmac
import os
import secrets
import sqlite3
import struct
import threading
import time

# --- Konfiguration (eigene Werte, getrennt von anderen Nodes) ---
COOKIE_NAME = "jdnode_sess"
SESSION_IDLE_S = 1800        # 30 min ohne Aktivitaet
SESSION_ABS_S = 12 * 3600    # 12 h absolut
PW_MIN_LEN = 12
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1              # +/- 1 Schritt Drift
ISSUER = "JustDNS Node"
TOKEN_PREFIX = "jdnt_"       # JustDNS Node Token (API)

# Throttle
MAX_FAILS = 5
LOCKOUT_S = 300              # 5 min Sperre nach MAX_FAILS
FAIL_WINDOW_S = 900          # Fehlversuche aelter als 15 min zaehlen nicht

_fails = {}                  # key -> list[ts]  (key = "ip:<addr>" oder "user:<name>")
_fails_lock = threading.Lock()


# =========================================================================
# DB-Schicht (eigenstaendig, nur sqlite3)
# =========================================================================
_SCHEMA = """
CREATE TABLE IF NOT EXISTS auth_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer',
  is_owner INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  mfa_enforced INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_ts TEXT,
  last_login_ts TEXT
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  token_sha256 TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_ts TEXT, last_seen_ts TEXT, expires_ts TEXT,
  ip TEXT, user_agent TEXT,
  mfa_pending INTEGER NOT NULL DEFAULT 0,
  csrf TEXT
);
CREATE TABLE IF NOT EXISTS auth_recovery (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  code_sha256 TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auth_totp_used (
  user_id INTEGER NOT NULL,
  step INTEGER NOT NULL,
  PRIMARY KEY (user_id, step)
);
CREATE TABLE IF NOT EXISTS auth_api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_sha256 TEXT NOT NULL,
  label TEXT,
  created_ts TEXT,
  last_used_ts TEXT,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS auth_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, actor TEXT, ip TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
"""

_DB_PATH = None
_DB_LOCK = threading.Lock()


def _resolve_db_path():
    env = os.environ.get("NODEUI_AUTH_DB", "").strip()
    cands = []
    if env:
        cands.append(env)
    cands.append("/var/lib/justdns-nodeui/auth.db")
    cands.append(os.path.join(os.path.expanduser("~"), ".justdns-nodeui-auth.db"))
    cands.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "nodeui_auth.db"))
    cands.append("nodeui_auth.db")
    for p in cands:
        d = os.path.dirname(os.path.abspath(p))
        try:
            os.makedirs(d, exist_ok=True)
            # Schreibbarkeit testen
            t = os.path.join(d, ".jdnode_wtest")
            with open(t, "w") as fh:
                fh.write("x")
            os.remove(t)
            return os.path.abspath(p)
        except OSError:
            continue
    return os.path.abspath("nodeui_auth.db")


def db_path():
    global _DB_PATH
    if _DB_PATH is None:
        _DB_PATH = _resolve_db_path()
    return _DB_PATH


def connect():
    conn = sqlite3.connect(db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    with _DB_LOCK:
        conn = connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_setting(conn, key, default=None):
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn, key, value):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    conn.commit()


# =========================================================================
# Passwort-Hashing (scrypt)
# =========================================================================
# N=2**14 (OWASP-Minimum): ca. 16 MB transient je Hash. Bewusst lean (kein
# RAM-Hochdrehen) - Logins sind selten. maxmem explizit, damit die OpenSSL-Grenze
# (32 MB) nicht greift.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_MAXMEM = 48 * 1024 * 1024


def hash_password(pw):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                        p=_SCRYPT_P, dklen=32, maxmem=_SCRYPT_MAXMEM)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(pw, stored):
    try:
        algo, n, r, p, salthex, dkhex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salthex)
        want = bytes.fromhex(dkhex)
        got = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=int(n), r=int(r),
                             p=int(p), dklen=len(want), maxmem=_SCRYPT_MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, want)


def password_problem(pw):
    if not isinstance(pw, str) or len(pw) < PW_MIN_LEN:
        return f"Passwort braucht mindestens {PW_MIN_LEN} Zeichen"
    if len(pw) > 1024:
        return "Passwort zu lang"
    return None


# =========================================================================
# TOTP (RFC 6238)
# =========================================================================
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_at(secret_b32, step):
    pad = "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    msg = struct.pack(">Q", step)
    dig = hmac.new(key, msg, hashlib.sha1).digest()
    off = dig[-1] & 0x0F
    code = (struct.unpack(">I", dig[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_uri(username, secret_b32):
    from urllib.parse import quote
    label = quote(f"{ISSUER}:{username}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(ISSUER)}&algorithm=SHA1"
            f"&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


def _totp_match_step(secret_b32, code, now=None):
    code = (code or "").strip()
    if not code.isdigit():
        return None
    base = int((now or time.time()) // TOTP_PERIOD)
    for d in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        if hmac.compare_digest(_totp_at(secret_b32, base + d), code):
            return base + d
    return None


def totp_verify(conn, user_id, secret_b32, code, record=True, now=None):
    step = _totp_match_step(secret_b32, code, now)
    if step is None:
        return False
    if record:
        row = conn.execute(
            "SELECT 1 FROM auth_totp_used WHERE user_id=? AND step=?",
            (user_id, step)).fetchone()
        if row:
            return False   # bereits verbraucht (Replay)
        conn.execute("INSERT INTO auth_totp_used (user_id, step) VALUES (?, ?)",
                     (user_id, step))
        conn.execute("DELETE FROM auth_totp_used WHERE user_id=? AND step < ?",
                     (user_id, step - 5))
        conn.commit()
    return True


# =========================================================================
# Recovery-Codes
# =========================================================================
def _norm_recovery(code):
    return (code or "").strip().upper().replace("-", "").replace(" ", "")


def gen_recovery_codes(conn, user_id, count=8):
    conn.execute("DELETE FROM auth_recovery WHERE user_id=?", (user_id,))
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()          # 10 hex Zeichen
        pretty = raw[:5] + "-" + raw[5:]
        codes.append(pretty)
        conn.execute(
            "INSERT INTO auth_recovery (user_id, code_sha256, used) VALUES (?, ?, 0)",
            (user_id, hashlib.sha256(raw.encode()).hexdigest()))
    conn.commit()
    return codes


def consume_recovery(conn, user_id, code):
    h = hashlib.sha256(_norm_recovery(code).encode()).hexdigest()
    row = conn.execute(
        "SELECT id FROM auth_recovery WHERE user_id=? AND code_sha256=? AND used=0",
        (user_id, h)).fetchone()
    if not row:
        return False
    conn.execute("UPDATE auth_recovery SET used=1 WHERE id=?", (row["id"],))
    conn.commit()
    return True


# =========================================================================
# Benutzer
# =========================================================================
def user_count(conn):
    return conn.execute("SELECT COUNT(*) AS n FROM auth_users").fetchone()["n"]


def get_user(conn, user_id):
    return conn.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone()


def get_user_by_name(conn, username):
    return conn.execute("SELECT * FROM auth_users WHERE username=?",
                        (username,)).fetchone()


def list_users(conn):
    return conn.execute(
        "SELECT id, username, role, is_owner, mfa_secret, mfa_enforced, disabled, "
        "created_ts, last_login_ts FROM auth_users ORDER BY id").fetchall()


def create_user(conn, username, password, role="viewer", is_owner=False,
                mfa_enforced=False, created_by=None):
    conn.execute(
        "INSERT INTO auth_users (username, pw_hash, role, is_owner, mfa_enforced, "
        "disabled, created_by, created_ts) VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        (username, hash_password(password), role, 1 if is_owner else 0,
         1 if mfa_enforced else 0, created_by, now_iso()))
    conn.commit()
    return get_user_by_name(conn, username)


def set_password(conn, user_id, password):
    conn.execute("UPDATE auth_users SET pw_hash=? WHERE id=?",
                 (hash_password(password), user_id))
    conn.commit()


def touch_login(conn, user_id):
    conn.execute("UPDATE auth_users SET last_login_ts=? WHERE id=?",
                 (now_iso(), user_id))
    conn.commit()


def global_mfa_enforced(conn):
    return get_setting(conn, "auth_mfa_global", "off") == "on"


def set_global_mfa(conn, enforced):
    set_setting(conn, "auth_mfa_global", "on" if enforced else "off")


def must_enroll_mfa(conn, user):
    if user["mfa_secret"]:
        return False
    return bool(user["mfa_enforced"]) or global_mfa_enforced(conn)


# =========================================================================
# Sessions
# =========================================================================
def _hash_token(raw):
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_session(conn, user_id, ip="", ua="", mfa_pending=False):
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = time.time()
    conn.execute(
        "INSERT INTO auth_sessions (token_sha256, user_id, created_ts, last_seen_ts, "
        "expires_ts, ip, user_agent, mfa_pending, csrf) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (_hash_token(raw), user_id, _iso(now), _iso(now), _iso(now + SESSION_ABS_S),
         ip, (ua or "")[:200], 1 if mfa_pending else 0, csrf))
    conn.commit()
    return raw, csrf


def get_session(conn, raw):
    if not raw:
        return None
    row = conn.execute("SELECT * FROM auth_sessions WHERE token_sha256=?",
                       (_hash_token(raw),)).fetchone()
    if not row:
        return None
    now = time.time()
    if now > _ts(row["expires_ts"]) or (now - _ts(row["last_seen_ts"])) > SESSION_IDLE_S:
        conn.execute("DELETE FROM auth_sessions WHERE token_sha256=?",
                     (_hash_token(raw),))
        conn.commit()
        return None
    conn.execute("UPDATE auth_sessions SET last_seen_ts=? WHERE token_sha256=?",
                 (_iso(now), _hash_token(raw)))
    conn.commit()
    return row


def promote_session(conn, raw):
    conn.execute("UPDATE auth_sessions SET mfa_pending=0 WHERE token_sha256=?",
                 (_hash_token(raw),))
    conn.commit()


def destroy_session(conn, raw):
    if raw:
        conn.execute("DELETE FROM auth_sessions WHERE token_sha256=?",
                     (_hash_token(raw),))
        conn.commit()


def destroy_user_sessions(conn, user_id):
    conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
    conn.commit()


def build_cookie(raw, secure, max_age=SESSION_ABS_S):
    parts = [f"{COOKIE_NAME}={raw}", "Path=/", "HttpOnly", "SameSite=Strict",
             f"Max-Age={max_age}"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_cookie(secure):
    parts = [f"{COOKIE_NAME}=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def read_cookie(cookie_header):
    if not cookie_header:
        return ""
    for part in cookie_header.split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE_NAME:
            return v
    return ""


# =========================================================================
# API-Tokens
# =========================================================================
def gen_api_token():
    return TOKEN_PREFIX + secrets.token_hex(24)


def create_api_token(conn, user_id, label=""):
    raw = gen_api_token()
    conn.execute(
        "INSERT INTO auth_api_tokens (user_id, token_sha256, label, created_ts, revoked) "
        "VALUES (?, ?, ?, ?, 0)",
        (user_id, _hash_token(raw), (label or "")[:64], now_iso()))
    conn.commit()
    return raw


def user_for_api_token(conn, raw):
    if not raw or not raw.startswith(TOKEN_PREFIX):
        return None
    row = conn.execute(
        "SELECT t.id AS tid, u.* FROM auth_api_tokens t JOIN auth_users u ON u.id=t.user_id "
        "WHERE t.token_sha256=? AND t.revoked=0 AND u.disabled=0",
        (_hash_token(raw),)).fetchone()
    if row:
        conn.execute("UPDATE auth_api_tokens SET last_used_ts=? WHERE id=?",
                     (now_iso(), row["tid"]))
        conn.commit()
    return row


def list_api_tokens(conn, user_id):
    return conn.execute(
        "SELECT id, label, created_ts, last_used_ts, revoked FROM auth_api_tokens "
        "WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()


def revoke_api_token(conn, user_id, token_id):
    cur = conn.execute(
        "UPDATE auth_api_tokens SET revoked=1 WHERE id=? AND user_id=?",
        (token_id, user_id))
    conn.commit()
    return cur.rowcount > 0


# =========================================================================
# Throttle
# =========================================================================
def _prune(key, now):
    lst = [t for t in _fails.get(key, []) if now - t < FAIL_WINDOW_S]
    if lst:
        _fails[key] = lst
    else:
        _fails.pop(key, None)
    return lst


def throttle_blocked(ip, username):
    now = time.time()
    with _fails_lock:
        for key in (f"ip:{ip}", f"user:{username}"):
            lst = _prune(key, now)
            if len(lst) >= MAX_FAILS and (now - lst[-1]) < LOCKOUT_S:
                return int(LOCKOUT_S - (now - lst[-1]))
    return 0


def throttle_fail(ip, username):
    now = time.time()
    with _fails_lock:
        for key in (f"ip:{ip}", f"user:{username}"):
            _fails.setdefault(key, []).append(now)


def throttle_reset(ip, username):
    with _fails_lock:
        _fails.pop(f"ip:{ip}", None)
        _fails.pop(f"user:{username}", None)


# =========================================================================
# Audit
# =========================================================================
def audit(conn, actor, ip, action, detail=""):
    conn.execute(
        "INSERT INTO auth_audit (ts, actor, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
        (now_iso(), actor or "", ip or "", action, (detail or "")[:400]))
    conn.commit()


def list_audit(conn, limit=200):
    return conn.execute(
        "SELECT ts, actor, ip, action, detail FROM auth_audit ORDER BY id DESC LIMIT ?",
        (limit,)).fetchall()


# --- Zeit-Helfer (ISO <-> epoch) ---
def _iso(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _ts(iso):
    try:
        return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0
