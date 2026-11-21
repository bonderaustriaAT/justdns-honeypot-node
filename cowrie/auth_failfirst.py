# JustDNS honeypot auth class. Wird von scripts/install-auth-failfirst.sh an
# cowrie/src/cowrie/core/auth.py angehaengt. cowrie laedt die auth_class per
# getattr() aus genau dem Modul cowrie.core.auth, darum MUSS die Klasse dort
# leben (ein dotted path geht nicht). Die Imports sind aliasiert, damit das
# Anhaengen keine vorhandenen Namen in auth.py ueberschreibt.
from twisted.logger import Logger as _FFLogger
from cowrie.core.config import CowrieConfig as _FFConfig
import json as _ffjson
import os as _ffos
import threading as _ffthreading


class AuthFailFirst:
    """
    Die ersten N Login-Versuche je Quell-IP werden abgelehnt (cowrie.login.failed,
    Quell-IP wird erfasst = Brute-Force/Threat-Signal), danach wird JEDER weitere
    Login dieser IP angenommen -> Angreifer landet im Fake-Shell und seine
    Nachlade-Kommandos werden mitgeschnitten.

    Unterschied zu AuthRandom: es zaehlt ALLE Versuche (auch identische
    Credentials, also auch Einzelpasswort-Bots) und es gibt KEINEN Rueckkehrer-
    Lockout (kein Zwang zur exakten Gewinner-Kombi).

    Proven-cred Fast-Path (gegen den Scout/Loader-Split): Sobald eine Credential-
    Kombi (User/Passwort) einmal durch die Fail-Schwelle gekommen ist, wird GENAU
    diese Kombi danach bei JEDEM weiteren Login SOFORT angenommen - egal von welcher
    IP, ohne die N Fehlversuche. Zweck: der Mirai-Loader kommt mit einer frischen IP
    und macht nur EINEN Login mit dem vom Scout gemeldeten Passwort; so landet er
    sofort im Shell und sein Nachlade-Payload wird mitgeschnitten. UNBEKANNTE
    Credentials laufen weiter ueber die Fail-Schwelle -> Brute-/Credential-Signal
    bleibt voll erhalten.

    Bewiesene Credentials werden nach var/lib/cowrie/proven_creds.json persistiert
    (ueberlebt Neustart). IP-Zaehler bleiben im Speicher (kein Rueckkehrer-Lockout).
    N kommt aus auth_class_parameters (erster Wert), Default 2.
    """

    _log = _FFLogger()
    _tries: dict = {}
    _proven: set = set()
    _lock = _ffthreading.Lock()
    _loaded = False
    _store = None

    def __init__(self) -> None:
        self.need_fail = 2
        try:
            params = _FFConfig.get("honeypot", "auth_class_parameters")
            self.need_fail = int(params.split(",")[0].strip())
        except Exception:
            self.need_fail = 2
        if not AuthFailFirst._loaded:
            self._load_proven()

    def _store_path(self) -> str:
        if AuthFailFirst._store:
            return AuthFailFirst._store
        base = "/home/cowrie/cowrie/var/lib/cowrie"
        for section, key in (("honeypot", "state_path"), ("honeypot", "data_path")):
            try:
                val = _FFConfig.get(section, key)
                if val:
                    base = val
                    break
            except Exception:
                pass
        AuthFailFirst._store = _ffos.path.join(base, "proven_creds.json")
        return AuthFailFirst._store

    def _load_proven(self) -> None:
        with AuthFailFirst._lock:
            if AuthFailFirst._loaded:
                return
            try:
                with open(self._store_path(), encoding="utf-8") as fh:
                    for item in _ffjson.load(fh):
                        AuthFailFirst._proven.add((item[0], item[1]))
            except Exception:
                pass
            AuthFailFirst._loaded = True

    def _mark_proven(self, u: str, p: str) -> None:
        key = (u, p)
        with AuthFailFirst._lock:
            if key in AuthFailFirst._proven:
                return
            AuthFailFirst._proven.add(key)
            try:
                path = self._store_path()
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    _ffjson.dump([list(k) for k in AuthFailFirst._proven], fh)
                _ffos.replace(tmp, path)
            except Exception:
                pass

    @staticmethod
    def _decode(v) -> str:
        if isinstance(v, bytes):
            try:
                return v.decode("utf-8", "replace")
            except Exception:
                return repr(v)
        return str(v)

    def checklogin(self, thelogin, thepasswd, src_ip: str) -> bool:
        u = self._decode(thelogin)
        p = self._decode(thepasswd)
        # Fast-Path: schon bewiesene Credentials sofort annehmen (Loader-Tuer).
        if (u, p) in AuthFailFirst._proven:
            return True
        n = AuthFailFirst._tries.get(src_ip, 0) + 1
        AuthFailFirst._tries[src_ip] = n
        if n <= self.need_fail:
            return False
        # Durchbruch nach N Fails: Credential als bewiesen merken -> ab jetzt Fast-Path.
        self._mark_proven(u, p)
        return True
