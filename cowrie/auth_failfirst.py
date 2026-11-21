# JustDNS honeypot auth class. Wird von scripts/install-auth-failfirst.sh an
# cowrie/src/cowrie/core/auth.py angehaengt. cowrie laedt die auth_class per
# getattr() aus genau dem Modul cowrie.core.auth, darum MUSS die Klasse dort
# leben (ein dotted path geht nicht). Die Imports sind aliasiert, damit das
# Anhaengen keine vorhandenen Namen in auth.py ueberschreibt.
from twisted.logger import Logger as _FFLogger
from cowrie.core.config import CowrieConfig as _FFConfig


class AuthFailFirst:
    """
    Die ersten N Login-Versuche je Quell-IP werden abgelehnt (cowrie.login.failed,
    Quell-IP wird erfasst = Brute-Force/Threat-Signal), danach wird JEDER weitere
    Login dieser IP angenommen -> Angreifer landet im Fake-Shell und seine
    Nachlade-Kommandos werden mitgeschnitten.

    Unterschied zu AuthRandom: es zaehlt ALLE Versuche (auch identische
    Credentials, also auch Einzelpasswort-Bots) und es gibt KEINEN Rueckkehrer-
    Lockout (kein Zwang zur exakten Gewinner-Kombi). Zustand ist rein im Speicher
    (dict pro IP), wird beim Neustart geleert - kein persistenter State-Bug.

    N kommt aus auth_class_parameters (erster Wert), Default 2.
    """

    _log = _FFLogger()
    _tries: dict = {}

    def __init__(self) -> None:
        self.need_fail = 2
        try:
            params = _FFConfig.get("honeypot", "auth_class_parameters")
            self.need_fail = int(params.split(",")[0].strip())
        except Exception:
            self.need_fail = 2

    def checklogin(self, thelogin: bytes, thepasswd: bytes, src_ip: str) -> bool:
        n = AuthFailFirst._tries.get(src_ip, 0) + 1
        AuthFailFirst._tries[src_ip] = n
        if n <= self.need_fail:
            return False
        return True
