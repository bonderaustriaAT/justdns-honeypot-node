#!/usr/bin/env python3
"""Tests der Agent-Logparser je App-Profil: Ablehnungen werden erkannt, erlaubte
Zugriffe (2xx/3xx) nicht, Quell-IP + Pfad korrekt extrahiert.

Lauf: python -m unittest discover -s tools/tests   (aus dem Repo-Root)
"""

import importlib.util
import os
import unittest

_HERE = os.path.dirname(__file__)
_AGENT = os.path.join(_HERE, "..", "agent", "justdns-agent.py")
_spec = importlib.util.spec_from_file_location("justdns_agent", _AGENT)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)

CTX = {"reject_status": {401, 403, 404, 405, 429, 444}}


class Parsers(unittest.TestCase):
    def p(self, app, line):
        return agent.PROFILES[app](line, CTX, app)

    def test_nginx_reject_and_allow(self):
        rej = self.p("nginx",
            '45.141.84.9 - - [21/Nov/2026:21:04:12 +0100] "GET /.env HTTP/1.1" 403 153 "-" "curl/8"')
        self.assertEqual(rej["src_ip"], "45.141.84.9")
        self.assertEqual(rej["status_code"], 403)
        self.assertEqual(rej["path"], "/.env")
        self.assertEqual(rej["reason"], "http_403")
        ok = self.p("nginx",
            '1.2.3.4 - - [21/Nov/2026:21:04:12 +0100] "GET / HTTP/1.1" 200 512 "-" "-"')
        self.assertIsNone(ok)

    def test_apache_same_format(self):
        rej = self.p("apache",
            '193.32.162.45 - - [21/Nov/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 429 0 "-" "-"')
        self.assertEqual(rej["src_ip"], "193.32.162.45")
        self.assertEqual(rej["status_code"], 429)

    def test_caddy_json(self):
        rej = self.p("caddy",
            '{"logger":"http.log.access","request":{"remote_ip":"103.14.2.77","method":"POST","uri":"/xmlrpc.php"},"status":403}')
        self.assertEqual(rej["src_ip"], "103.14.2.77")
        self.assertEqual(rej["path"], "/xmlrpc.php")
        self.assertEqual(rej["status_code"], 403)
        ok = self.p("caddy",
            '{"request":{"remote_ip":"8.8.8.8","uri":"/"},"status":200}')
        self.assertIsNone(ok)

    def test_node64_json_remote_addr_with_port(self):
        rej = self.p("node64",
            '{"request":{"remote_addr":"91.196.70.222:51234","uri":"/admin"},"status":401}')
        self.assertEqual(rej["src_ip"], "91.196.70.222")
        self.assertEqual(rej["status_code"], 401)

    def test_npm_client_bracket(self):
        rej = self.p("npm",
            '[21/Nov/2026:21:03:40 +0100] 403 - GET https example.com "/admin" [Client 10.10.5.2] [Length 0]')
        self.assertEqual(rej["src_ip"], "10.10.5.2")
        self.assertEqual(rej["status_code"], 403)
        self.assertEqual(rej["path"], "/admin")
        ok = self.p("npm",
            '[21/Nov/2026:21:03:40 +0100] 200 - GET https example.com "/" [Client 1.2.3.4] [Length 10]')
        self.assertIsNone(ok)

    def test_haproxy_httplog(self):
        rej = self.p("haproxy",
            'Nov 21 21:00:00 lb haproxy[12]: 45.141.84.9:51000 [21/Nov/2026:21:00:00.123] fe be/srv1 0/0/0/0/5 403 220 - - ---- 1/1/0/0/0 0/0 "GET /.git/config HTTP/1.1"')
        self.assertEqual(rej["src_ip"], "45.141.84.9")
        self.assertEqual(rej["status_code"], 403)
        self.assertEqual(rej["path"], "/.git/config")

    def test_sshd_failed_password(self):
        rej = self.p("sshd",
            'Nov 21 21:00:00 host sshd[99]: Failed password for root from 193.32.162.45 port 51000 ssh2')
        self.assertEqual(rej["src_ip"], "193.32.162.45")
        self.assertEqual(rej["reason"], "auth_fail")
        self.assertEqual(rej["path"], "user=root")
        rej2 = self.p("sshd",
            'Nov 21 21:00:01 host sshd[99]: Invalid user admin from 185.220.101.4 port 2000')
        self.assertEqual(rej2["src_ip"], "185.220.101.4")
        ok = self.p("sshd",
            'Nov 21 21:00:02 host sshd[99]: Accepted publickey for ops from 10.0.0.5 port 2000 ssh2')
        self.assertIsNone(ok)

    def test_fail2ban_ban(self):
        rej = self.p("fail2ban",
            '2026-11-21 21:00:00,123 fail2ban.actions [1]: NOTICE [sshd] Ban 45.141.84.9')
        self.assertEqual(rej["src_ip"], "45.141.84.9")
        self.assertEqual(rej["reason"], "fw_ban")

    def test_reject_status_parsing(self):
        self.assertEqual(agent.parse_reject_status("403, 404 ,429"), {403, 404, 429})
        self.assertEqual(agent.parse_reject_status("junk"), {401, 403, 404, 405, 429, 444})


if __name__ == "__main__":
    unittest.main()
