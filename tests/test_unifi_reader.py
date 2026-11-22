#!/usr/bin/env python3
"""Tests fuer den Unifi-Alarm-Parser (alarm_to_event).

Lauf: python -m unittest discover -s tests   (aus dem Repo-Root)
"""

import importlib.util
import os
import unittest

_HERE = os.path.dirname(__file__)
_UR = os.path.join(_HERE, "..", "firewall", "unifi_reader.py")
_spec = importlib.util.spec_from_file_location("unifi_reader", _UR)
unifi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(unifi)


class AlarmParser(unittest.TestCase):
    def test_ips_alert(self):
        uid, ev = unifi.alarm_to_event({
            "_id": "abc123", "src_ip": "185.220.101.4",
            "inner_alert_signature": "ET SCAN Nmap", "datetime": "2026-11-21T21:00:00Z"})
        self.assertEqual(uid, "abc123")
        self.assertEqual(ev["src_ip"], "185.220.101.4")
        self.assertEqual(ev["reason"], "ips_alert")
        self.assertEqual(ev["app"], "unifi")
        self.assertEqual(ev["uid"], "unifi:abc123")
        self.assertIn("Nmap", ev["path"])

    def test_fw_drop_without_signature(self):
        uid, ev = unifi.alarm_to_event({"_id": "d1", "src_ip": "45.141.84.9"})
        self.assertEqual(ev["reason"], "fw_drop")

    def test_missing_ip_or_id(self):
        self.assertIsNone(unifi.alarm_to_event({"_id": "x"}))
        self.assertIsNone(unifi.alarm_to_event({"src_ip": "8.8.8.8"}))


if __name__ == "__main__":
    unittest.main()
