#!/usr/bin/env python3
"""Tests des node64-Readers: Mapping der Policy-Gruende, Blocklist-Ausschluss
(keine Zirkularitaet), Paging/Dedupe gegen die zuletzt gesehene id.

Lauf: python -m unittest discover -s tests   (aus dem Repo-Root)
"""

import importlib.util
import os
import unittest

_HERE = os.path.dirname(__file__)
_MOD = os.path.join(_HERE, "..", "node64", "node64_reader.py")
_spec = importlib.util.spec_from_file_location("node64_reader", _MOD)
nr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nr)


# Echte Zeilen-Form aus der node64-API (gekuerzt).
def row(rid, client, reason, status=403, path="/"):
    return {"id": rid, "client": client, "rejected_reason": reason,
            "status": status, "time": "2026-11-22T05:25:49Z",
            "untrusted": {"path": path, "method": "GET"}}


class RawRestShape(unittest.TestCase):
    """Rohe /api/cdn64/log-Zeile: reason + path liegen oben (nicht rejected_reason/untrusted)."""
    def test_raw_exploit_top_level_fields(self):
        raw = {"id": 2904, "client": "15.207.88.3", "reason": "exploit", "status": 403,
               "time": "2026-11-22T05:25:49Z", "host": "pw.justfuture.at",
               "method": "GET", "path": "/.git/config", "user_agent": "x"}
        rid, ev = nr.row_to_event(raw)
        self.assertEqual(rid, 2904)
        self.assertEqual(ev["src_ip"], "15.207.88.3")
        self.assertEqual(ev["reason"], "waf_block")
        self.assertEqual(ev["path"], "/.git/config")

    def test_raw_blocklist_reported(self):
        rid, ev = nr.row_to_event(
            {"id": 1, "client": "1.2.3.4", "reason": "blocklist", "status": 0})
        self.assertEqual(rid, 1)
        self.assertEqual(ev["reason"], "blocklist_hit")
        self.assertEqual(ev["src_ip"], "1.2.3.4")


class Mapping(unittest.TestCase):
    def test_exploit_is_waf_block(self):
        rid, ev = nr.row_to_event(row(2904, "15.207.88.3", "exploit", 403, "/.git/config"))
        self.assertEqual(rid, 2904)
        self.assertEqual(ev["src_ip"], "15.207.88.3")
        self.assertEqual(ev["reason"], "waf_block")
        self.assertEqual(ev["app"], "node64")
        self.assertEqual(ev["path"], "/.git/config")
        self.assertEqual(ev["status_code"], 403)
        self.assertEqual(ev["uid"], "node64:2904")

    def test_acl_is_http_403(self):
        _, ev = nr.row_to_event(row(2888, "159.89.8.251", "acl", 403, "/wp-login.php"))
        self.assertEqual(ev["reason"], "http_403")

    def test_rate_limit_is_http_429(self):
        _, ev = nr.row_to_event(row(10, "1.2.3.4", "rate_limit", 429, "/"))
        self.assertEqual(ev["reason"], "http_429")

    def test_honeypot_is_waf_block(self):
        _, ev = nr.row_to_event(row(11, "1.2.3.4", "honeypot", 403, "/trap"))
        self.assertEqual(ev["reason"], "waf_block")

    def test_blocklist_is_reported(self):
        _, ev = nr.row_to_event(row(2970, "45.198.224.32", "blocklist", 0))
        self.assertEqual(ev["reason"], "blocklist_hit")
        self.assertEqual(ev["src_ip"], "45.198.224.32")

    def test_unknown_reason_dropped(self):
        self.assertIsNone(nr.row_to_event(row(1, "1.2.3.4", "geo", 403)))

    def test_missing_client_dropped(self):
        r = row(5, "", "exploit"); r["client"] = None
        self.assertIsNone(nr.row_to_event(r))


class Paging(unittest.TestCase):
    class FakeClient(nr.Node64):
        def __init__(self, pages):
            self._pages = pages

        def _get(self, path, params=None):
            import json as _j
            before = params.get("before") if params else None
            idx = 0 if before is None else self._lookup(before)
            return 200, _j.dumps(self._pages[idx])

        def _lookup(self, before):
            for i, pg in enumerate(self._pages):
                if pg.get("_marker") == before:
                    return i
            return len(self._pages) - 1

    def test_stops_at_last_seen(self):
        pages = [{
            "_marker": None,
            "rows": [row(30, "a", "exploit"), row(29, "b", "acl"), row(28, "c", "blocklist")],
            "next_before": "m1",
        }, {
            "_marker": "m1",
            "rows": [row(27, "d", "exploit"), row(26, "e", "exploit")],
            "next_before": "m2",
        }]
        c = self.FakeClient(pages)
        rows, max_id = c.fetch_rejected("/x", pages=20, page_size=3, stop_after_id=27)
        ids = sorted(r["id"] for r in rows)
        self.assertEqual(ids, [28, 29, 30])   # 27 und aelter gestoppt
        self.assertEqual(max_id, 30)


if __name__ == "__main__":
    unittest.main()
