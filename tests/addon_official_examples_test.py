"""Integrity checks for the reviewed mitmproxy 12 example inventory."""

import json
from collections import Counter
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/corpus/addon_official_examples_v12.json"


class OfficialExampleAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads(MANIFEST.read_text())

    def test_inventory_is_complete_and_partitioned(self):
        examples = self.audit["examples"]
        names = [entry["name"] for entry in examples]

        self.assertEqual(self.audit["reference"], "mitmproxy 12.3.1")
        self.assertEqual(self.audit["reviewed"], "2026-10-31")
        self.assertEqual(len(names), 30)
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(
            set(names),
            {
                "anatomy.py",
                "anatomy2.py",
                "commands-flows.py",
                "commands-paths.py",
                "commands-simple.py",
                "contentview-interactive.py",
                "contentview.py",
                "dns-simple.py",
                "duplicate-modify-replay.py",
                "filter-flows.py",
                "http-add-header.py",
                "http-modify-form.py",
                "http-modify-query-string.py",
                "http-redirect-requests.py",
                "http-reply-from-proxy.py",
                "http-stream-modify.py",
                "http-stream-simple.py",
                "http-trailers.py",
                "internet-in-mirror.py",
                "io-read-saved-flows.py",
                "io-write-flow-file.py",
                "log-events.py",
                "nonblocking.py",
                "options-configure.py",
                "options-simple.py",
                "shutdown.py",
                "tcp-simple.py",
                "websocket-inject-message.py",
                "websocket-simple.py",
                "wsgi-flask-app.py",
            },
        )

        allowed = {
            "supported",
            "producer-gated",
            "host-gated",
            "native-gated",
        }
        self.assertTrue(all(entry["status"] in allowed for entry in examples))
        self.assertEqual(
            Counter(entry["status"] for entry in examples),
            {
                "supported": 20,
                "producer-gated": 4,
                "host-gated": 3,
                "native-gated": 3,
            },
        )
        self.assertTrue(all(entry["reason"] for entry in examples))
        self.assertTrue(all(entry["evidence"] for entry in examples))

    def test_every_evidence_path_exists(self):
        for entry in self.audit["examples"]:
            with self.subTest(example=entry["name"]):
                for relative_path in entry["evidence"]:
                    path = ROOT / relative_path
                    self.assertTrue(path.is_file(), relative_path)


if __name__ == "__main__":
    unittest.main()
