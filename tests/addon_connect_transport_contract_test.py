#!/usr/bin/env python3
"""Keep the verified HTTP CONNECT transport corpora internally consistent."""

import json
from pathlib import Path
import unittest


CORPUS_DIR = Path(__file__).with_name("corpus")


def load_corpus(name):
    with (CORPUS_DIR / name).open(encoding="utf-8") as handle:
        return json.load(handle)


class ConnectTransportContractTests(unittest.TestCase):
    def test_regular_connect_lifecycle(self):
        corpus = load_corpus("addon_connect_transport_v12.json")
        hooks = corpus["hooks"]

        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(
            [item["hook"] for item in hooks],
            [
                "http_connect",
                "http_connected",
                "http_connect",
                "http_connect_error",
            ],
        )
        self.assertEqual(hooks[0]["flow"], hooks[1]["flow"])
        self.assertEqual(hooks[2]["flow"], hooks[3]["flow"])
        self.assertFalse(hooks[0]["response_present"])
        self.assertEqual(hooks[1]["response_status"], 200)
        self.assertFalse(hooks[2]["response_present"])
        self.assertEqual(hooks[3]["response_status"], 502)
        self.assertIsNone(hooks[3]["error"])
        self.assertTrue(hooks[1]["server_peername_present"])
        self.assertFalse(hooks[3]["server_peername_present"])
        self.assertTrue(all(
            item["server_object_preserved"]
            and item["server_id_preserved"]
            for item in hooks
        ))

    def test_upstream_connect_is_lazy_and_distinct(self):
        corpus = load_corpus("addon_connect_upstream_v12.json")
        hooks = corpus["hooks"]

        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(
            [item["hook"] for item in hooks],
            ["http_connect", "http_connected", "http_connect_upstream"],
        )
        self.assertEqual({item["flow"] for item in hooks}, {"upstream"})
        self.assertFalse(hooks[0]["response_present"])
        self.assertEqual(hooks[1]["response_status"], 200)
        self.assertFalse(hooks[1]["server_peername_present"])
        self.assertFalse(hooks[2]["response_present"])
        self.assertTrue(hooks[2]["server_peername_present"])
        self.assertEqual(hooks[1]["server_address"][1], "destination")
        self.assertEqual(hooks[2]["server_address"][1], "upstream")
        self.assertTrue(all(
            item["server_object_preserved"]
            and item["server_id_preserved"]
            for item in hooks
        ))

    def test_connect_control_decisions_reach_the_wire(self):
        corpus = load_corpus("addon_connect_control_v12.json")
        scenarios = {
            item["action"]: item
            for item in corpus["scenarios"]
        }

        local = scenarios["local-response"]
        self.assertEqual(
            [item["hook"] for item in local["hooks"]],
            ["http_connect", "http_connect_error"],
        )
        self.assertFalse(local["origin_contacted"])
        self.assertEqual(local["hooks"][1]["response_status"], 418)

        killed = scenarios["kill"]
        self.assertEqual(
            [item["hook"] for item in killed["hooks"]],
            ["http_connect"],
        )
        self.assertFalse(killed["hooks"][0]["live"])
        self.assertEqual(killed["status"], "connection-closed")

        rerouted = scenarios["reroute"]
        self.assertTrue(rerouted["origin_contacted"])
        self.assertEqual(rerouted["hooks"][0]["port"], "origin")
        self.assertEqual(rerouted["status"], "HTTP/1.1 200 Connection established")

        connected = scenarios["mutate-connected"]
        self.assertEqual(connected["hooks"][1]["response_status"], 299)
        self.assertTrue(connected["status"].startswith("HTTP/1.1 299 "))

        failed = scenarios["mutate-error"]
        self.assertEqual(failed["hooks"][1]["response_status"], 599)
        self.assertTrue(failed["status"].startswith("HTTP/1.1 599 "))

        killed_connected = scenarios["kill-connected"]
        self.assertFalse(killed_connected["hooks"][1]["live"])
        self.assertEqual(
            killed_connected["hooks"][1]["error"],
            "Connection killed.",
        )
        self.assertEqual(
            killed_connected["status"],
            "HTTP/1.1 200 Connection established",
        )

        killed_error = scenarios["kill-error"]
        self.assertFalse(killed_error["hooks"][1]["live"])
        self.assertEqual(killed_error["status"], "HTTP/1.1 502 Bad Gateway")

    def test_proxy_authentication_precedes_connect_outcome(self):
        corpus = load_corpus("addon_connect_auth_v12.json")
        hooks = corpus["hooks"]

        self.assertEqual(corpus["origin_connections"], 1)
        self.assertEqual(
            corpus["statuses"],
            {
                "correct": "HTTP/1.1 200 Connection established",
                "incorrect": "HTTP/1.1 407 Proxy Authentication Required",
                "missing": "HTTP/1.1 407 Proxy Authentication Required",
            },
        )
        self.assertEqual(
            [item["hook"] for item in hooks],
            [
                "http_connect",
                "http_connect_error",
                "http_connect",
                "http_connect_error",
                "http_connect",
                "http_connected",
            ],
        )
        self.assertEqual(hooks[0]["response_status"], 407)
        self.assertFalse(hooks[0]["proxy_authorization_present"])
        self.assertEqual(hooks[2]["response_status"], 407)
        self.assertTrue(hooks[2]["proxy_authorization_present"])
        self.assertIsNone(hooks[4]["response_status"])
        self.assertFalse(hooks[4]["proxy_authorization_present"])

    def test_upstream_control_is_late_but_can_change_authority(self):
        corpus = load_corpus("addon_connect_upstream_control_v12.json")
        scenarios = {
            item["action"]: item
            for item in corpus["scenarios"]
        }

        rejected = scenarios["pass"]
        self.assertEqual(rejected["upstream_status"], 502)
        self.assertEqual(
            rejected["client_status"],
            "HTTP/1.1 200 Connection established",
        )
        self.assertNotIn(
            "http_connect_error",
            [item["hook"] for item in rejected["hooks"]],
        )

        rerouted = scenarios["reroute"]
        self.assertEqual(
            rerouted["upstream_request"],
            "CONNECT rewritten.invalid:9443 HTTP/1.1",
        )
        upstream_hooks = [
            item for item in rerouted["hooks"]
            if item["hook"] == "http_connect_upstream"
        ]
        self.assertFalse(upstream_hooks[0]["live"])
        self.assertEqual(upstream_hooks[1]["host"], "rewritten.invalid")

        killed = scenarios["kill"]
        self.assertEqual(killed["exceptions"], [{
            "message": "Flow is not killable.",
            "module": "mitmproxy.exceptions",
            "type": "ControlException",
        }])
        self.assertIsNotNone(killed["upstream_request"])

        local = scenarios["local-response"]
        self.assertEqual(local["hooks"][-1]["response_status"], 418)
        self.assertIsNotNone(local["upstream_request"])


if __name__ == "__main__":
    unittest.main()
