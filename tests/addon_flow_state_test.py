"""Saved flow observations, exercised unchanged against the reference API."""

from pathlib import Path
from copy import deepcopy
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import addon_connection as connection
import addon_flow as flow
from addon_http_message import Request, Response


def peers():
    return (
        connection.Client(peername=("client", 123), sockname=("proxy", 443)),
        connection.Server(address=("example.test", 443)),
    )


class FlowStateTests(unittest.TestCase):
    def test_backup_retains_first_snapshot_even_with_force(self):
        exchange = flow.HTTPFlow(*peers(), live=True)
        exchange.request = Request.make("POST", "https://example.test/", b"original")
        exchange.metadata = {"nested": ["original"]}
        self.assertFalse(exchange.modified())
        exchange.revert()
        exchange.backup()
        # This surprising result is observable in the v12 reference: the
        # comparison includes the newly populated backup field itself.
        self.assertTrue(exchange.modified())
        exchange.request.content = b"changed"
        exchange.metadata["nested"].append("changed")
        exchange.comment = "changed"
        exchange.backup(force=True)
        exported = exchange.get_state()
        self.assertEqual(exported["backup"]["comment"], "")
        exported["backup"]["comment"] = "external mutation"
        self.assertEqual(exchange.get_state()["backup"]["comment"], "")
        exchange.revert()
        self.assertEqual(exchange.request.content, b"original")
        self.assertEqual(exchange.metadata, {"nested": ["original"]})
        self.assertEqual(exchange.comment, "")
        self.assertTrue(exchange.live)
        self.assertFalse(exchange.modified())
        self.assertIsNone(exchange.get_state()["backup"])
        exchange.comment = "next snapshot"
        exchange.backup(force=True)
        exchange.comment = "next change"
        exchange.revert()
        self.assertEqual(exchange.comment, "next snapshot")

    def test_restored_backup_reverts_messages_without_resurrecting_transport(self):
        exchange = flow.TCPFlow(*peers(), live=True)
        exchange.messages.append(flow.TCPMessage(True, b"original", 1))
        exchange.backup()
        exchange.messages.append(flow.TCPMessage(False, b"later", 2))
        restored = flow.Flow.from_state(exchange.get_state())
        self.assertTrue(restored.modified())
        restored.revert()
        self.assertEqual([item.content for item in restored.messages], [b"original"])
        self.assertFalse(restored.live)
        self.assertFalse(restored.modified())

    def test_restore_dispatches_by_saved_type_and_consumes_state(self):
        exchanges = [flow.HTTPFlow(*peers()), flow.TCPFlow(*peers()), flow.UDPFlow(*peers())]
        exchanges[0].request = Request.make("GET", "https://example.test/")
        exchanges[1].messages.append(flow.TCPMessage(True, b"stream", 1))
        exchanges[2].messages.append(flow.UDPMessage(False, b"datagram", 2))
        for original in exchanges:
            with self.subTest(kind=original.type):
                original.live = True
                original.client_conn.state = connection.ConnectionState.OPEN
                expected = original.get_state()
                consumed = deepcopy(expected)
                restored = flow.Flow.from_state(consumed)
                self.assertEqual(consumed, {})
                self.assertIs(type(restored), type(original))
                self.assertEqual(restored.get_state(), expected)
                self.assertFalse(restored.live)
                self.assertFalse(restored.client_conn.connected)

    def test_update_keeps_connections_and_live_flag_but_replaces_message(self):
        exchange = flow.HTTPFlow(*peers(), live=True)
        exchange.request = Request.make("GET", "https://example.test/")
        client, server, request = exchange.client_conn, exchange.server_conn, exchange.request
        state = exchange.get_state()
        metadata = state["metadata"]
        client_state = state["client_conn"]
        exchange.set_state(state)
        self.assertEqual(state, {})
        self.assertEqual(client_state, {})
        self.assertIs(exchange.client_conn, client)
        self.assertIs(exchange.server_conn, server)
        self.assertIsNot(exchange.request, request)
        self.assertIs(exchange.metadata, metadata)
        self.assertTrue(exchange.live)

    def test_restore_rejects_wrong_version_and_unknown_type(self):
        exchange = flow.HTTPFlow(*peers())
        exchange.request = Request.make("GET", "https://example.test/")
        with self.assertRaises(AssertionError):
            flow.Flow.from_state(dict(exchange.get_state(), version=999))
        with self.assertRaises(ValueError):
            flow.Flow.from_state(dict(exchange.get_state(), type="unknown"))

    def test_http_state_contains_messages_but_no_live_transport(self):
        client, server = peers()
        client.state = connection.ConnectionState.OPEN
        exchange = flow.HTTPFlow(client, server, live=True)
        exchange.request = Request.make("GET", "https://example.test/")
        exchange.response = Response.make(200, b"response")
        exchange.error = flow.Error("test error", 12)
        exchange.metadata = {"nested": ["original"]}
        exchange.intercept()
        state = exchange.get_state()
        self.assertEqual(set(state), {
            "version", "type", "id", "error", "client_conn", "server_conn",
            "intercepted", "is_replay", "marked", "metadata", "comment",
            "timestamp_created", "backup", "request", "response", "websocket",
        })
        self.assertEqual(state["version"], 21)
        self.assertEqual(state["type"], "http")
        self.assertEqual(state["id"], exchange.id)
        self.assertEqual(state["error"], {"msg": "test error", "timestamp": 12.0})
        self.assertEqual(state["client_conn"], client.get_state())
        self.assertNotIn("state", state["client_conn"])
        self.assertEqual(state["request"], exchange.request.get_state())
        self.assertEqual(state["response"], exchange.response.get_state())
        self.assertTrue(state["intercepted"])
        self.assertIsNone(state["backup"])
        self.assertIsNone(state["websocket"])
        state["metadata"]["nested"].append("edited")
        self.assertEqual(exchange.metadata, {"nested": ["original"]})

    def test_request_without_response_or_error(self):
        exchange = flow.HTTPFlow(*peers())
        exchange.request = Request.make("GET", "http://example.test/")
        state = exchange.get_state()
        self.assertIsNone(state["response"])
        self.assertIsNone(state["error"])

    def test_transport_state_preserves_order_and_datagram_boundaries(self):
        for kind in ("TCP", "UDP"):
            with self.subTest(kind=kind):
                exchange = getattr(flow, kind + "Flow")(*peers(), live=True)
                message = getattr(flow, kind + "Message")
                exchange.messages = [message(True, b"", 1), message(False, b"reply", 2)]
                state = exchange.get_state()
                self.assertEqual(state["type"], kind.lower())
                self.assertEqual(state["messages"], [(True, b"", 1), (False, b"reply", 2)])
                self.assertNotIn("request", state)
                self.assertNotIn("live", state)
                state["messages"].clear()
                self.assertEqual(len(exchange.messages), 2)


if __name__ == "__main__":
    unittest.main()
