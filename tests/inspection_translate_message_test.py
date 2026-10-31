"""Complete-message helpers keep input accounting separate from generated output."""

import base64
import gzip
import json
from pathlib import Path
import sys
import unittest

import h2.events

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from inspection_api import CommitException, Connection, Http2
from inspection_h2_test import frame, unpack
from inspection_translate_windows_test import Peers


H2 = Http2(False, (), ())
HEADERS = [(b":method", b"POST"), (b":scheme", b"https"),
           (b":authority", b"example.org"), (b":path", b"/")]


def head(message):
    return next(part for part in message.parts if part.frame_type == 1)


class MessageReplacementTests(unittest.TestCase):
    def request(self, peers, body=None, trailers=None):
        client = peers.peers["L"]
        client.send_headers(1, HEADERS, end_stream=body is None and trailers is None)
        if body is not None:
            client.send_data(1, body, end_stream=trailers is None)
        if trailers is not None:
            client.send_headers(1, trailers, end_stream=True)
        return client.data_to_send()

    def test_added_body_and_trailers_have_one_end_and_no_fabricated_input_credit(self):
        peers = Peers()
        wire = self.request(peers)

        def replace(message):
            before = message.commit()
            policy = Connection(message).http2
            policy.replace_body(head(message), b"synthetic body")
            policy.replace_trailers(head(message), [H2.Header(b"x-end", b"yes")])
            # The operation is a plan, not a list mutation or early output.
            self.assertEqual(len(message.parts), 1)
            self.assertEqual(message.parts[0].commit(), before)

        forward, reverse = peers.bridge.feed("L", wire, replace)
        events = peers.peers["R"].receive_data(forward)
        self.assertEqual(reverse, b"")
        self.assertEqual([event.data for event in events if isinstance(event, h2.events.DataReceived)], [b"synthetic body"])
        self.assertEqual([event.headers for event in events if isinstance(event, h2.events.TrailersReceived)], [[(b"x-end", b"yes")]])
        self.assertEqual(sum(isinstance(event, h2.events.StreamEnded) for event in events), 1)
        self.assertEqual(peers.peers["L"].outbound_flow_control_window, 65535)
        direction = peers.bridge.control["flow"]["L"]
        self.assertEqual(direction["input"]["owned"], 0)
        self.assertEqual(direction["credit"], 0)

    def test_generated_data_obeys_output_window_and_cancellation(self):
        for cancel in ("reset", "goaway"):
            with self.subTest(cancel=cancel):
                peers = Peers()
                wire = self.request(peers)

                def replace(message):
                    Connection(message).http2.replace_body(head(message), b"x" * 100000)

                forward, reverse = peers.bridge.feed("L", wire, replace)
                events = peers.peers["R"].receive_data(forward)
                received = sum(len(event.data) for event in events if isinstance(event, h2.events.DataReceived))
                self.assertEqual(received, 65535)
                self.assertEqual(reverse, b"")
                self.assertTrue(peers.bridge.control["flow"]["L"]["queue"])
                server = peers.peers["R"]
                if cancel == "reset":
                    server.reset_stream(1)
                else:
                    server.close_connection(last_stream_id=0)
                forward, reverse = peers.bridge.feed("R", server.data_to_send())
                self.assertFalse(any(kind == 0 for kind, flags, stream, body in unpack(forward + reverse)))
                direction = peers.bridge.control["flow"]["L"]
                self.assertEqual(direction["queue"], [])
                self.assertEqual(direction["input"]["owned"], 0)
                self.assertEqual(direction["credit"], 0)
                self.assertEqual(direction["streams"], {})

    def test_generated_body_completes_after_multiple_window_updates(self):
        peers = Peers()
        wire = self.request(peers)
        replacement = b"x" * 160000

        def replace(message):
            Connection(message).http2.replace_body(head(message), replacement)

        peers.pump("L", wire, replace)
        self.assertEqual(b"".join(peers.received["R"]), replacement)
        self.assertEqual(peers.ended["R"], [1])
        self.assertEqual(peers.peers["L"].outbound_flow_control_window, 65535)
        self.assertEqual(peers.bridge.control["flow"]["L"]["queue"], [])

    def test_response_body_can_be_added_independently(self):
        peers = Peers()
        peers.pump("L", self.request(peers))
        server = peers.peers["R"]
        server.send_headers(1, [(b":status", b"200"), (b"content-length", b"0")], end_stream=True)

        def replace(message):
            Connection(message).http2.replace_body(head(message), b"reply")

        peers.pump("R", server.data_to_send(), replace)
        self.assertEqual(peers.received["L"], [b"reply"])
        self.assertEqual(peers.ended["L"], [1])
        self.assertEqual(server.outbound_flow_control_window, 65535)

    def test_removing_last_trailers_without_data_closes_at_initial_headers(self):
        peers = Peers()
        wire = self.request(peers, trailers=[(b"x-old", b"value")])

        def replace(message):
            Connection(message).http2.replace_trailers(head(message), None)

        forward, _ = peers.bridge.feed("L", wire, replace)
        events = peers.peers["R"].receive_data(forward)
        self.assertFalse(any(isinstance(event, h2.events.TrailersReceived) for event in events))
        self.assertEqual(sum(isinstance(event, h2.events.StreamEnded) for event in events), 1)
        self.assertEqual(len(unpack(forward)), 1)

    def test_removed_source_trailers_still_advance_input_hpack(self):
        peers = Peers()
        client = peers.peers["L"]
        repeated = (b"x-shared-table-entry", b"value reused later")
        wire = self.request(peers, body=b"body", trailers=[repeated])
        client.send_headers(3, HEADERS + [repeated], end_stream=True)
        wire += client.data_to_send()

        def replace(message):
            Connection(message).http2.replace_trailers(head(message), None)

        forward, _ = peers.bridge.feed("L", wire, replace)
        events = peers.peers["R"].receive_data(forward)
        requests = [event for event in events if isinstance(event, h2.events.RequestReceived)]
        self.assertEqual([event.stream_id for event in requests], [1, 3])
        self.assertIn(repeated, requests[-1].headers)

    def test_generated_trailer_and_next_source_header_keep_output_hpack_order(self):
        peers = Peers()
        client = peers.peers["L"]
        wire = self.request(peers)
        client.send_headers(3, HEADERS + [(b"x-same", b"second")], end_stream=True)
        wire += client.data_to_send()

        def replace(message):
            Connection(message).http2.replace_trailers(head(message), [H2.Header(b"x-same", b"first")])

        forward, _ = peers.bridge.feed("L", wire, replace)
        events = peers.peers["R"].receive_data(forward)
        self.assertEqual([event.headers for event in events if isinstance(event, h2.events.TrailersReceived)], [[(b"x-same", b"first")]])
        requests = [event for event in events if isinstance(event, h2.events.RequestReceived)]
        self.assertIn((b"x-same", b"second"), requests[-1].headers)

    def test_padding_bit_does_not_leak_after_payload_resize(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, HEADERS + [(b"content-length", b"3")])
        client.send_data(1, b"old", end_stream=True, pad_length=4)

        def replace(message):
            policy = Connection(message).http2
            # Eight bytes makes the new unpadded payload exactly as long as
            # the old padded payload. Length equality must not restore PADDED.
            policy.replace_body(head(message), b"12345678")
            policy.replace_trailers(head(message), [H2.Header(b"x-end", b"yes")])

        forward, _ = peers.bridge.feed("L", client.data_to_send(), replace)
        events = peers.peers["R"].receive_data(forward)
        self.assertEqual([event.data for event in events if isinstance(event, h2.events.DataReceived)], [b"12345678"])
        data = next(item for item in unpack(forward) if item[0] == 0)
        self.assertFalse(data[1] & 8)
        self.assertFalse(data[1] & 1)
        self.assertEqual(sum(isinstance(event, h2.events.StreamEnded) for event in events), 1)

    def test_decoded_replacement_uses_native_content_coding(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, HEADERS + [(b"content-encoding", b"gzip"), (b"content-length", b"0")], end_stream=True)

        def replace(message):
            Connection(message).http2.replace_body(head(message), b"decoded text")

        peers.pump("L", client.data_to_send(), replace)
        self.assertEqual(gzip.decompress(b"".join(peers.received["R"])), b"decoded text")

    def test_encoded_replacement_does_not_encode_twice(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, HEADERS + [(b"content-encoding", b"gzip")], end_stream=True)
        wire_body = gzip.compress(b"already encoded", mtime=123)

        def replace(message):
            Connection(message).http2.replace_body(head(message), wire_body, encoded=True)

        peers.pump("L", client.data_to_send(), replace)
        self.assertEqual(b"".join(peers.received["R"]), wire_body)

    def test_replacement_rejects_incomplete_message_and_held_publication(self):
        for complete in (False, True):
            with self.subTest(complete=complete):
                peers = Peers()
                client = peers.peers["L"]
                client.send_headers(1, HEADERS, end_stream=complete)
                message = peers.bridge.message("L", client.data_to_send())
                before = json.dumps(peers.bridge.control, sort_keys=True)
                header = head(message)
                Connection(message).http2.replace_body(header, b"new")
                if complete:
                    message.parts.hold_from(header)
                with self.assertRaises(CommitException):
                    peers.bridge.publish("L", message)
                self.assertEqual(json.dumps(peers.bridge.control, sort_keys=True), before)
                self.assertIsNone(message._translation.result)

    def test_original_parts_reordering_guard_still_applies(self):
        peers = Peers()
        message = peers.bridge.message("L", self.request(peers))
        Connection(message).http2.replace_body(head(message), b"new")
        message.parts.append(H2.Frame(0, 1, 1, b"unexpected"))
        with self.assertRaisesRegex(CommitException, 'insert, remove or reorder'):
            peers.bridge.publish("L", message)

    def test_reset_in_same_callback_cancels_planned_output_and_preserves_input_hpack(self):
        peers = Peers()
        client = peers.peers["L"]
        client.send_headers(1, HEADERS, end_stream=True)
        client.reset_stream(1)

        def replace(message):
            Connection(message).http2.replace_body(head(message), b"must not escape")

        forward, reverse = peers.bridge.feed("L", client.data_to_send(), replace)
        self.assertEqual(forward, b"")
        self.assertEqual(reverse, b"")
        client.send_headers(3, HEADERS, end_stream=True)
        forward, _ = peers.bridge.feed("L", client.data_to_send())
        events = peers.peers["R"].receive_data(forward)
        self.assertEqual([item.stream_id for item in events if isinstance(item, h2.events.RequestReceived)], [3])

    def test_direct_body_edits_cannot_be_mixed_with_planned_replacement(self):
        peers = Peers()
        message = peers.bridge.message("L", self.request(peers, body=b"old"))
        Connection(message).http2.replace_body(head(message), b"new")
        message.bodies()[0].set_bytes(b"different edit")
        with self.assertRaisesRegex(CommitException, 'combine'):
            peers.bridge.publish("L", message)

    def test_trailer_validation_is_atomic(self):
        peers = Peers()
        message = peers.bridge.message("L", self.request(peers))
        policy = Connection(message).http2
        for name in (b":status", b"content-length", b"Bad-Case", b"bad name", b"bad\nname"):
            with self.subTest(name=name):
                with self.assertRaises(CommitException):
                    policy.replace_trailers(head(message), [H2.Header(b"x-good", b"ok"), H2.Header(name, b"bad")])
                self.assertEqual(message._translation.message_edits, {})
        with self.assertRaises(CommitException):
            policy.replace_trailers(head(message), [H2.HeaderIndex(1)])
        self.assertEqual(message._translation.message_edits, {})

    def test_failed_quota_check_can_be_retried_without_early_publication(self):
        peers = Peers()
        message = peers.bridge.message("L", self.request(peers))
        original = message.parts[0].commit()
        before = json.dumps(peers.bridge.control, sort_keys=True)
        policy = Connection(message).http2
        policy.replace_body(head(message), b"large" * 100000)
        with self.assertRaisesRegex(CommitException, 'pending output'):
            peers.bridge.publish("L", message)
        self.assertIsNone(message._translation.result)
        self.assertEqual(message.parts[0].commit(), original)
        self.assertEqual(json.dumps(peers.bridge.control, sort_keys=True), before)
        policy.replace_body(head(message), b"small")
        forward = peers.bridge.publish("L", message)
        events = peers.peers["R"].receive_data(forward)
        self.assertEqual([event.data for event in events if isinstance(event, h2.events.DataReceived)], [b"small"])

    def test_staged_replacement_cannot_be_silently_committed_as_rewrite(self):
        peers = Peers()
        message = peers.bridge.message("L", self.request(peers))
        Connection(message).http2.replace_body(head(message), b"new")
        with self.assertRaisesRegex(CommitException, 'message.translate'):
            message.commit()

    def test_sandboxed_worker_requires_publication_of_staged_edits(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event

        endings = ("return api.message.translate()", "return api.message.commit()", "return None")
        cases = [(active, ending) for active in (False, True) for ending in endings]
        for active, ending in cases:
            with self.subTest(active=active, ending=ending):
                peers = Peers()
                wire = self.request(peers)
                callback = event(wire)
                callback["details"]["info"]["webhook_control"] = {"content-reverse": True}
                script = (
                    "header = next(part for part in api.message.parts if part.frame_type == 1)\n"
                    "api.connection.http2.replace_body(header, b'from sandbox')\n"
                    "api.connection.http2.replace_trailers(header, [api.http2.Header(b'x-end', b'yes')])\n"
                    + ending
                )
                result = run(script, callback, translate_active=active, translate_allowed=not active,
                             translate_state=peers.bridge.tables["L"] if active else None,
                             translate_control=peers.bridge.control if active else None,
                             instance={"mode": "flow"})
                self.assertEqual(result["ok"], ending == "return api.message.translate()", result)
                if result["ok"]:
                    events = peers.peers["R"].receive_data(base64.b64decode(result["replacement"]))
                    self.assertEqual([item.data for item in events if isinstance(item, h2.events.DataReceived)], [b"from sandbox"])
                    self.assertTrue(result["translated"])
                else:
                    self.assertIsNone(result["replacement"])
                    self.assertNotIn("translate_control", result)


if __name__ == "__main__":
    unittest.main()
