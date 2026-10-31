"""Saved-flow compatibility tests for the clean-room addon facade."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import addon_connection
import addon_dns
import addon_flow
import addon_flowfilter
import addon_http_message
import addon_io
import addon_tnetstring
import addon_websocket
from addon_io_contract import (
    collect, collect_dns, collect_path_errors, collect_tnetstrings,
    collect_transport, make_flow,
    collect_websocket,
)
from addon_loader import compatibility_imports
from addon_modules import compatibility_modules


class SavedFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(
            (ROOT / "tests/corpus/addon_io_v12.json").read_text()
        )

    def test_tnetstring_reference_contract(self):
        self.assertEqual(
            collect_tnetstrings(addon_tnetstring),
            self.corpus["tnetstring"],
        )

    def test_tnetstring_edge_probe_matches_reference_corpus(self):
        output = io.StringIO()
        with compatibility_imports(compatibility_modules()):
            with redirect_stdout(output):
                runpy.run_path(
                    str(ROOT / "tests/probes/addon_tnetstring_edges_probe.py")
                )

        actual = json.loads(output.getvalue())
        expected = json.loads(
            (ROOT / "tests/corpus/addon_tnetstring_edges_v12.json").read_text()
        )

        # The reference leaks IndexError for a truncated file. Keep Spider's
        # stable format error rather than copying that implementation accident.
        truncated = actual["cases"].pop("load-truncated")
        expected["cases"].pop("load-truncated")
        self.assertEqual(truncated, {
            "cause": None,
            "message": "not a tnetstring: invalid length prefix: 3",
            "ok": False,
            "type": "ValueError",
        })
        self.assertEqual(actual, expected)

    def test_flow_io_reference_contract(self):
        actual = collect(
            addon_io,
            addon_flow.HTTPFlow,
            addon_http_message.Request,
            addon_http_message.Response,
            addon_connection.Client,
            addon_connection.Server,
            addon_flowfilter.parse,
        )
        self.assertEqual(actual, self.corpus["flow_io"])

    def test_path_error_reference_contract(self):
        self.assertEqual(
            collect_path_errors(addon_io),
            self.corpus["path_errors"],
        )

    def test_public_import_surface(self):
        with compatibility_imports(compatibility_modules()):
            from mitmproxy import io as public_io
            from mitmproxy.io import tnetstring

            self.assertIs(public_io.FlowReader, addon_io.FlowReader)
            self.assertEqual(tnetstring.loads(tnetstring.dumps("saved")), "saved")
            length, remaining = tnetstring.split(
                memoryview(b"3:abc,tail"), b":"
            )
            self.assertEqual(length, 3)
            self.assertEqual(bytes(remaining), b"abc,tail")
            self.assertEqual(
                tnetstring.parse(ord(","), memoryview(b"payload")),
                b"payload",
            )

    def test_tcp_udp_saved_flow_reference_contract(self):
        actual = collect_transport(
            addon_io,
            addon_flow.TCPFlow,
            addon_flow.TCPMessage,
            addon_flow.UDPFlow,
            addon_flow.UDPMessage,
            addon_connection.Client,
            addon_connection.Server,
        )
        self.assertEqual(actual, self.corpus["transport_io"])

    def test_dns_saved_flow_reference_contract(self):
        actual = collect_dns(
            addon_io,
            addon_dns.DNSFlow,
            addon_dns.DNSMessage,
            addon_dns.Question,
            addon_dns.ResourceRecord,
            addon_dns.types,
            addon_dns.classes,
            addon_dns.op_codes,
            addon_dns.response_codes,
            addon_connection.Client,
            addon_connection.Server,
        )
        self.assertEqual(actual, self.corpus["dns_io"])

    def test_websocket_saved_flow_reference_contract(self):
        actual = collect_websocket(
            addon_io,
            addon_flow.HTTPFlow,
            addon_http_message.Request,
            addon_http_message.Response,
            addon_websocket.WebSocketData,
            addon_websocket.WebSocketMessage,
            addon_connection.Client,
            addon_connection.Server,
        )
        self.assertEqual(actual, self.corpus["websocket_io"])

    def test_multiple_flows_and_path_reader(self):
        first = make_flow(
            addon_flow.HTTPFlow,
            addon_http_message.Request,
            addon_http_message.Response,
            addon_connection.Client,
            addon_connection.Server,
            "GET",
        )
        second = make_flow(
            addon_flow.HTTPFlow,
            addon_http_message.Request,
            addon_http_message.Response,
            addon_connection.Client,
            addon_connection.Server,
            "POST",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows"
            with path.open("wb") as destination:
                writer = addon_io.FlowWriter(destination)
                writer.add(first)
                writer.add(second)
            restored = addon_io.read_flows_from_paths([path, path])
        self.assertEqual(
            [flow.request.method for flow in restored],
            ["GET", "POST", "GET", "POST"],
        )

    def test_non_seekable_input_preserves_first_byte(self):
        flow = make_flow(
            addon_flow.HTTPFlow,
            addon_http_message.Request,
            addon_http_message.Response,
            addon_connection.Client,
            addon_connection.Server,
        )
        destination = io.BytesIO()
        addon_io.FlowWriter(destination).add(flow)

        class NonSeekable:
            def __init__(self, data):
                self.source = io.BytesIO(data)

            def read(self, size=-1):
                return self.source.read(size)

        restored = list(addon_io.FlowReader(NonSeekable(destination.getvalue())).stream())
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].request.url, flow.request.url)

    def test_prefixed_reader_handles_unbounded_and_partial_reads(self):
        reader = addon_io._PrefixedReader(b"ab", io.BytesIO(b"cd"))
        self.assertEqual(reader.read(), b"abcd")
        self.assertEqual(reader.read(), b"")

        reader = addon_io._PrefixedReader(b"ab", io.BytesIO(b"cdef"))
        self.assertEqual(reader.read(3), b"abc")
        self.assertEqual(reader.read(3), b"def")

    def test_reader_wraps_unknown_flow_type_as_invalid_flow(self):
        wire = addon_tnetstring.dumps({"type": "unknown"})
        reader = addon_io.FlowReader(io.BytesIO(wire)).stream()
        with self.assertRaisesRegex(
            addon_io.FlowReadException,
            "Invalid flow: Unknown flow type: unknown",
        ):
            next(reader)

    def test_reader_yields_complete_prefix_before_reporting_corruption(self):
        flow = make_flow(
            addon_flow.HTTPFlow,
            addon_http_message.Request,
            addon_http_message.Response,
            addon_connection.Client,
            addon_connection.Server,
        )
        destination = io.BytesIO()
        addon_io.FlowWriter(destination).add(flow)
        destination.write(b"broken suffix")
        destination.seek(0)

        reader = addon_io.FlowReader(destination).stream()
        self.assertEqual(next(reader).id, flow.id)
        with self.assertRaisesRegex(addon_io.FlowReadException, "Invalid data format"):
            next(reader)

    def test_large_collection_roundtrip_does_not_require_nested_buffer_copies(self):
        value = [
            {"index": index, "payload": bytes([index % 251]) * 64}
            for index in range(2048)
        ]
        wire = addon_tnetstring.dumps(value)
        self.assertEqual(addon_tnetstring.loads(wire), value)


if __name__ == "__main__":
    unittest.main()
