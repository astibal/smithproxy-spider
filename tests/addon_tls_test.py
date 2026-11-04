"""TLS addon value parity against public mitmproxy 12.3.1 behavior."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_tls_contract import collect, tls_client_hello, dtls_client_hello
from addon_tls import ClientHello


class TLSAddonTests(unittest.TestCase):
    def test_raw_bytes_can_omit_record(self):
        body = tls_client_hello()
        hello = ClientHello(body)
        record = bytes.fromhex('160303') + (len(body) + 4).to_bytes(2, 'big')
        record += bytes([1]) + len(body).to_bytes(3, 'big') + body

        self.assertEqual(hello.raw_bytes(), record)
        self.assertEqual(hello.raw_bytes(wrap_in_record=True), record)
        self.assertEqual(hello.raw_bytes(False), body)
        self.assertEqual(hello.raw_bytes(wrap_in_record=False), body)

    def test_dtls_raw_bytes_remains_unsupported(self):
        hello = ClientHello(dtls_client_hello(), dtls=True)
        for wrap in (False, True):
            with self.subTest(wrap=wrap):
                with self.assertRaises(NotImplementedError):
                    hello.raw_bytes(wrap_in_record=wrap)

    def test_public_contract_matches_reference(self):
        expected = json.loads(
            (ROOT / "tests/corpus/addon_tls_v12.json").read_text()
        )
        modules = compatibility_modules()

        with compatibility_imports(modules):
            from mitmproxy import connection, options, tls
            from mitmproxy.proxy import context

            actual = collect(tls, connection, options, context)
            self.assertIs(
                modules["mitmproxy.proxy"].context,
                modules["mitmproxy.proxy.context"],
            )

        self.assertEqual(expected["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, {
            key: value
            for key, value in expected.items()
            if key != "reference"
        })


if __name__ == "__main__":
    unittest.main()
