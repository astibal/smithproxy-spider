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
from addon_tls_contract import collect


class TLSAddonTests(unittest.TestCase):
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
