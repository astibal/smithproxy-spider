"""TLS hook value parity against mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_tls_hooks_contract import collect


class TLSHookTests(unittest.TestCase):
    def test_public_value_contract_matches_reference(self):
        expected = json.loads(
            (ROOT / "tests/corpus/addon_tls_hooks_v12.json").read_text()
        )
        modules = compatibility_modules()

        with compatibility_imports(modules):
            from mitmproxy import connection, options, tls
            from mitmproxy.proxy import context
            from mitmproxy.proxy.layers import tls as tls_hooks

            actual = collect(tls_hooks, tls, connection, options, context)

        self.assertEqual(expected["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, expected["hooks"])


if __name__ == "__main__":
    unittest.main()
