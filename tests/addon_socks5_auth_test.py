"""SOCKS5 authentication value parity against mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_socks5_auth_contract import collect


class Socks5AuthTests(unittest.TestCase):
    def test_public_value_contract_matches_reference(self):
        expected = json.loads(
            (ROOT / "tests/corpus/addon_socks5_auth_v12.json").read_text()
        )
        modules = compatibility_modules()

        with compatibility_imports(modules):
            from mitmproxy import connection, proxy
            from mitmproxy.proxy.layers import modes

            actual = collect(modes, connection)
            self.assertIs(proxy.layers, modules["mitmproxy.proxy.layers"])
            self.assertIs(
                proxy.layers.modes,
                modules["mitmproxy.proxy.layers.modes"],
            )

        self.assertEqual(expected["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, {
            "surface": expected["surface"],
            "before": expected["before"],
            "after": expected["after"],
        })


if __name__ == "__main__":
    unittest.main()
