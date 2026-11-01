"""Connection lifecycle hook value parity against mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_server_hooks_contract import collect


class ServerHookTests(unittest.TestCase):
    def test_public_value_contract_matches_reference(self):
        expected = json.loads(
            (ROOT / "tests/corpus/addon_server_hooks_v12.json").read_text()
        )
        modules = compatibility_modules()

        with compatibility_imports(modules):
            from mitmproxy import connection
            from mitmproxy.proxy import server_hooks

            actual = collect(server_hooks, connection)
            self.assertIs(
                modules["mitmproxy.proxy"].server_hooks,
                modules["mitmproxy.proxy.server_hooks"],
            )

        self.assertEqual(expected["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, {
            "data": expected["data"],
            "hooks": expected["hooks"],
        })


if __name__ == "__main__":
    unittest.main()
