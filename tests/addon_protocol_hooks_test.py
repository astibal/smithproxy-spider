"""Protocol hook value parity against mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_protocol_hooks_contract import collect


class ProtocolHookTests(unittest.TestCase):
    def test_public_value_contract_matches_reference(self):
        expected = json.loads(
            (ROOT / "tests/corpus/addon_protocol_hooks_v12.json").read_text()
        )
        modules = compatibility_modules()

        with compatibility_imports(modules):
            from mitmproxy import connection, dns, http, tcp, udp
            from mitmproxy.proxy.layers import dns as dns_hooks
            from mitmproxy.proxy.layers import tcp as tcp_hooks
            from mitmproxy.proxy.layers import udp as udp_hooks
            from mitmproxy.proxy.layers import websocket as websocket_hooks

            actual = collect(
                websocket_hooks,
                dns_hooks,
                tcp_hooks,
                udp_hooks,
                http,
                dns,
                tcp,
                udp,
                connection,
            )

        self.assertEqual(expected["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, expected["hooks"])


if __name__ == "__main__":
    unittest.main()
