"""Record non-HTTP protocol hook values from an isolated reference."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection, dns, http, tcp, udp
from mitmproxy.proxy.layers import dns as dns_hooks
from mitmproxy.proxy.layers import tcp as tcp_hooks
from mitmproxy.proxy.layers import udp as udp_hooks
from mitmproxy.proxy.layers import websocket as websocket_hooks

from addon_protocol_hooks_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "hooks": collect(
        websocket_hooks,
        dns_hooks,
        tcp_hooks,
        udp_hooks,
        http,
        dns,
        tcp,
        udp,
        connection,
    ),
}, sort_keys=True, indent=2))
