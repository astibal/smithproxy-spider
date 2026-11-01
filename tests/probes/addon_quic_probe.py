"""Record public QUIC TLS hook values from an isolated reference runtime."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection, options, tls
from mitmproxy.proxy import context
from mitmproxy.proxy.layers import quic

from addon_quic_contract import collect


result = collect(quic, tls, connection, options, context)
print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    **result,
}, sort_keys=True, indent=2))
