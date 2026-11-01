"""Record public TLS hook values from an isolated reference."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection, options, tls
from mitmproxy.proxy import context
from mitmproxy.proxy.layers import tls as tls_hooks

from addon_tls_hooks_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "hooks": collect(tls_hooks, tls, connection, options, context),
}, sort_keys=True, indent=2))
