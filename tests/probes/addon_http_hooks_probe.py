"""Record public HTTP hook values from an isolated reference."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection, http
from mitmproxy.proxy.layers import http as http_hooks
from mitmproxy.proxy.layers.http import _hooks as private_http_hooks

from addon_http_hooks_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "hooks": collect(http_hooks, private_http_hooks, http, connection),
}, sort_keys=True, indent=2))
