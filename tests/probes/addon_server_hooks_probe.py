"""Record connection lifecycle hook values from an isolated reference."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection
from mitmproxy.proxy import server_hooks

from addon_server_hooks_contract import collect


result = collect(server_hooks, connection)
print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    **result,
}, sort_keys=True, indent=2))
