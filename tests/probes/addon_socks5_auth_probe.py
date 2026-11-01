"""Record the public SOCKS5 authentication value contract."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection
from mitmproxy.proxy.layers import modes

from addon_socks5_auth_contract import collect

result = collect(modes, connection)
result = {
    "reference": "mitmproxy 12.3.1",
    **result,
}

print(json.dumps(result, sort_keys=True, indent=2))
