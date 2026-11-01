"""Record public TLS addon values from an isolated reference runtime."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import connection, options, tls
from mitmproxy.proxy import context

from addon_tls_contract import collect


result = collect(tls, connection, options, context)
print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    **result,
}, sort_keys=True, indent=2))
