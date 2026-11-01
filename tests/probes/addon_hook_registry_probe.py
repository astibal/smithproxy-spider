"""Record the populated public hook registry from an isolated reference."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import addonmanager, hooks, log
from mitmproxy.proxy import server_hooks
from mitmproxy.proxy.layers import http

from addon_hook_registry_contract import collect


# These imports intentionally populate the reference's dynamic registry.
assert addonmanager.LoadHook
assert log.AddLogHook
assert server_hooks.ServerConnectHook
assert http.HttpRequestHook

print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "hooks": collect(hooks),
}, sort_keys=True, indent=2))
