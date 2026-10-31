"""Observe AddonManager.handle_lifecycle in isolated mitmproxy 12.3.1."""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_lifecycle_handler_contract import collect
from mitmproxy import connection, exceptions, hooks, http
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy.proxy.layers.http import _hooks


def factory():
    return Master(Options())


def make_flow():
    client = connection.Client(
        peername=("127.0.0.1", 1234),
        sockname=("127.0.0.1", 8080),
    )
    server = connection.Server(address=("example.test", 80))
    flow = http.HTTPFlow(client, server, live=True)
    flow.request = http.Request.make("GET", "http://example.test/")
    return flow


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": asyncio.run(collect(
            factory,
            _hooks.HttpRequestHook,
            hooks.RunningHook,
            make_flow,
            exceptions.OptionsError,
        )),
    }, indent=2))
