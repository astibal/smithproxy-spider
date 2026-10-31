"""Observe content-view helpers in an isolated mitmproxy 12.3.1 runtime."""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_contentviews_helpers_contract import collect
from mitmproxy import connection, contentviews, dns, http, tcp, udp, websocket
from mitmproxy.master import Master
from mitmproxy.options import Options


async def observe():
    master = Master(Options())
    try:
        return collect(
            contentviews, http, tcp, udp, websocket, dns, connection,
            master.options)
    finally:
        await master.done()


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": asyncio.run(observe()),
    }, indent=2))
