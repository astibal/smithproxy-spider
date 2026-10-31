"""Observe public Master.load_flow behavior with an isolated mitmproxy 12."""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from addon_load_flow_contract import collect
from mitmproxy import connection, dns, flow, http, tcp, udp, websocket
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy import version


async def main():
    master = Master(Options())
    print(json.dumps({
        "reference": version.MITMPROXY,
        "cases": await collect(
            master, http, tcp, udp, dns, websocket, connection, flow
        ),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
