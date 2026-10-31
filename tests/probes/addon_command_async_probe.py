"""Observe asynchronous public command behavior in mitmproxy 12.3.1."""

import asyncio
import json
from pathlib import Path
import sys

from mitmproxy import command
from mitmproxy.master import Master
from mitmproxy.options import Options

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_command_async_contract import collect


async def observe():
    master = None

    def factory():
        nonlocal master
        master = Master(Options())
        return master

    try:
        return await collect(command, factory)
    finally:
        if master is not None:
            await master.done()


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": asyncio.run(observe()),
    }, indent=2))
