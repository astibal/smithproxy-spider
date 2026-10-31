"""Observe the public update hook in isolated mitmproxy 12.3.1."""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_update_contract import collect
from mitmproxy import hooks
from mitmproxy.master import Master
from mitmproxy.options import Options


def factory():
    return Master(Options())


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": asyncio.run(collect(factory, hooks.UpdateHook)),
    }, indent=2))
