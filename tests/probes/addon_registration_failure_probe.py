"""Observe registration failure boundaries in isolated mitmproxy 12.3.1."""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from addon_registration_failure_contract import collect
from mitmproxy import hooks
from mitmproxy.master import Master
from mitmproxy.options import Options


def factory():
    return Master(Options())


def running_event(master):
    master.addons.trigger(hooks.RunningHook())


if __name__ == "__main__":
    observations = asyncio.run(collect(factory, running_event))
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "cases": observations,
    }, indent=2))
