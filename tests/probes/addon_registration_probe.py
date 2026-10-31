"""Run public registration observations with the isolated reference Python."""

import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_registration_contract import collect
from mitmproxy import hooks
from mitmproxy.master import Master
from mitmproxy.options import Options


def factory():
    return Master(Options())


def running_event(master):
    master.addons.trigger(hooks.RunningHook())


if __name__ == '__main__':
    print(json.dumps({'reference': 'mitmproxy 12.3.1',
                      'cases': asyncio.run(collect(factory, running_event))}, indent=2))
