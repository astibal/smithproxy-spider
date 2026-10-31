"""Run original public command observations in a separate reference environment."""

import asyncio
import json
import logging
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_command_contract import collect, collect_lifecycle
from mitmproxy import command
from mitmproxy.master import Master
from mitmproxy.options import Options


def factory():
    return Master(Options())


if __name__ == '__main__':
    # Keep diagnostics out of the JSON artifact; the contract records whether
    # failed declarations remain callable, not logger formatting.
    logging.disable(logging.CRITICAL)
    print(json.dumps({'reference': 'mitmproxy 12.3.1', 'cases': collect(command),
                      'lifecycle': asyncio.run(collect_lifecycle(command, factory))}, indent=2))
