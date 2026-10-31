"""Emit black-box observations for mitmproxy 12's public signal helpers."""

import asyncio
import json

from mitmproxy.utils import signals

from addon_signal_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "signals": asyncio.run(collect(signals)),
}, indent=2, sort_keys=True))
