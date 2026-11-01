#!/usr/bin/env python3
"""Emit reference observations for connection-model edge cases."""

import json

from mitmproxy import connection

from addon_connection_adversarial_contract import collect


print(json.dumps({
    "cases": collect(connection),
    "reference": "mitmproxy 12.3.1",
}, indent=2, sort_keys=True))
