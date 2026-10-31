"""Emit black-box observations for mitmproxy 12's option type helpers."""

import json

from mitmproxy.utils import typecheck

from addon_typecheck_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "typecheck": collect(typecheck),
}, indent=2, sort_keys=True))
