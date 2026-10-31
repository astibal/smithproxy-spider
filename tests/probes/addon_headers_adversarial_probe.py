#!/usr/bin/env python3
"""Emit public Headers edge-case observations from the reference runtime."""

import json

from mitmproxy import http

from addon_headers_adversarial_contract import collect


print(json.dumps({"cases": collect(http)}, indent=2, sort_keys=True))
