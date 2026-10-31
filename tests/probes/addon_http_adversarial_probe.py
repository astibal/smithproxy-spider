"""Observe HTTP message edge cases in isolated mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_http_adversarial_contract import collect
from mitmproxy import http


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": collect(http),
    }, indent=2))
