"""Observe addon traversal in an isolated mitmproxy 12.3.1 runtime."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_traverse_contract import collect
from mitmproxy import addonmanager


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": collect(addonmanager),
    }, indent=2))
