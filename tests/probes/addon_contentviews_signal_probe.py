"""Observe content-view registry signals in isolated mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_contentviews_signal_contract import collect
from mitmproxy import contentviews


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": collect(contentviews),
    }, indent=2))
