"""Record the legacy content-view bridge from an isolated reference."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mitmproxy import contentviews

from addon_contentviews_legacy_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "observations": collect(contentviews),
}, sort_keys=True, indent=2))
