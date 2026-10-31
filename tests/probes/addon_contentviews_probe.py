"""Record the public custom-content-view contract from mitmproxy 12.3.1."""

import json

from mitmproxy import contentviews

from addon_contentviews_contract import collect


print(json.dumps({
    "reference": "mitmproxy 12.3.1",
    "cases": collect(contentviews),
}, indent=2, sort_keys=True))
