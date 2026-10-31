"""Observe caller-owned query and cookie value lists in mitmproxy 12.3.1."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from addon_cookie_contract import collect as collect_cookies
from addon_query_contract import collect as collect_query
from mitmproxy import http


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "cookies": collect_cookies(http)["preserved_input"],
        "query": collect_query(http)["preserved_input"],
    }, indent=2))
