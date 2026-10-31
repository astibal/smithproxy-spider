"""Record public server-spec parsing through an isolated mitmproxy runtime."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_server_spec_contract import collect
from mitmproxy.net import server_spec


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "cases": collect(server_spec),
    }, indent=2, sort_keys=True))
