"""Observe command registration edges in an isolated mitmproxy runtime."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_command_registration_edges_contract import collect
from mitmproxy import command


if __name__ == "__main__":
    print(json.dumps({
        "reference": "mitmproxy 12.3.1",
        "observations": collect(command),
    }, indent=2, ensure_ascii=False))
