"""Record public WebSocket values with an isolated reference installation."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_websocket_contract import collect
from mitmproxy import websocket


if __name__ == '__main__':
    print(json.dumps({'reference': 'mitmproxy 12.3.1',
                      'cases': collect(websocket)}, indent=2))
