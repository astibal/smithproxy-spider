"""Observe proxy-mode values through the public data-model API."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_proxy_mode_contract import collect
from mitmproxy.proxy import mode_specs


if __name__ == '__main__':
    print(json.dumps({'reference': 'mitmproxy 12.3.1',
                      'cases': collect(mode_specs)}, indent=2))
