"""Observe extended command annotations through public calls only."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_command_extended_types_contract import collect
from mitmproxy import command, types


if __name__ == '__main__':
    print(json.dumps({'reference': 'mitmproxy 12.3.1',
                      'cases': collect(command, types)}, indent=2))
