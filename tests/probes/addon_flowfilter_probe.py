"""Observe flow-filter behavior through public APIs only."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from addon_flowfilter_contract import collect
from mitmproxy import connection, flow, flowfilter, http, tcp, udp


def peers(transport):
    return (
        connection.Client(
            peername=('10.0.0.5', 54321),
            sockname=('10.0.0.1', 8080),
            transport_protocol=transport,
        ),
        connection.Server(
            address=('example.org', 443),
            transport_protocol=transport,
        ),
    )


if __name__ == '__main__':
    print(json.dumps({
        'reference': 'mitmproxy 12.3.1',
        'cases': collect(flowfilter, http, flow, tcp, udp, peers),
    }, indent=2, sort_keys=True))
