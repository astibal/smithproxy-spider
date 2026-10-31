#!/usr/bin/env python3
"""Record clean-room black-box observations of the public saved-flow API."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_io_contract import (
    collect, collect_dns, collect_path_errors, collect_tnetstrings, collect_transport,
    collect_websocket,
)


def observations():
    from mitmproxy import connection, dns, flowfilter, http, io, tcp, udp, websocket
    from mitmproxy.io import tnetstring

    return {
        "reference": "mitmproxy 12.3.1",
        "tnetstring": collect_tnetstrings(tnetstring),
        "path_errors": collect_path_errors(io),
        "flow_io": collect(
            io,
            http.HTTPFlow,
            http.Request,
            http.Response,
            connection.Client,
            connection.Server,
            flowfilter.parse,
        ),
        "transport_io": collect_transport(
            io,
            tcp.TCPFlow,
            tcp.TCPMessage,
            udp.UDPFlow,
            udp.UDPMessage,
            connection.Client,
            connection.Server,
        ),
        "dns_io": collect_dns(
            io,
            dns.DNSFlow,
            dns.DNSMessage,
            dns.Question,
            dns.ResourceRecord,
            dns.types,
            dns.classes,
            dns.op_codes,
            dns.response_codes,
            connection.Client,
            connection.Server,
        ),
        "websocket_io": collect_websocket(
            io,
            http.HTTPFlow,
            http.Request,
            http.Response,
            websocket.WebSocketData,
            websocket.WebSocketMessage,
            connection.Client,
            connection.Server,
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", type=Path)
    args = parser.parse_args()
    actual = observations()
    if args.expect:
        expected = json.loads(args.expect.read_text())
        if actual != expected:
            print(json.dumps(actual, indent=2, sort_keys=True))
            raise SystemExit("saved-flow observations differ from the corpus")
    else:
        print(json.dumps(actual, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
