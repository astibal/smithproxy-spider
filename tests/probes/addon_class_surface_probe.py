"""Record the public attributes of core mitmproxy 12 addon value classes."""

import argparse
import json
from pathlib import Path

from mitmproxy import connection, dns, flow, http, tcp, udp, websocket
from mitmproxy import version


CLASSES = {
    "Client": connection.Client,
    "Connection": connection.Connection,
    "DNSFlow": dns.DNSFlow,
    "DNSMessage": dns.DNSMessage,
    "Error": flow.Error,
    "Flow": flow.Flow,
    "HTTPFlow": http.HTTPFlow,
    "Headers": http.Headers,
    "Message": http.Message,
    "Request": http.Request,
    "Response": http.Response,
    "Server": connection.Server,
    "TCPFlow": tcp.TCPFlow,
    "TCPMessage": tcp.TCPMessage,
    "UDPFlow": udp.UDPFlow,
    "UDPMessage": udp.UDPMessage,
    "WebSocketData": websocket.WebSocketData,
    "WebSocketMessage": websocket.WebSocketMessage,
}


def collect():
    return {
        "reference": version.MITMPROXY,
        "classes": {
            name: sorted(attribute for attribute in dir(value)
                         if not attribute.startswith("_"))
            for name, value in CLASSES.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()

    result = collect()
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference class surface changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
