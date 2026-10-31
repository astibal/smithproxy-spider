"""Black-box saved-flow observations shared by reference and local tests."""

import hashlib
import io as stdlib_io
import ipaddress
from pathlib import Path
import re
import tempfile


def _stable_message(value):
    if value is None:
        return None
    return re.sub(r"<memory at 0x[0-9a-fA-F]+>", "<memory>", value)


def _outcome(operation):
    try:
        value = operation()
        return {
            "ok": True,
            "type": type(value).__name__,
            "repr": repr(value),
        }
    except Exception as error:
        cause = error.__cause__
        return {
            "ok": False,
            "type": type(error).__name__,
            "message": _stable_message(str(error)),
            "cause_type": None if cause is None else type(cause).__name__,
            "cause_message": _stable_message(None if cause is None else str(cause)),
        }


def make_flow(HTTPFlow, Request, Response, Client, Server, method="POST"):
    client = Client(peername=("127.0.0.1", 12345),
                    sockname=("127.0.0.1", 8080))
    server = Server(address=("example.test", 443))
    flow = HTTPFlow(client, server)
    flow.id = "flow-id"
    flow.timestamp_created = 1.0
    client.id = "client-id"
    client.timestamp_start = 2.0
    server.id = "server-id"
    flow.request = Request.make(
        method,
        "https://example.test/path?x=1",
        b"request body",
        [(b"X-Order", b"one"), (b"X-Order", b"two")],
    )
    flow.request.timestamp_start = 3.0
    flow.request.timestamp_end = 4.0
    flow.response = Response.make(
        201,
        b"response body",
        [(b"X-Response", b"three")],
    )
    flow.response.timestamp_start = 5.0
    flow.response.timestamp_end = 6.0
    flow.metadata = {"flag": True, "list": [b"x", "y"]}
    flow.comment = "saved observation"
    return flow


def collect_tnetstrings(tnetstring):
    values = [
        None, True, False, 0, 1, -2, 1.0, -0.0, 1.25,
        b"", b"a", b"\x00\xff", "", "héllo",
        [], [1, "a"], (), (1, b"x"),
        {}, {"a": 1}, {b"a": 1}, {"z": 1, "a": 2},
        {2: "two", 1: "one"}, {"1": "string", 1: "integer"},
    ]
    encoded = []
    for value in values:
        wire = tnetstring.dumps(value)
        encoded.append({
            "value": repr(value),
            "wire": wire.hex(),
            "loaded_type": type(tnetstring.loads(wire)).__name__,
            "loaded": repr(tnetstring.loads(wire)),
        })

    malformed = [
        b"", b"junk", b"3:abc", b"4:tru!", b"2:{}", b"1:a}",
        b"1:\xff;", b"2:1:a]", b"4:1:a,}", b"1:x#",
    ]
    errors = [
        {"wire": wire.hex(), **_outcome(lambda wire=wire: tnetstring.loads(wire))}
        for wire in malformed
    ]

    split_length, split_remainder = tnetstring.split(
        memoryview(b"3:abc,tail"), b":"
    )
    helpers = {
        "split": {
            "length": split_length,
            "remainder": bytes(split_remainder).hex(),
            "remainder_type": type(split_remainder).__name__,
        },
        "parse_bytes": repr(tnetstring.parse(ord(","), memoryview(b"abc"))),
        "parse_integer": repr(tnetstring.parse(ord("#"), memoryview(b"-12"))),
        "split_missing": _outcome(
            lambda: tnetstring.split(memoryview(b"abc"), b":")
        ),
        "parse_unknown": _outcome(
            lambda: tnetstring.parse(ord("?"), memoryview(b"abc"))
        ),
    }
    return {"encoded": encoded, "errors": errors, "helpers": helpers}


def collect_path_errors(io_module):
    with tempfile.TemporaryDirectory(prefix="addon-io-contract-") as directory:
        root = Path(directory)
        return {
            "missing": _outcome(
                lambda: io_module.read_flows_from_paths([root / "missing"])
            ),
            "directory": _outcome(
                lambda: io_module.read_flows_from_paths([root])
            ),
        }


def collect(io_module, HTTPFlow, Request, Response, Client, Server, parse_filter):
    flow = make_flow(HTTPFlow, Request, Response, Client, Server)
    output = stdlib_io.BytesIO()
    io_module.FlowWriter(output).add(flow)
    wire = output.getvalue()
    restored = list(io_module.FlowReader(stdlib_io.BytesIO(wire)).stream())[0]

    filtered = {}
    for expression in (None, "~m POST", "~m GET"):
        destination = stdlib_io.BytesIO()
        parsed = None if expression is None else parse_filter(expression)
        writer = io_module.FilteredFlowWriter(destination, parsed)
        writer.add(flow)
        filtered[repr(expression)] = destination.getvalue().hex()

    invalid = []
    for data in (b"", b"junk", b"1:a,", b"0:~", b"1:x#"):
        invalid.append({
            "wire": data.hex(),
            **_outcome(lambda data=data: list(
                io_module.FlowReader(stdlib_io.BytesIO(data)).stream()
            )),
        })

    return {
        "wire_hex": wire.hex(),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
        "roundtrip": {
            "type": type(restored).__name__,
            "id": restored.id,
            "method": restored.request.method,
            "url": restored.request.url,
            "request_headers": [
                [name.decode("latin-1"), value.decode("latin-1")]
                for name, value in restored.request.headers.fields
            ],
            "request_content": restored.request.raw_content.decode("ascii"),
            "status_code": restored.response.status_code,
            "response_content": restored.response.raw_content.decode("ascii"),
            "metadata": repr(restored.metadata),
            "comment": restored.comment,
            "live": restored.live,
        },
        "filtered": filtered,
        "invalid": invalid,
    }


def collect_transport(io_module, TCPFlow, TCPMessage, UDPFlow, UDPMessage,
                      Client, Server):
    flows = []
    for kind, flow_type, message_type in (
        ("tcp", TCPFlow, TCPMessage),
        ("udp", UDPFlow, UDPMessage),
    ):
        client = Client(peername=("192.0.2.10", 2345),
                        sockname=("192.0.2.20", 443))
        server = Server(address=("transport.example", 443))
        flow = flow_type(client, server)
        flow.id = kind + "-flow"
        flow.timestamp_created = 10.0
        client.id = kind + "-client"
        client.timestamp_start = 11.0
        server.id = kind + "-server"
        flow.messages = [
            message_type(True, b"\x00request", 12.0),
            message_type(False, b"reply\xff", 13.0),
        ]
        flow.metadata = {"transport": kind}
        flows.append(flow)

    destination = stdlib_io.BytesIO()
    writer = io_module.FlowWriter(destination)
    for flow in flows:
        writer.add(flow)
    wire = destination.getvalue()
    restored = list(io_module.FlowReader(stdlib_io.BytesIO(wire)).stream())
    return {
        "wire_hex": wire.hex(),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
        "flows": [
            {
                "type": type(flow).__name__,
                "id": flow.id,
                "messages": [
                    [message.from_client, message.content.hex(), message.timestamp]
                    for message in flow.messages
                ],
                "metadata": flow.metadata,
                "live": flow.live,
            }
            for flow in restored
        ],
    }


def collect_dns(io_module, DNSFlow, DNSMessage, Question, ResourceRecord,
                types, classes, op_codes, response_codes, Client, Server):
    client = Client(peername=("192.0.2.30", 53000),
                    sockname=("192.0.2.20", 53),
                    transport_protocol="udp")
    server = Server(address=("resolver.example", 53),
                    transport_protocol="udp")
    flow = DNSFlow(client, server)
    flow.id = "dns-flow"
    flow.timestamp_created = 20.0
    client.id = "dns-client"
    client.timestamp_start = 21.0
    server.id = "dns-server"
    flow.request = DNSMessage(
        id=0x1234,
        query=True,
        op_code=op_codes.QUERY,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=True,
        recursion_available=False,
        reserved=0,
        response_code=response_codes.NOERROR,
        questions=[Question("example.test", types.A, classes.IN)],
        answers=[],
        authorities=[],
        additionals=[],
        timestamp=22.0,
    )
    flow.response = flow.request.succeed([
        ResourceRecord.A(
            "example.test", ipaddress.IPv4Address("192.0.2.40"), ttl=30
        )
    ])
    flow.response.timestamp = 23.0

    destination = stdlib_io.BytesIO()
    io_module.FlowWriter(destination).add(flow)
    wire = destination.getvalue()
    restored = list(io_module.FlowReader(stdlib_io.BytesIO(wire)).stream())[0]
    return {
        "wire_hex": wire.hex(),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
        "type": type(restored).__name__,
        "id": restored.id,
        "request": restored.request.packed.hex(),
        "response": restored.response.packed.hex(),
        "live": restored.live,
    }


def collect_websocket(io_module, HTTPFlow, Request, Response, WebSocketData,
                      WebSocketMessage, Client, Server):
    flow = make_flow(HTTPFlow, Request, Response, Client, Server, "GET")
    flow.id = "websocket-flow"
    flow.websocket = WebSocketData([
        WebSocketMessage(1, True, b"client text", timestamp=30.0),
        WebSocketMessage(2, False, b"\x00server binary", timestamp=31.0),
    ])
    flow.websocket.closed_by_client = True
    flow.websocket.close_code = 1000
    flow.websocket.close_reason = "finished"
    flow.websocket.timestamp_end = 32.0

    destination = stdlib_io.BytesIO()
    io_module.FlowWriter(destination).add(flow)
    wire = destination.getvalue()
    restored = list(io_module.FlowReader(stdlib_io.BytesIO(wire)).stream())[0]
    return {
        "wire_hex": wire.hex(),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
        "type": type(restored.websocket).__name__,
        "messages": [
            [message.type, message.from_client, message.content.hex(),
             message.timestamp, message.dropped, message.injected]
            for message in restored.websocket.messages
        ],
        "closed_by_client": restored.websocket.closed_by_client,
        "close_code": restored.websocket.close_code,
        "close_reason": restored.websocket.close_reason,
        "timestamp_end": restored.websocket.timestamp_end,
        "live": restored.live,
    }
