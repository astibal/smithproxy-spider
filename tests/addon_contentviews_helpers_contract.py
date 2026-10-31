"""Public content-view helper behavior shared with the reference probe."""

import gzip
import re


def collect(contentviews, http, tcp, udp, websocket, dns, connection, options):
    observations = {}

    def serializable(value):
        if isinstance(value, bytes):
            return {"bytes": value.hex()}
        if isinstance(value, tuple):
            return [serializable(item) for item in value]
        if isinstance(value, list):
            return [serializable(item) for item in value]
        if isinstance(value, dict):
            return {key: serializable(item) for key, item in value.items()}
        return value

    def record(name, operation):
        try:
            observations[name] = {"value": serializable(operation())}
        except Exception as error:
            observations[name] = {
                "error": type(error).__name__,
                "message": re.sub(
                    r"0x[0-9a-fA-F]+", "0xADDRESS", str(error)),
            }

    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.20", 443),
    )
    server = connection.Server(address=("198.51.100.30", 443))

    http_flow = http.HTTPFlow(client, server)
    request = http.Request.make(
        "POST",
        "https://example.test/path",
        b"request body",
        {"Content-Type": "text/x-edge"},
    )
    response = http.Response.make(
        200,
        b"response body",
        {"Content-Type": "application/x-edge-response"},
    )
    http_flow.request = request
    http_flow.response = response

    tcp_flow = tcp.TCPFlow(client, server)
    tcp_message = tcp.TCPMessage(True, b"tcp payload", 1.0)
    tcp_flow.messages.append(tcp_message)

    udp_flow = udp.UDPFlow(client, server)
    udp_message = udp.UDPMessage(False, b"udp payload", 2.0)
    udp_flow.messages.append(udp_message)

    websocket_flow = http.HTTPFlow(client, server)
    websocket_flow.request = request.copy()
    websocket_flow.response = response.copy()
    websocket_flow.websocket = websocket.WebSocketData()
    websocket_message = websocket.WebSocketMessage(1, True, b"websocket payload", 3.0)
    websocket_flow.websocket.messages.append(websocket_message)

    dns_flow = dns.DNSFlow(client, server)
    dns_message = dns.DNSMessage(
        7, True, 0, False, False, True, False, 0, 0,
        [], [], [], [], 4.0,
    )
    dns_flow.request = dns_message

    messages = (
        ("http_request", request, http_flow),
        ("http_response", response, http_flow),
        ("tcp", tcp_message, tcp_flow),
        ("udp", udp_message, udp_flow),
        ("websocket", websocket_message, websocket_flow),
        ("dns", dns_message, dns_flow),
    )

    for name, message, flow in messages:
        record("get_data/" + name, lambda message=message:
               contentviews.get_data(message))

        def metadata_snapshot(message=message, flow=flow):
            metadata = contentviews.make_metadata(message, flow)
            return {
                "flow": metadata.flow is flow,
                "content_type": metadata.content_type,
                "http_message": metadata.http_message is message,
                "tcp_message": metadata.tcp_message is message,
                "udp_message": metadata.udp_message is message,
                "websocket_message": metadata.websocket_message is message,
                "dns_message": metadata.dns_message is message,
                "protobuf_definitions": (
                    None if metadata.protobuf_definitions is None
                    else str(metadata.protobuf_definitions)
                ),
                "original_data": metadata.original_data,
            }

        record("metadata/" + name, metadata_snapshot)

    record("get_data/invalid", lambda: contentviews.get_data(object()))
    record("metadata/invalid", lambda: contentviews.make_metadata(object(), http_flow))

    compressed = gzip.compress(b"compressed body", mtime=0)
    encoded = http.Response(
        b"HTTP/1.1", 200, b"OK",
        http.Headers(((b"content-encoding", b"gzip"),)),
        compressed, None, 5.0, None)
    broken_encoding = http.Response(
        b"HTTP/1.1", 200, b"OK",
        http.Headers(((b"content-encoding", b"gzip"),)),
        b"broken", None, 5.0, None)
    record("get_data/encoded", lambda: contentviews.get_data(encoded))
    record("get_data/broken_encoding", lambda: contentviews.get_data(broken_encoding))

    options.protobuf_definitions = "/tmp/contentview-edge.proto"
    record(
        "metadata/protobuf_definitions",
        lambda: str(contentviews.make_metadata(
            request, http_flow).protobuf_definitions),
    )
    options.protobuf_definitions = None

    class HelperEdge(contentviews.InteractiveContentview):
        name = "HelperEdge"
        syntax_highlight = "yaml"

        def prettify(self, data, metadata):
            return metadata.content_type + ":" + data.decode("ascii")

        def render_priority(self, data, metadata):
            return 10000

        def reencode(self, prettified, metadata):
            return (metadata.content_type + ":" + prettified).encode("ascii")

    class ReadOnlyEdge(contentviews.Contentview):
        name = "ReadOnlyEdge"

        def prettify(self, data, metadata):
            return data.decode("ascii")

    contentviews.add(HelperEdge())
    contentviews.add(ReadOnlyEdge())

    record(
        "prettify/http",
        lambda: vars(contentviews.prettify_message(
            request, http_flow, "HelperEdge")),
    )
    record(
        "prettify/missing",
        lambda: vars(contentviews.prettify_message(
            request, http_flow, "missing-edge-view")),
    )
    record(
        "reencode/http",
        lambda: contentviews.reencode_message(
            "edited", request, http_flow, "HelperEdge"),
    )
    record(
        "reencode/read_only",
        lambda: contentviews.reencode_message(
            "edited", request, http_flow, "ReadOnlyEdge"),
    )
    record(
        "reencode/missing",
        lambda: contentviews.reencode_message(
            "edited", request, http_flow, "missing-edge-view"),
    )

    empty = http.Response(
        b"HTTP/1.1", 204, b"No Content", (), None, None, 5.0, None)
    empty_flow = http.HTTPFlow(client, server)
    empty_flow.request = request.copy()
    empty_flow.response = empty
    record("get_data/empty", lambda: contentviews.get_data(empty))
    record(
        "prettify/empty",
        lambda: vars(contentviews.prettify_message(
            empty, empty_flow, "HelperEdge")),
    )

    return observations
