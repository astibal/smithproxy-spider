"""Shared live HTTP behavior used by the reference and Spider probes."""

import gzip


ADDON_SOURCE = '''#!mitmproxy
request_count = 0


def request(flow):
    global request_count
    request_count += 1
    flow.metadata["request_count"] = request_count
    flow.request.method = "PUT"
    flow.request.path = f"/addon/{request_count}?source=compat"
    flow.request.headers["x-addon-count"] = str(request_count)
    flow.request.headers.add("x-addon-duplicate", "first")
    flow.request.headers.add("x-addon-duplicate", "second")
    flow.request.content = f"request-{request_count}".encode()


def response(flow):
    request_count = flow.metadata["request_count"]
    flow.response.status_code = 210 + request_count
    flow.response.reason = f"Addon {request_count}"
    flow.response.headers["x-addon-count"] = str(request_count)
    flow.response.headers.add("x-addon-duplicate", "first")
    flow.response.headers.add("x-addon-duplicate", "second")
    flow.response.content = f"response-{request_count}".encode()
'''


SELECTED_HEADERS = frozenset({
    "content-encoding",
    "content-length",
    "content-type",
    "x-addon-count",
    "x-addon-duplicate",
    "x-client",
    "x-case",
    "x-matrix",
    "x-multi",
    "x-origin",
    "x-pipeline-sequence",
    "x-remove",
})


MATRIX_SOURCE = '''#!mitmproxy
def request(flow):
    case = int(flow.request.headers["x-case"])
    flow.metadata["case"] = case
    flow.request.method = ("PATCH", "PUT", "POST")[case % 3]
    flow.request.query["addon"] = str(case)
    flow.request.headers["x-matrix"] = f"request-{case}"
    flow.request.headers.set_all("x-multi", [f"{case}-first", f"{case}-second"])
    flow.request.headers.pop("x-remove", None)
    flow.request.content = flow.request.content[::-1] + f"/{case}".encode()


def response(flow):
    case = flow.metadata["case"]
    flow.response.status_code = 220 + case % 10
    flow.response.reason = f"Matrix {case}"
    flow.response.headers["x-matrix"] = f"response-{case}"
    flow.response.headers.set_all("x-multi", [f"{case}-left", f"{case}-right"])
    flow.response.headers.pop("x-remove", None)
    flow.response.content = flow.response.content[::-1] + f"/{case}".encode()
'''


PIPELINE_SOURCE = '''#!mitmproxy
request_count = 0


def request(flow):
    global request_count
    request_count += 1
    flow.metadata["pipeline_sequence"] = request_count
    flow.request.path = f"/pipeline/{request_count}"
    flow.request.headers["x-pipeline-sequence"] = str(request_count)


def response(flow):
    sequence = flow.metadata["pipeline_sequence"]
    flow.response.status_code = 220 + sequence
    flow.response.reason = f"Pipeline {sequence}"
    flow.response.headers["x-pipeline-sequence"] = str(sequence)
    flow.response.content = f"client-{sequence}".encode()
'''


TRAILER_SOURCE = '''#!mitmproxy
def request(flow):
    assert flow.request.trailers is not None
    assert flow.request.trailers["x-input-trailer"] == "request"
    flow.request.trailers.pop("x-remove", None)
    flow.request.trailers.set_all(
        "x-addon-trailer", ["request-first", "request-second"]
    )


def response(flow):
    assert flow.response.trailers is not None
    assert flow.response.trailers["x-input-trailer"] == "response"
    flow.response.trailers.pop("x-remove", None)
    flow.response.trailers.set_all(
        "x-addon-trailer", ["response-first", "response-second"]
    )
'''


H1_TRAILER_REQUEST = (
    b"POST /trailers HTTP/1.1\r\n"
    b"Host: input.example\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Trailer: X-Input-Trailer, X-Remove\r\n"
    b"Connection: close\r\n\r\n"
    b"7\r\nold-one\r\n"
    b"0\r\nX-Input-Trailer: request\r\nX-Remove: request\r\n\r\n"
)


H1_TRAILER_RESPONSE = (
    b"HTTP/1.1 201 Created\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Trailer: X-Input-Trailer, X-Remove\r\n"
    b"Connection: close\r\n\r\n"
    b"8\r\norigin-1\r\n"
    b"0\r\nX-Input-Trailer: response\r\nX-Remove: response\r\n\r\n"
)


def selected_headers(fields):
    """Normalize only deterministic application headers, retaining duplicates."""
    return [
        [name.lower(), value.strip()]
        for name, value in fields
        if name.lower() in SELECTED_HEADERS
    ]


def canonical_headers(fields):
    """Compare field values by name while preserving duplicate value order."""
    result = {}
    for name, value in selected_headers(fields):
        result.setdefault(name, []).append(value)
    return {name: result[name] for name in sorted(result)}


def matrix_cases(count=64):
    cases = []
    methods = ("GET", "POST", "DELETE", "OPTIONS")
    for case in range(count):
        body = (f"input-{case}-" + "x" * ((case * 17) % 257)).encode()
        cases.append({
            "case": case,
            "method": methods[case % len(methods)],
            "path": f"/matrix/{case}?input=yes",
            "body": body,
            "gzip_request": case % 4 == 3,
            "gzip_response": case % 5 == 4,
        })
    return cases


def matrix_request_wire(scenario):
    body = scenario["body"]
    headers = [
        ("Host", "input.example"),
        ("X-Case", str(scenario["case"])),
        ("X-Remove", "request"),
        ("X-Multi", "old"),
        ("Content-Type", "application/octet-stream"),
    ]
    if scenario["gzip_request"]:
        body = gzip.compress(body, mtime=0)
        headers.append(("Content-Encoding", "gzip"))
    headers.insert(0, ("Content-Length", str(len(body))))
    head = scenario["method"] + " " + scenario["path"] + " HTTP/1.1\r\n"
    head += "".join(name + ": " + value + "\r\n" for name, value in headers)
    return head.encode("latin-1") + b"\r\n" + body


def matrix_response_wire(scenario):
    case = scenario["case"]
    body = f"origin-{case}-".encode() + b"y" * ((case * 13) % 193)
    headers = [
        ("Content-Type", "application/octet-stream"),
        ("X-Origin", str(case)),
        ("X-Remove", "response"),
        ("X-Multi", "old"),
    ]
    if scenario["gzip_response"]:
        body = gzip.compress(body, mtime=0)
        headers.append(("Content-Encoding", "gzip"))
    headers.append(("Content-Length", str(len(body))))
    head = "HTTP/1.1 201 Created\r\n"
    head += "".join(name + ": " + value + "\r\n" for name, value in headers)
    return head.encode("latin-1") + b"\r\n" + body


def decoded_body(fields, body):
    """Decode the one content coding intentionally covered by this corpus."""
    encodings = [value.lower() for name, value in fields
                 if name.lower() == "content-encoding"]
    if encodings == ["gzip"]:
        return gzip.decompress(body)
    if encodings:
        raise AssertionError("Unexpected content coding in live HTTP corpus")
    return body


def parse_http1_message(wire):
    """Parse one complete Content-Length message produced by this contract."""
    head, separator, body = wire.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError("HTTP/1 message has no complete head")
    lines = head.split(b"\r\n")
    start_line = lines.pop(0).decode("latin-1")
    fields = []
    for line in lines:
        name, colon, value = line.partition(b":")
        if not colon:
            raise AssertionError("Malformed HTTP/1 field")
        fields.append((name.decode("latin-1"), value.decode("latin-1").strip()))
    return start_line, selected_headers(fields), body


def parse_http1_stream(wire):
    """Split complete Content-Length messages without interpreting semantics."""
    messages = []
    remaining = wire
    while remaining:
        head, separator, tail = remaining.partition(b"\r\n\r\n")
        if not separator:
            raise AssertionError("HTTP/1 stream ends inside a message head")
        lines = head.split(b"\r\n")
        fields = []
        content_length = 0
        for line in lines[1:]:
            name, colon, value = line.partition(b":")
            if not colon:
                raise AssertionError("Malformed HTTP/1 field")
            fields.append((name.decode("latin-1"), value.decode("latin-1").strip()))
            if name.lower() == b"content-length":
                content_length = int(value.strip())
        if len(tail) < content_length:
            raise AssertionError("HTTP/1 stream ends inside a message body")
        body = tail[:content_length]
        remaining = tail[content_length:]
        messages.append({
            "start": lines[0].decode("latin-1"),
            "headers": selected_headers(fields),
            "body": body.decode("latin-1"),
        })
    return messages


def parse_http1_chunked(wire):
    """Parse one complete HTTP/1 chunked message for differential tests."""
    head, separator, tail = wire.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError("HTTP/1 message has no complete head")
    lines = head.split(b"\r\n")
    fields = []
    transfer_encoding = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise AssertionError("Malformed HTTP/1 field")
        fields.append((name.decode("latin-1"), value.decode("latin-1").strip()))
        if name.lower() == b"transfer-encoding":
            transfer_encoding.extend(
                item.strip().lower() for item in value.split(b",")
            )
    if transfer_encoding != [b"chunked"]:
        raise AssertionError("Expected one chunked transfer coding")

    body = bytearray()
    remaining = tail
    while True:
        size_line, marker, remaining = remaining.partition(b"\r\n")
        if not marker:
            raise AssertionError("HTTP/1 message ends inside a chunk size")
        size_text = size_line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as error:
            raise AssertionError("Invalid HTTP/1 chunk size") from error
        if size == 0:
            break
        if len(remaining) < size + 2 or remaining[size:size + 2] != b"\r\n":
            raise AssertionError("HTTP/1 message ends inside chunk data")
        body.extend(remaining[:size])
        remaining = remaining[size + 2:]

    trailer_block, marker, extra = remaining.partition(b"\r\n\r\n")
    if not marker:
        raise AssertionError("HTTP/1 message has incomplete trailers")
    trailers = []
    if trailer_block:
        for line in trailer_block.split(b"\r\n"):
            name, colon, value = line.partition(b":")
            if not colon:
                raise AssertionError("Malformed HTTP/1 trailer")
            trailers.append([
                name.decode("latin-1").lower(),
                value.decode("latin-1").strip(),
            ])
    return {
        "start": lines[0].decode("latin-1"),
        "headers": fields,
        "body": bytes(body),
        "trailers": trailers,
        "extra": extra,
    }
