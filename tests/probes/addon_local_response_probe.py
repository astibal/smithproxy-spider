"""Observe local-response lifecycle behavior in an isolated mitmproxy.

This opt-in black-box probe never imports reference implementation source. It
starts an independently installed mitmdump executable, uses only loopback
sockets, and records JSON observations suitable for a checked-in test corpus.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import time


def reserve_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Reference proxy exited before accepting connections")
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not start within five seconds")


def parse_chunked_body(wire, *, require_complete):
    body = bytearray()
    cursor = 0
    while True:
        line_end = wire.find(b"\r\n", cursor)
        if line_end < 0:
            if require_complete:
                raise RuntimeError("Reference returned an incomplete chunk size")
            return None
        size_text = wire[cursor:line_end].partition(b";")[0]
        try:
            size = int(size_text, 16)
        except ValueError as error:
            raise RuntimeError("Reference returned an invalid chunk size") from error
        cursor = line_end + 2
        if size:
            end = cursor + size
            if end + 2 > len(wire):
                if require_complete:
                    raise RuntimeError("Reference returned an incomplete chunk")
                return None
            if wire[end:end + 2] != b"\r\n":
                raise RuntimeError("Reference returned an invalid chunk terminator")
            body.extend(wire[cursor:end])
            cursor = end + 2
            continue

        if wire[cursor:cursor + 2] == b"\r\n":
            return bytes(body), [], cursor + 2
        trailer_end = wire.find(b"\r\n\r\n", cursor)
        if trailer_end < 0:
            if require_complete:
                raise RuntimeError("Reference returned incomplete HTTP trailers")
            return None
        trailers = []
        for line in wire[cursor:trailer_end].split(b"\r\n"):
            name, colon, value = line.partition(b":")
            if not colon:
                raise RuntimeError("Reference returned an invalid HTTP trailer")
            trailers.append([
                name.decode("latin-1"),
                value.lstrip().decode("latin-1"),
            ])
        return bytes(body), trailers, trailer_end + 4


def response_complete(wire):
    head, separator, body = wire.partition(b"\r\n\r\n")
    if not separator:
        return False
    content_length = None
    chunked = False
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise RuntimeError("Reference returned an invalid HTTP header")
        if name.lower() == b"content-length":
            content_length = int(value.strip())
        elif name.lower() == b"transfer-encoding":
            chunked = value.strip().lower() == b"chunked"
    if chunked:
        return parse_chunked_body(body, require_complete=False) is not None
    if content_length is not None:
        return len(body) >= content_length
    return False


def request(port, path):
    wire = (
        f"POST http://example.invalid{path} HTTP/1.1\r\n"
        "Host: example.invalid\r\n"
        "Content-Length: 4\r\n"
        "Connection: close\r\n"
        "\r\n"
        "test"
    ).encode("ascii")
    received = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(5)
        connection.sendall(wire)
        while True:
            try:
                chunk = connection.recv(65535)
            except TimeoutError as error:
                raise RuntimeError(
                    "Reference did not complete its HTTP response: "
                    + repr(bytes(received))
                ) from error
            if not chunk:
                break
            received.extend(chunk)
            if response_complete(bytes(received)):
                break

    head, separator, body = bytes(received).partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError("Reference returned an incomplete HTTP response")
    lines = head.split(b"\r\n")
    version, status, reason = lines[0].decode("latin-1").split(" ", 2)
    headers = []
    content_length = None
    chunked = False
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise RuntimeError("Reference returned an invalid HTTP header")
        value = value.lstrip()
        headers.append([name.decode("latin-1"), value.decode("latin-1")])
        if name.lower() == b"content-length":
            content_length = int(value)
        elif name.lower() == b"transfer-encoding":
            chunked = value.lower() == b"chunked"

    trailers = None
    if chunked:
        body, trailers, consumed = parse_chunked_body(body, require_complete=True)
        if consumed != len(bytes(received).partition(b"\r\n\r\n")[2]):
            raise RuntimeError("Reference returned bytes after the chunked response")
    elif content_length is not None:
        if len(body) != content_length:
            raise RuntimeError("Reference returned an invalid Content-Length body")
    result = {
        "version": version,
        "status": int(status),
        "reason": reason,
        "headers": headers,
        "body": body.decode("latin-1"),
    }
    if trailers is not None:
        result["trailers"] = trailers
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    port = reserve_port()
    addon = Path(__file__).with_name("addon_local_response_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    responses = {}
    try:
        wait_for_proxy(port, process)
        for path in (
            "/headers",
            "/request",
            "/empty",
            "/trailers",
        ):
            responses[path] = request(port, path)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    events = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "responses": responses,
        "events": events,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference local-response behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
