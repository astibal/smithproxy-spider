"""Observe HTTP/1 streaming lifecycle in an isolated mitmproxy 12.3.1.

This opt-in loopback probe starts an independently installed mitmdump and a
minimal disposable origin. It never imports reference implementation source.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading
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


def read_head(connection):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before complete HTTP headers")
        data.extend(chunk)
    head, body = bytes(data).split(b"\r\n\r\n", 1)
    return head, bytearray(body)


def content_length(head):
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if colon and name.lower() == b"content-length":
            return int(value.strip())
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    origin.settimeout(5)
    origin_port = origin.getsockname()[1]
    observed = {}
    origin_error = []

    def serve():
        try:
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(5)
                head, body = read_head(connection)
                length = content_length(head)
                while len(body) < length:
                    body.extend(connection.recv(length - len(body)))
                observed["request_line"] = head.split(b"\r\n", 1)[0].decode("latin-1")
                observed["request_body"] = bytes(body[:length]).decode("latin-1")
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 13\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    b"origin result"
                )
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_streaming_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(proxy_port, process)
        wire = (
            f"POST http://127.0.0.1:{origin_port}/stream HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Content-Length: 12\r\n"
            "Connection: close\r\n"
            "\r\n"
            "request body"
        ).encode("ascii")
        received = bytearray()
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(5)
            client.sendall(wire)
            while True:
                chunk = client.recv(65535)
                if not chunk:
                    break
                received.extend(chunk)
        server.join(5)
    finally:
        origin.close()
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    if origin_error:
        raise RuntimeError("Origin failed: " + repr(origin_error))
    response_head, response_body = bytes(received).split(b"\r\n\r\n", 1)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin": observed,
        "client": {
            "status_line": response_head.split(b"\r\n", 1)[0].decode("latin-1"),
            "body": response_body.decode("latin-1"),
        },
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference HTTP streaming behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
