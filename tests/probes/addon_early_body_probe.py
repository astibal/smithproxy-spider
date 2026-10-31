"""Observe early HTTP body assignment in an isolated mitmproxy.

This opt-in black-box probe treats mitmproxy as an executable. It does not
import or inspect reference implementation source.
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


def receive_message(connection):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(65535)
        if not chunk:
            raise RuntimeError("Peer closed before the HTTP headers completed")
        data.extend(chunk)
    head, body = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator:
            headers[name.lower()] = value.strip()
    length = int(headers.get(b"content-length", b"0"))
    while len(body) < length:
        chunk = connection.recv(65535)
        if not chunk:
            raise RuntimeError("Peer closed before the HTTP body completed")
        body += chunk
    return lines[0], headers, body[:length]


def serve_origin(port, requests, ready):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen()
        ready.set()
        for _ in range(2):
            connection, _ = listener.accept()
            with connection:
                start, headers, body = receive_message(connection)
                path = start.split(b" ", 2)[1].decode("ascii")
                requests[path] = {
                    "body": body.decode("latin-1"),
                    "content_length": headers.get(b"content-length", b"").decode("ascii"),
                }
                response_body = b"origin response"
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    + b"Content-Length: " + str(len(response_body)).encode("ascii") + b"\r\n"
                    + b"Connection: close\r\n\r\n"
                    + response_body
                )
                connection.sendall(response)


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


def send_request(proxy_port, origin_port, path):
    body = b"original request"
    wire = (
        f"POST http://127.0.0.1:{origin_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{origin_port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as connection:
        connection.settimeout(5)
        connection.sendall(wire)
        _, headers, response_body = receive_message(connection)
    return {
        "body": response_body.decode("latin-1"),
        "content_length": headers.get(b"content-length", b"").decode("ascii"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    proxy_port = reserve_port()
    origin_port = reserve_port()
    origin_requests = {}
    origin_ready = threading.Event()
    origin = threading.Thread(
        target=serve_origin,
        args=(origin_port, origin_requests, origin_ready),
        daemon=True,
    )
    origin.start()
    if not origin_ready.wait(2):
        raise TimeoutError("Origin server did not start")

    addon = Path(__file__).with_name("addon_early_body_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    responses = {}
    paths = ("/replace-request", "/replace-response")
    try:
        wait_for_proxy(proxy_port, process)
        for path in paths:
            responses[path] = send_request(proxy_port, origin_port, path)
        origin.join(timeout=5)
        if origin.is_alive():
            raise TimeoutError("Origin server did not receive every request")
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
        "origin_requests": origin_requests,
        "responses": responses,
        "events": events,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference early-body behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
