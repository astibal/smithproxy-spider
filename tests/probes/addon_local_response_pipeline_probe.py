"""Observe pipelined HTTP/1 local responses in isolated mitmproxy 12.3.1.

Both requests are sent before either response is read. The reference addon
answers locally, so no origin server is contacted. Reference implementation
source is never imported.
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


def parse_response(wire, offset):
    head_end = wire.find(b"\r\n\r\n", offset)
    if head_end < 0:
        raise RuntimeError("Reference returned an incomplete HTTP response head")

    lines = wire[offset:head_end].split(b"\r\n")
    version, status, reason = lines[0].decode("latin-1").split(" ", 2)
    headers = []
    content_length = None
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise RuntimeError("Reference returned an invalid HTTP header")
        value = value.lstrip()
        headers.append([name.decode("latin-1"), value.decode("latin-1")])
        if name.lower() == b"content-length":
            content_length = int(value)

    if content_length is None:
        raise RuntimeError("Reference local response omitted Content-Length")
    body_start = head_end + 4
    body_end = body_start + content_length
    if body_end > len(wire):
        raise RuntimeError("Reference returned an incomplete HTTP response body")
    return {
        "version": version,
        "status": int(status),
        "reason": reason,
        "headers": headers,
        "body": wire[body_start:body_end].decode("latin-1"),
    }, body_end


def exchange(port):
    requests = (
        b"POST http://example.invalid/pipeline-first HTTP/1.1\r\n"
        b"Host: example.invalid\r\nContent-Length: 1\r\n\r\na"
        b"POST http://example.invalid/pipeline-second HTTP/1.1\r\n"
        b"Host: example.invalid\r\nContent-Length: 1\r\n"
        b"Connection: close\r\n\r\nb"
    )
    received = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(5)
        connection.sendall(requests)
        while True:
            chunk = connection.recv(65535)
            if not chunk:
                break
            received.extend(chunk)

    responses = []
    offset = 0
    wire = bytes(received)
    while offset < len(wire):
        response, offset = parse_response(wire, offset)
        responses.append(response)
    if len(responses) != 2:
        raise RuntimeError(f"Reference returned {len(responses)} responses, expected 2")
    return responses


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

    try:
        wait_for_proxy(port, process)
        responses = exchange(port)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "responses": responses,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference HTTP/1 pipeline behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
