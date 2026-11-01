"""Observe intercept/resume lifecycle in an isolated mitmproxy 12.3.1.

This opt-in black-box probe invokes an independently installed mitmdump and a
disposable loopback origin. It never imports reference implementation source.
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
    origin_result = {"request_seen": False}
    origin_time = []
    origin_error = []

    def serve():
        try:
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(5)
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        raise RuntimeError("Origin received an incomplete request")
                    request.extend(chunk)
                origin_result["request_seen"] = True
                origin_time.append(time.monotonic())
                origin_result["request_line"] = bytes(request).split(b"\r\n", 1)[0].decode("latin-1")
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 7\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    b"resumed"
                )
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_intercept_addon.py")
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
            f"GET http://127.0.0.1:{origin_port}/intercept HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Connection: close\r\n"
            "\r\n"
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
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    resumed_at = next(
        hook["monotonic_time"]
        for hook in hooks
        if hook["hook"] == "after-resume"
    )
    origin_result["request_after_resume"] = bool(
        origin_time and origin_time[0] >= resumed_at
    )
    for hook in hooks:
        del hook["monotonic_time"]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin": origin_result,
        "client": {
            "status_line": head.split(b"\r\n", 1)[0].decode("latin-1"),
            "body": body.decode("latin-1"),
        },
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference intercept/resume behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
