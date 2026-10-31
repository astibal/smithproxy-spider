"""Observe response-side flow.kill behavior in mitmproxy 12.3.1.

This is an opt-in loopback black-box probe. It invokes an independently
installed mitmdump executable and a disposable origin server. It never imports
reference implementation source.
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


class Origin:
    def __init__(self, requests):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(5)
        self.port = self.listener.getsockname()[1]
        self.requests = requests
        self.paths = []
        self.errors = []
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.listener.close()
        self.thread.join(5)

    def _serve(self):
        try:
            for _ in range(self.requests):
                connection, _ = self.listener.accept()
                with connection:
                    connection.settimeout(5)
                    received = bytearray()
                    while b"\r\n\r\n" not in received:
                        chunk = connection.recv(4096)
                        if not chunk:
                            raise RuntimeError("Client closed an incomplete origin request")
                        received.extend(chunk)
                    request_line = bytes(received).split(b"\r\n", 1)[0]
                    self.paths.append(request_line.split(b" ", 2)[1].decode("ascii"))
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 13\r\n"
                        b"Connection: close\r\n"
                        b"\r\n"
                        b"origin answer"
                    )
        except Exception as error:
            self.errors.append(repr(error))


def request(proxy_port, origin_port, path):
    wire = (
        f"GET http://127.0.0.1:{origin_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{origin_port}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    received = bytearray()
    outcome = "eof"
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as connection:
        connection.settimeout(3)
        connection.sendall(wire)
        try:
            while True:
                chunk = connection.recv(65535)
                if not chunk:
                    break
                received.extend(chunk)
        except ConnectionResetError:
            outcome = "reset"
        except TimeoutError:
            outcome = "timeout"
    return {"outcome": outcome, "wire": bytes(received).hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    paths = ("/kill-response-headers", "/kill-response")
    origin = Origin(len(paths))
    origin.start()
    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_kill_response_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    clients = {}
    try:
        wait_for_proxy(proxy_port, process)
        for path in paths:
            clients[path] = request(proxy_port, origin.port, path)
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
    if origin.errors:
        raise RuntimeError("Origin failed: " + repr(origin.errors))

    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin_paths": origin.paths,
        "clients": clients,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference response-side flow.kill behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
