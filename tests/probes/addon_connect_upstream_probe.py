"""Observe upstream-proxy HTTP CONNECT hooks in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading
import time


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before binding HTTP\n" + output)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise TimeoutError("Reference proxy did not bind HTTP within five seconds")


class UpstreamProxy:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.request = None
        self.accepted = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        self.listener.settimeout(5)
        try:
            connection, _ = self.listener.accept()
            with connection:
                request = bytearray()
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    request.extend(chunk)
                self.request = bytes(request)
                connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.accepted.set()
                self.stop.wait(5)
        finally:
            self.listener.close()

    def close(self):
        self.stop.set()
        self.thread.join(5)


def connect(proxy_port, destination_port):
    request = (
        f"CONNECT 127.0.0.1:{destination_port} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{destination_port}\r\n\r\n"
    ).encode()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
        client.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        # CONNECT upstream establishment is lazy until tunneled bytes arrive.
        client.sendall(b"probe")
        time.sleep(.2)
    return bytes(response).partition(b"\r\n")[0].decode("ascii", "replace")


def normalize_hooks(hooks, destination_port, upstream_port):
    result = []
    for item in hooks:
        item.pop("flow_id")
        item["flow"] = "upstream"
        item["port"] = "destination"
        address = item["server_address"]
        if address is not None:
            label = "upstream" if address[1] == upstream_port else "destination"
            item["server_address"] = [address[0], label]
        result.append(item)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    upstream = UpstreamProxy()
    upstream.start()
    destination_port = reserve_port()
    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_connect_transport_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"upstream:http://127.0.0.1:{upstream.port}@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(proxy_port, process)
        status = connect(proxy_port, destination_port)
        if not upstream.accepted.wait(5):
            raise TimeoutError("Reference proxy did not contact upstream proxy")
        time.sleep(.2)
    finally:
        upstream.close()
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
    first_line = None
    if upstream.request:
        first_line = upstream.request.partition(b"\r\n")[0].decode(
            "ascii", "replace")
        first_line = first_line.replace(str(destination_port), "destination")
    result = {
        "reference": "mitmproxy 12.3.1",
        "hooks": normalize_hooks(hooks, destination_port, upstream.port),
        "wire": {
            "client_status": status,
            "upstream_contacted": upstream.accepted.is_set(),
            "upstream_request": first_line,
        },
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference upstream CONNECT behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
