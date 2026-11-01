"""Observe live HTTP CONNECT behavior in mitmproxy 12.3.1."""

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


class OneConnectionOrigin:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.accepted = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        self.listener.settimeout(5)
        try:
            connection, _ = self.listener.accept()
            self.accepted.set()
            with connection:
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
    status_line = bytes(response).partition(b"\r\n")[0].decode(
        "ascii", "replace")
    return status_line


def normalize_hooks(hooks, accepted_port, rejected_port):
    flow_names = {}
    result = []
    for item in hooks:
        flow_id = item.pop("flow_id")
        if flow_id not in flow_names:
            flow_names[flow_id] = "accepted" if item["port"] == accepted_port else "rejected"
        item["flow"] = flow_names[flow_id]
        item["port"] = "accepted" if item["port"] == accepted_port else "rejected"
        address = item["server_address"]
        if address is not None:
            item["server_address"] = [
                address[0],
                "accepted" if address[1] == accepted_port else "rejected",
            ]
        result.append(item)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    origin = OneConnectionOrigin()
    origin.start()
    rejected_port = reserve_port()
    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_connect_transport_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"regular@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(proxy_port, process)
        accepted_status = connect(proxy_port, origin.port)
        if not origin.accepted.wait(5):
            raise TimeoutError("Reference proxy did not contact CONNECT origin")
        rejected_status = connect(proxy_port, rejected_port)
        time.sleep(.2)
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
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "hooks": normalize_hooks(hooks, origin.port, rejected_port),
        "wire": {
            "accepted_status": accepted_status,
            "rejected_status": rejected_status,
            "origin_contacted": origin.accepted.is_set(),
        },
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference HTTP CONNECT behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
