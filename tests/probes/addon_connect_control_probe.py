"""Observe HTTP CONNECT control behavior in mitmproxy 12.3.1."""

import argparse
import json
import os
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


class Origin:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.accepted = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        self.listener.settimeout(.2)
        try:
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                self.accepted.set()
                connection.close()
        finally:
            self.listener.close()

    def reset(self):
        self.accepted.clear()

    def close(self):
        self.stop.set()
        self.thread.join(5)


def request_connect(proxy_port, destination_port):
    request = (
        f"CONNECT 127.0.0.1:{destination_port} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{destination_port}\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
            client.sendall(request)
            response = bytearray()
            while b"\r\n\r\n" not in response:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except ConnectionResetError:
        return "connection-reset"

    if not response:
        return "connection-closed"
    return bytes(response).partition(b"\r\n")[0].decode("ascii", "replace")


def run_scenario(reference, addon, origin, action, destination_port):
    proxy_port = reserve_port()
    environment = os.environ.copy()
    environment["CONNECT_ACTION"] = action
    environment["CONNECT_REROUTE_PORT"] = str(origin.port)
    process = subprocess.Popen([
        reference,
        "--mode", f"regular@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)

    origin.reset()
    try:
        wait_for_proxy(proxy_port, process)
        status = request_connect(proxy_port, destination_port)
        time.sleep(.2)
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
    for item in hooks:
        item.pop("flow_id")
        if item["port"] == origin.port:
            item["port"] = "origin"
        elif item["port"] == destination_port:
            item["port"] = "destination"
    return {
        "action": action,
        "hooks": hooks,
        "origin_contacted": origin.accepted.is_set(),
        "status": status,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    origin = Origin()
    origin.start()
    rejected_port = reserve_port()
    addon = Path(__file__).with_name("addon_connect_control_addon.py")
    try:
        scenarios = [
            run_scenario(args.reference, addon, origin, "local-response", origin.port),
            run_scenario(args.reference, addon, origin, "kill", origin.port),
            run_scenario(args.reference, addon, origin, "reroute", rejected_port),
            run_scenario(args.reference, addon, origin, "mutate-connected", origin.port),
            run_scenario(args.reference, addon, origin, "mutate-error", rejected_port),
            run_scenario(args.reference, addon, origin, "kill-connected", origin.port),
            run_scenario(args.reference, addon, origin, "kill-error", rejected_port),
        ]
    finally:
        origin.close()

    result = {
        "reference": "mitmproxy 12.3.1",
        "scenarios": scenarios,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference CONNECT control behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
