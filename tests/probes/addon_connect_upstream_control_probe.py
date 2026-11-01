"""Observe upstream CONNECT control behavior in mitmproxy 12.3.1."""

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


class UpstreamProxy:
    def __init__(self, status):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.status = status
        self.connected = False
        self.request = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def _serve(self):
        self.listener.settimeout(5)
        try:
            connection, _ = self.listener.accept()
            self.connected = True
            with connection:
                connection.settimeout(1)
                request = bytearray()
                try:
                    while b"\r\n\r\n" not in request:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)
                except socket.timeout:
                    pass
                self.request = bytes(request)
                if request:
                    reason = "Connection established" if self.status == 200 else "Bad Gateway"
                    response = f"HTTP/1.1 {self.status} {reason}\r\n\r\n".encode()
                    connection.sendall(response)
        finally:
            self.listener.close()

    def close(self):
        self.thread.join(5)


def client_connect(proxy_port, destination_port):
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
        status = bytes(response).partition(b"\r\n")[0].decode("ascii", "replace")

        try:
            client.sendall(b"probe")
            client.settimeout(1)
            tunnel_result = "data" if client.recv(4096) else "closed"
        except (BrokenPipeError, ConnectionResetError):
            tunnel_result = "reset"
        except socket.timeout:
            tunnel_result = "open"
    return status, tunnel_result


def run_scenario(reference, addon, action, upstream_status):
    upstream = UpstreamProxy(upstream_status)
    upstream.start()
    destination_port = reserve_port()
    proxy_port = reserve_port()
    environment = os.environ.copy()
    environment["CONNECT_ACTION"] = action
    process = subprocess.Popen([
        reference,
        "--mode", f"upstream:http://127.0.0.1:{upstream.port}@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)

    try:
        wait_for_proxy(proxy_port, process)
        status, tunnel_result = client_connect(proxy_port, destination_port)
        time.sleep(.2)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
        upstream.close()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    exceptions = [
        json.loads(line.removeprefix("PROBE_EXCEPTION "))
        for line in output.splitlines()
        if line.startswith("PROBE_EXCEPTION ")
    ]
    for item in hooks:
        item.pop("flow_id")
        if item["port"] == destination_port:
            item["port"] = "destination"
    upstream_line = None
    if upstream.request:
        upstream_line = upstream.request.partition(b"\r\n")[0].decode(
            "ascii", "replace")
        upstream_line = upstream_line.replace(str(destination_port), "destination")
    return {
        "action": action,
        "upstream_status": upstream_status,
        "client_status": status,
        "tunnel_result": tunnel_result,
        "upstream_connected": upstream.connected,
        "upstream_request": upstream_line,
        "hooks": hooks,
        "exceptions": exceptions,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    addon = Path(__file__).with_name("addon_connect_upstream_control_addon.py")
    scenarios = [
        run_scenario(args.reference, addon, "pass", 502),
        run_scenario(args.reference, addon, "reroute", 200),
        run_scenario(args.reference, addon, "kill", 200),
        run_scenario(args.reference, addon, "local-response", 200),
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "scenarios": scenarios,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference upstream control behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
