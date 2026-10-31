"""Observe flow.kill lifecycle and HTTP/1 client effects in mitmproxy 12.3.1.

This is an opt-in loopback black-box probe. It invokes an independently
installed mitmdump executable and never imports reference implementation source.
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
    outcome = "eof"
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(2)
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

    port = reserve_port()
    addon = Path(__file__).with_name("addon_kill_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    clients = {}
    try:
        wait_for_proxy(port, process)
        for path in ("/kill-headers", "/kill-request"):
            clients[path] = request(port, path)
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
        "clients": clients,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference flow.kill behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
