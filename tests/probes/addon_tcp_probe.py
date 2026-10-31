"""Observe raw TCP addon lifecycle in an isolated mitmproxy 12.3.1.

This opt-in black-box probe invokes an independently installed mitmdump in
reverse TCP mode and a disposable loopback origin. It never imports reference
implementation source.
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
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before accepting connections\n" + output)
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
    origin_observation = {}
    origin_error = []

    def serve():
        try:
            while True:
                connection, _ = origin.accept()
                with connection:
                    connection.settimeout(5)
                    data = connection.recv(4096)
                    if not data:
                        continue
                    origin_observation["received"] = data.decode("latin-1")
                    connection.sendall(b"echo:" + data)
                    return
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_tcp_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"reverse:tcp://127.0.0.1:{origin_port}",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    received = bytearray()
    client_outcome = "eof"
    try:
        wait_for_proxy(proxy_port, process)
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(5)
            client.sendall(b"hello")
            try:
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
            except TimeoutError:
                client_outcome = "timeout"
        server.join(5)
        time.sleep(.1)
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
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    active_ids = {
        event["flow_id"] for event in hooks
        if event["hook"] == "tcp_message"
    }
    hooks = [event for event in hooks if event["flow_id"] in active_ids]
    for event in hooks:
        del event["flow_id"]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin": origin_observation,
        "client_received": bytes(received).decode("latin-1"),
        "client_outcome": client_outcome,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference raw TCP behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
