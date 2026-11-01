"""Measure destructive WebSocket behavior in mitmproxy 12.3.1."""

import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from addon_websocket_control_probe import (
    frame,
    perform_handshake,
    read_frame,
    read_head,
    reserve_port,
    wait_for_proxy,
)


SCENARIOS = (
    "kill-start",
    "kill-client-message",
    "kill-server-message",
    "origin-abort",
    "client-abort",
    "invalid-client-text",
    "invalid-server-text",
)


def observe_frame(connection, buffered):
    try:
        final, opcode, payload = read_frame(connection, buffered)
    except TimeoutError:
        return ["timeout"]
    except (ConnectionError, OSError):
        return ["closed"]
    return [
        "frame",
        final,
        opcode,
        base64.b64encode(payload).decode("ascii"),
    ]


def run_scenario(reference, scenario):
    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    origin.settimeout(3)
    origin_port = origin.getsockname()[1]
    origin_result = {}
    origin_errors = []

    def serve():
        try:
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(2)
                buffered = perform_handshake(connection)
                if scenario == "origin-abort":
                    origin_result["received"] = observe_frame(
                        connection, buffered)
                    return
                if scenario == "client-abort":
                    origin_result["received"] = observe_frame(
                        connection, buffered)
                    origin_result["after"] = observe_frame(
                        connection, buffered)
                    return

                incoming = observe_frame(connection, buffered)
                origin_result["received"] = incoming
                if incoming[0] == "frame":
                    if scenario == "invalid-server-text":
                        connection.sendall(frame(1, b"\xff"))
                        origin_result["close_reply"] = observe_frame(
                            connection, buffered)
                        return
                    payload = base64.b64decode(incoming[3])
                    connection.sendall(frame(incoming[2], b"echo:" + payload))
                    connection.sendall(frame(8, b"\x03\xe8done"))
                    origin_result["close_reply"] = observe_frame(
                        connection, buffered)
        except Exception as error:
            origin_errors.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_websocket_error_addon.py")
    environment = dict(os.environ)
    environment["WEBSOCKET_PROBE_SCENARIO"] = scenario
    process = subprocess.Popen([
        reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
       env=environment)

    client_result = {}
    try:
        wait_for_proxy(proxy_port, process)
        request = (
            f"GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(2)
            client.sendall(request)
            head, buffered = read_head(client)
            client_result["status"] = head.split(b"\r\n", 1)[0].decode("latin-1")
            if scenario == "client-abort":
                client.sendall(frame(1, b"hello", masked=True))
            else:
                payload = b"\xff" if scenario == "invalid-client-text" else b"hello"
                client.sendall(frame(1, payload, masked=True))
                client_result["first"] = observe_frame(client, buffered)
                if client_result["first"][:3] == ["frame", True, 1]:
                    client_result["second"] = observe_frame(client, buffered)
                    if client_result["second"][:3] == ["frame", True, 8]:
                        close_payload = base64.b64decode(client_result["second"][3])
                        client.sendall(frame(8, close_payload, masked=True))
        server.join(3)
        time.sleep(.3)
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
    return {
        "origin": origin_result,
        "origin_errors": origin_errors,
        "client": client_result,
        "hooks": hooks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    result = {
        "reference": "mitmproxy 12.3.1",
        "scenarios": {
            scenario: run_scenario(args.reference, scenario)
            for scenario in SCENARIOS
        },
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference WebSocket error behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
