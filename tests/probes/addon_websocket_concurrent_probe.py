"""Measure shared addon state across two live WebSocket connections."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading
import time

from addon_websocket_control_probe import (
    GUID,
    frame,
    read_frame,
    read_head,
    reserve_port,
    wait_for_proxy,
)


def serve_connection(connection, label, result, errors):
    try:
        with connection:
            connection.settimeout(4)
            head, buffered = read_head(connection)
            fields = {}
            for line in head.split(b"\r\n")[1:]:
                name, colon, value = line.partition(b":")
                if colon:
                    fields[name.lower()] = value.strip()
            accept = base64.b64encode(
                hashlib.sha1(
                    fields[b"sec-websocket-key"] + GUID).digest())
            connection.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            result[label] = []
            for _ in range(2):
                _, opcode, payload = read_frame(connection, buffered)
                result[label].append(base64.b64encode(payload).decode("ascii"))
                connection.sendall(frame(opcode, b"origin:" + payload))
            connection.sendall(frame(8, b"\x03\xe8" + label.encode("ascii")))
            _, _, close_payload = read_frame(connection, buffered)
            result[label + "_close"] = base64.b64encode(
                close_payload).decode("ascii")
    except Exception as error:
        errors.append(label + ":" + repr(error))


def open_client(proxy_port, origin_port, key):
    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
    client.settimeout(4)
    request = (
        f"GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{origin_port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode("ascii")
    client.sendall(request)
    head, buffered = read_head(client)
    status = head.split(b"\r\n", 1)[0].decode("latin-1")
    return client, buffered, status


def exchange(client, buffered, content):
    client.sendall(frame(1, content, masked=True))
    _, opcode, payload = read_frame(client, buffered)
    if opcode != 1:
        raise RuntimeError("Expected a text response")
    return base64.b64encode(payload).decode("ascii")


def close_client(client, buffered):
    _, opcode, payload = read_frame(client, buffered)
    if opcode != 8:
        raise RuntimeError("Expected a close frame")
    client.sendall(frame(8, payload, masked=True))
    return base64.b64encode(payload).decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(2)
    origin.settimeout(4)
    origin_port = origin.getsockname()[1]
    origin_result = {}
    origin_errors = []
    origin_threads = []

    def accept_origins():
        try:
            for label in ("one", "two"):
                connection, _ = origin.accept()
                worker = threading.Thread(
                    target=serve_connection,
                    args=(connection, label, origin_result, origin_errors),
                    daemon=True,
                )
                worker.start()
                origin_threads.append(worker)
        except Exception as error:
            origin_errors.append("accept:" + repr(error))

    accept_thread = threading.Thread(target=accept_origins, daemon=True)
    accept_thread.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_websocket_concurrent_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    clients = []
    client_result = {"responses": []}
    try:
        wait_for_proxy(proxy_port, process)
        first = open_client(
            proxy_port, origin_port, "dGhlIHNhbXBsZSBub25jZTE=")
        second = open_client(
            proxy_port, origin_port, "dGhlIHNhbXBsZSBub25jZTI=")
        clients.extend((first[0], second[0]))
        client_result["statuses"] = [first[2], second[2]]

        operations = (
            (first, b"one-a"),
            (second, b"two-a"),
            (first, b"one-b"),
            (second, b"two-b"),
        )
        for (client, buffered, _), content in operations:
            client_result["responses"].append(
                exchange(client, buffered, content))

        client_result["closes"] = [
            close_client(first[0], first[1]),
            close_client(second[0], second[1]),
        ]
        for client in clients:
            client.close()
        clients.clear()
        for worker in origin_threads:
            worker.join(4)
        accept_thread.join(4)
        time.sleep(.2)
    finally:
        for client in clients:
            client.close()
        origin.close()
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    if origin_errors:
        raise RuntimeError("Origin failed: " + repr(origin_errors))
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin": origin_result,
        "client": client_result,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference WebSocket concurrency changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
