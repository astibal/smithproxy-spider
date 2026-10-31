"""Observe live WebSocket addon behavior in mitmproxy 12.3.1.

The opt-in black-box probe uses an independently installed mitmdump and a
minimal disposable RFC 6455 origin. It never imports reference source.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading
import time


GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


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


def read_head(connection):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before WebSocket headers")
        data.extend(chunk)
    head, remainder = bytes(data).split(b"\r\n\r\n", 1)
    return head, bytearray(remainder)


def frame(opcode, payload, *, masked=False):
    if len(payload) >= 126:
        raise ValueError("Probe frames must remain below 126 bytes")
    first = bytes((0x80 | opcode, (0x80 if masked else 0) | len(payload)))
    if not masked:
        return first + payload
    mask = b"\x01\x02\x03\x04"
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first + mask + encoded


def read_frame(connection, buffered):
    while len(buffered) < 2:
        buffered.extend(connection.recv(4096))
    first, second = buffered[0], buffered[1]
    length = second & 0x7f
    masked = bool(second & 0x80)
    if length >= 126:
        raise RuntimeError("Probe received an extended WebSocket frame")
    needed = 2 + (4 if masked else 0) + length
    while len(buffered) < needed:
        buffered.extend(connection.recv(4096))
    cursor = 2
    mask = None
    if masked:
        mask = bytes(buffered[cursor:cursor + 4])
        cursor += 4
    payload = bytes(buffered[cursor:cursor + length])
    del buffered[:needed]
    if mask is not None:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 0x0f, payload


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
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(5)
                head, buffered = read_head(connection)
                lines = head.split(b"\r\n")
                fields = {}
                for line in lines[1:]:
                    name, colon, value = line.partition(b":")
                    if colon:
                        fields[name.lower()] = value.strip()
                accept = base64.b64encode(hashlib.sha1(fields[b"sec-websocket-key"] + GUID).digest())
                connection.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
                )
                opcode, payload = read_frame(connection, buffered)
                origin_observation["opcode"] = opcode
                origin_observation["received"] = payload.decode("latin-1")
                connection.sendall(frame(1, b"reply"))
                connection.sendall(frame(8, b""))
                close_opcode, close_payload = read_frame(connection, buffered)
                origin_observation["close_opcode"] = close_opcode
                origin_observation["close_payload"] = close_payload.decode("latin-1")
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_websocket_transport_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_observation = {}
    try:
        wait_for_proxy(proxy_port, process)
        key = b"dGhlIHNhbXBsZSBub25jZQ=="
        request = (
            f"GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key.decode()}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(5)
            client.sendall(request)
            head, buffered = read_head(client)
            client_observation["status_line"] = head.split(b"\r\n", 1)[0].decode("latin-1")
            client.sendall(frame(1, b"hello", masked=True))
            text_opcode, text_payload = read_frame(client, buffered)
            client_observation["opcode"] = text_opcode
            client_observation["received"] = text_payload.decode("latin-1")
            close_opcode, close_payload = read_frame(client, buffered)
            client_observation["close_opcode"] = close_opcode
            client_observation["close_payload"] = close_payload.decode("latin-1")
            client.sendall(frame(8, close_payload, masked=True))
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
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin": origin_observation,
        "client": client_observation,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference WebSocket behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
