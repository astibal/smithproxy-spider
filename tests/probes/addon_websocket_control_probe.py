"""Measure WebSocket message boundaries and decisions in mitmproxy 12.3.1."""

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
            raise RuntimeError("Reference proxy exited early\n" + output)
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


def frame(opcode, payload, *, masked=False, final=True):
    if len(payload) >= 126:
        raise ValueError("Probe frames must remain below 126 bytes")
    first = (0x80 if final else 0) | opcode
    second = (0x80 if masked else 0) | len(payload)
    result = bytes((first, second))
    if not masked:
        return result + payload
    mask = b"\x01\x02\x03\x04"
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return result + mask + encoded


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
    return bool(first & 0x80), first & 0x0f, payload


def read_data_message(connection, buffered, *, reply_masked, controls):
    parts = []
    data_opcode = None
    while True:
        final, opcode, payload = read_frame(connection, buffered)
        if opcode == 9:
            controls.append(["ping", payload.decode("latin-1")])
            connection.sendall(frame(10, payload, masked=reply_masked))
            continue
        if opcode == 10:
            controls.append(["pong", payload.decode("latin-1")])
            continue
        if opcode == 8:
            return opcode, payload
        if opcode in (1, 2):
            if data_opcode is not None:
                raise RuntimeError("New data message before continuation completed")
            data_opcode = opcode
            parts.append(payload)
        elif opcode == 0 and data_opcode is not None:
            parts.append(payload)
        else:
            raise RuntimeError("Unexpected WebSocket opcode " + str(opcode))
        if final:
            return data_opcode, b"".join(parts)


def encode_message(opcode, payload):
    return [opcode, base64.b64encode(payload).decode("ascii")]


def perform_handshake(connection):
    head, buffered = read_head(connection)
    fields = {}
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            fields[name.lower()] = value.strip()
    accept = base64.b64encode(
        hashlib.sha1(fields[b"sec-websocket-key"] + GUID).digest())
    connection.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
    )
    return buffered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    origin.settimeout(5)
    origin_port = origin.getsockname()[1]
    origin_result = {"messages": [], "controls": []}
    origin_errors = []

    def serve():
        try:
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(5)
                buffered = perform_handshake(connection)
                # The addon drops one of the five client data messages.
                for _ in range(4):
                    opcode, payload = read_data_message(
                        connection, buffered,
                        reply_masked=False,
                        controls=origin_result["controls"],
                    )
                    origin_result["messages"].append(encode_message(opcode, payload))

                connection.sendall(frame(9, b"server-ping"))
                connection.sendall(frame(1, b"ser", final=False))
                connection.sendall(frame(9, b"between-server"))
                connection.sendall(frame(0, b"ver"))
                connection.sendall(frame(2, b"\x10\xef"))
                connection.sendall(frame(1, b"drop-server"))
                connection.sendall(frame(1, b"after-server"))
                connection.sendall(frame(1, b""))
                connection.sendall(frame(8, b"\x03\xe8done"))

                while True:
                    final, close_opcode, close_payload = read_frame(
                        connection, buffered)
                    if close_opcode == 10:
                        origin_result["controls"].append(
                            ["pong", close_payload.decode("latin-1")])
                        continue
                    if close_opcode != 8:
                        raise RuntimeError(
                            "Expected close, received opcode "
                            + str(close_opcode))
                    origin_result["close"] = [
                        final, close_opcode,
                        base64.b64encode(close_payload).decode("ascii"),
                    ]
                    break
        except Exception as error:
            origin_errors.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_websocket_control_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_result = {"messages": [], "controls": []}
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
            client.settimeout(5)
            client.sendall(request)
            head, buffered = read_head(client)
            client_result["status"] = head.split(b"\r\n", 1)[0].decode("latin-1")

            client.sendall(frame(9, b"client-ping", masked=True))
            client.sendall(frame(1, b"frag", masked=True, final=False))
            client.sendall(frame(9, b"between-client", masked=True))
            client.sendall(frame(0, b"ment", masked=True))
            client.sendall(frame(2, b"\x00\xff", masked=True))
            client.sendall(frame(1, b"drop-client", masked=True))
            client.sendall(frame(1, b"after-client", masked=True))
            client.sendall(frame(1, b"", masked=True))

            for _ in range(4):
                opcode, payload = read_data_message(
                    client, buffered,
                    reply_masked=True,
                    controls=client_result["controls"],
                )
                client_result["messages"].append(encode_message(opcode, payload))
            close_opcode, close_payload = read_data_message(
                client, buffered,
                reply_masked=True,
                controls=client_result["controls"],
            )
            client_result["close"] = encode_message(close_opcode, close_payload)
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
            raise AssertionError("Reference WebSocket control behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
