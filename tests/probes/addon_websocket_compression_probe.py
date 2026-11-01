"""Measure permessage-deflate mutation behavior in mitmproxy 12.3.1."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading
import time
import zlib

from addon_websocket_control_probe import (
    GUID,
    read_head,
    reserve_port,
    wait_for_proxy,
)


EXTENSION = (
    "permessage-deflate; client_no_context_takeover; "
    "server_no_context_takeover"
)
SYNC_TAIL = b"\x00\x00\xff\xff"


def compress_message(content):
    compressor = zlib.compressobj(wbits=-15)
    encoded = compressor.compress(content)
    encoded += compressor.flush(zlib.Z_SYNC_FLUSH)
    if not encoded.endswith(SYNC_TAIL):
        raise RuntimeError("Raw DEFLATE stream has no sync-flush tail")
    return encoded[:-len(SYNC_TAIL)]


def decompress_message(content):
    decompressor = zlib.decompressobj(wbits=-15)
    decoded = decompressor.decompress(content + SYNC_TAIL)
    decoded += decompressor.flush()
    return decoded


def wire_frame(opcode, payload, *, masked=False, final=True, rsv1=False):
    if len(payload) >= 126:
        raise ValueError("Compression probe frames must remain below 126 bytes")
    first = opcode
    if final:
        first |= 0x80
    if rsv1:
        first |= 0x40
    second = len(payload)
    if masked:
        second |= 0x80
    result = bytes((first, second))
    if not masked:
        return result + payload
    mask = b"\x05\x06\x07\x08"
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return result + mask + encoded


def read_wire_frame(connection, buffered):
    while len(buffered) < 2:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed before a complete frame")
        buffered.extend(chunk)
    first, second = buffered[0], buffered[1]
    length = second & 0x7f
    if length >= 126:
        raise RuntimeError("Compression probe received an extended frame")
    masked = bool(second & 0x80)
    needed = 2 + (4 if masked else 0) + length
    while len(buffered) < needed:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed during a frame")
        buffered.extend(chunk)
    cursor = 2
    mask = None
    if masked:
        mask = bytes(buffered[cursor:cursor + 4])
        cursor += 4
    payload = bytes(buffered[cursor:cursor + length])
    del buffered[:needed]
    if mask is not None:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return {
        "final": bool(first & 0x80),
        "rsv1": bool(first & 0x40),
        "opcode": first & 0x0f,
        "payload": payload,
    }


def send_compressed_message(
        connection, content, *, masked, ping, fragmented=False):
    encoded = compress_message(content)
    if fragmented:
        split = max(1, len(encoded) // 2)
        connection.sendall(wire_frame(
            1, encoded[:split], masked=masked, final=False, rsv1=True))
        connection.sendall(wire_frame(9, ping, masked=masked))
        connection.sendall(wire_frame(
            0, encoded[split:], masked=masked, final=True, rsv1=False))
    else:
        connection.sendall(wire_frame(9, ping, masked=masked))
        connection.sendall(wire_frame(
            1, encoded, masked=masked, final=True, rsv1=True))


def read_compressed_message(connection, buffered, *, reply_masked, controls):
    content = bytearray()
    compressed = None
    opcode = None
    frame_count = 0
    while True:
        current = read_wire_frame(connection, buffered)
        current_opcode = current["opcode"]
        if current_opcode == 9:
            controls.append(["ping", current["payload"].decode("latin-1")])
            connection.sendall(wire_frame(
                10, current["payload"], masked=reply_masked))
            continue
        if current_opcode == 10:
            controls.append(["pong", current["payload"].decode("latin-1")])
            continue
        if current_opcode == 8:
            connection.sendall(wire_frame(
                8, current["payload"], masked=reply_masked))
            return {
                "close": True,
                "payload": base64.b64encode(
                    current["payload"]).decode("ascii"),
            }
        if current_opcode in (1, 2):
            if opcode is not None:
                raise RuntimeError("Nested data message")
            opcode = current_opcode
            compressed = current["rsv1"]
        elif current_opcode != 0 or opcode is None:
            diagnostic = base64.b64encode(
                current["payload"]).decode("ascii")
            raise RuntimeError(
                "Unexpected opcode " + str(current_opcode)
                + " with payload " + diagnostic)
        elif current["rsv1"]:
            raise RuntimeError("Continuation frame unexpectedly sets RSV1")
        content.extend(current["payload"])
        frame_count += 1
        if current["final"]:
            break
    raw = bytes(content)
    decoded = decompress_message(raw) if compressed else raw
    return {
        "opcode": opcode,
        "compressed": compressed,
        "frame_count": frame_count,
        "content": base64.b64encode(decoded).decode("ascii"),
    }


def parse_fields(head):
    fields = {}
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            fields[name.lower()] = value.strip()
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    parser.add_argument(
        "--fragmented-side", choices=("client", "server"))
    args = parser.parse_args()

    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    origin.settimeout(5)
    origin_port = origin.getsockname()[1]
    origin_result = {"controls": []}
    origin_errors = []

    def serve():
        try:
            connection, _ = origin.accept()
            with connection:
                connection.settimeout(5)
                head, buffered = read_head(connection)
                fields = parse_fields(head)
                origin_result["request_extension"] = fields.get(
                    b"sec-websocket-extensions", b"").decode("latin-1")
                accept = base64.b64encode(
                    hashlib.sha1(
                        fields[b"sec-websocket-key"] + GUID).digest())
                response = (
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"Sec-WebSocket-Accept: " + accept + b"\r\n"
                    b"Sec-WebSocket-Extensions: " + EXTENSION.encode("ascii")
                    + b"\r\n\r\n"
                )
                connection.sendall(response)
                origin_result["message"] = read_compressed_message(
                    connection, buffered,
                    reply_masked=False,
                    controls=origin_result["controls"],
                )
                if origin_result["message"].get("close"):
                    return
                send_compressed_message(
                    connection,
                    b"server-compressed-payload",
                    masked=False,
                    ping=b"origin-ping",
                    fragmented=args.fragmented_side == "server",
                )
                connection.sendall(wire_frame(8, b"\x03\xe8done"))
                while True:
                    close = read_wire_frame(connection, buffered)
                    if close["opcode"] == 10:
                        origin_result["controls"].append(
                            ["pong", close["payload"].decode("latin-1")])
                        continue
                    origin_result["close_opcode"] = close["opcode"]
                    break
        except Exception as error:
            origin_errors.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_websocket_compression_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_result = {"controls": []}
    try:
        wait_for_proxy(proxy_port, process)
        request = (
            f"GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Extensions: {EXTENSION}\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=2) as client:
            client.settimeout(5)
            client.sendall(request)
            head, buffered = read_head(client)
            fields = parse_fields(head)
            client_result["status"] = head.split(b"\r\n", 1)[0].decode("latin-1")
            client_result["response_extension"] = fields.get(
                b"sec-websocket-extensions", b"").decode("latin-1")
            send_compressed_message(
                client,
                b"client-compressed-payload",
                masked=True,
                ping=b"client-ping",
                fragmented=args.fragmented_side == "client",
            )
            client_result["message"] = read_compressed_message(
                client, buffered,
                reply_masked=True,
                controls=client_result["controls"],
            )
            if not client_result["message"].get("close"):
                while True:
                    close = read_wire_frame(client, buffered)
                    if close["opcode"] == 10:
                        client_result["controls"].append(
                            ["pong", close["payload"].decode("latin-1")])
                        continue
                    client_result["close_opcode"] = close["opcode"]
                    client.sendall(wire_frame(
                        8, close["payload"], masked=True))
                    break
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
    if args.fragmented_side is not None:
        result["fragmented_side"] = args.fragmented_side
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference WebSocket compression changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
