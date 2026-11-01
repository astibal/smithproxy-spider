"""Measure DNS-over-TCP framing behavior in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import time

from addon_dns_transport_probe import encode_name, parse_response, wait_for_proxy


def reserve_dual_protocol_port():
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port


def make_query(message_id, name):
    return (
        struct.pack("!HHHHHH", message_id, 0x0100, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", 1, 1)
    )


def receive_exact(connection, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise EOFError("DNS TCP connection closed inside a message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_message(connection):
    size = struct.unpack("!H", receive_exact(connection, 2))[0]
    return receive_exact(connection, size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    proxy_port = reserve_dual_protocol_port()
    addon = Path(__file__).with_name("addon_dns_tcp_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    responses = []
    try:
        wait_for_proxy(proxy_port, process)
        first = make_query(0x4567, "first.invalid")
        second = make_query(0x89AB, "second.invalid")

        with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as client:
            client.settimeout(5)

            # Exercise framing rather than relying on convenient socket writes:
            # split the first length prefix and payload, then pipeline a complete
            # second message before reading either response.
            first_frame = struct.pack("!H", len(first)) + first
            client.sendall(first_frame[:1])
            client.sendall(first_frame[1:7])
            client.sendall(first_frame[7:])
            client.sendall(struct.pack("!H", len(second)) + second)

            responses.append(parse_response(receive_message(client)))
            responses.append(parse_response(receive_message(client)))
        time.sleep(.1)
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
        "responses": responses,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference DNS-over-TCP behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
