"""Observe live DNS addon behavior in mitmproxy 12.3.1.

The opt-in black-box probe invokes an independently installed mitmdump in DNS
server mode. A reference-only addon creates and then mutates a local response,
so the probe never contacts an external resolver or network service.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import time


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def udp_listener_present(port):
    wanted = f"{port:04X}"
    for table in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            lines = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 1 and fields[1].partition(":")[2].upper() == wanted:
                return True
    return False


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before binding DNS\n" + output)
        if udp_listener_present(port):
            return
        time.sleep(.05)
    raise TimeoutError("Reference proxy did not bind DNS within five seconds")


def encode_name(name):
    labels = name.rstrip(".").split(".")
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\0"


def read_name(packet, offset):
    labels = []
    consumed = None
    while True:
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            pointer = ((length & 0x3f) << 8) | packet[offset + 1]
            if consumed is None:
                consumed = offset + 2
            offset = pointer
            continue
        offset += 1
        if length == 0:
            break
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels), consumed if consumed is not None else offset


def parse_response(packet):
    message_id, flags, questions, answers, authorities, additionals = struct.unpack_from(
        "!HHHHHH", packet, 0
    )
    offset = 12
    question_name, offset = read_name(packet, offset)
    question_type, question_class = struct.unpack_from("!HH", packet, offset)
    offset += 4
    answer_name, offset = read_name(packet, offset)
    answer_type, answer_class, ttl, size = struct.unpack_from("!HHIH", packet, offset)
    offset += 10
    address = str(ipaddress.IPv4Address(packet[offset:offset + size]))
    return {
        "id": message_id,
        "query": not bool(flags & 0x8000),
        "response_code": flags & 0x0f,
        "recursion_available": bool(flags & 0x0080),
        "counts": [questions, answers, authorities, additionals],
        "question": [question_name, question_type, question_class],
        "answer": [answer_name, answer_type, answer_class, ttl, address],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_transport_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(proxy_port, process)
        query = (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + encode_name("probe.invalid")
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(query, ("127.0.0.1", proxy_port))
            response, _ = client.recvfrom(65535)
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
        "wire": parse_response(response),
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference DNS behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
