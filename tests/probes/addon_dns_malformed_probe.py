"""Measure malformed DNS datagram boundaries in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import time

from addon_dns_transport_probe import encode_name, parse_response, reserve_port, wait_for_proxy


def valid_query(message_id, name):
    return (
        struct.pack("!HHHHHH", message_id, 0x0100, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", 1, 1)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    pointer_loop = (
        struct.pack("!HHHHHH", 0x1004, 0x0100, 1, 0, 0, 0)
        + b"\xc0\x0c"
        + struct.pack("!HH", 1, 1)
    )
    baseline = valid_query(0x1005, "baseline.invalid")
    cases = [
        ("empty", b""),
        ("one-byte", b"\x10"),
        ("short-header", b"\x10\x02" + b"\0" * 9),
        ("missing-question", struct.pack("!HHHHHH", 0x1003, 0x0100, 1, 0, 0, 0)),
        ("compression-pointer-loop", pointer_loop),
        ("trailing-bytes", valid_query(0x1006, "trailing.invalid") + b"\xde\xad"),
        ("baseline", baseline),
    ]

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_malformed_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    outcomes = []
    try:
        wait_for_proxy(proxy_port, process)
        for name, packet in cases:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(.25)
                client.sendto(packet, ("127.0.0.1", proxy_port))
                try:
                    response, _ = client.recvfrom(65535)
                except socket.timeout:
                    outcomes.append({"case": name, "outcome": "timeout"})
                else:
                    outcomes.append({
                        "case": name,
                        "outcome": "response",
                        "response": parse_response(response),
                    })
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
        "outcomes": outcomes,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference malformed DNS behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
