"""Measure an unreachable DNS resolver in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import time

from addon_dns_transport_probe import (
    encode_name,
    read_name,
    reserve_port,
    wait_for_proxy,
)


def parse_response(packet):
    message_id, flags, questions, answers, authorities, additionals = (
        struct.unpack_from("!HHHHHH", packet, 0)
    )
    name, offset = read_name(packet, 12)
    query_type, query_class = struct.unpack_from("!HH", packet, offset)
    return {
        "id": message_id,
        "query": not bool(flags & 0x8000),
        "response_code": flags & 0x0f,
        "counts": [questions, answers, authorities, additionals],
        "question": [name, query_type, query_class],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_error_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "--set", "dns_use_hosts_file=false",
        "--set", "dns_name_servers=127.0.0.2",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    response = None
    outcome = None
    try:
        wait_for_proxy(proxy_port, process)
        query = (
            struct.pack("!HHHHHH", 0x3456, 0x0100, 1, 0, 0, 0)
            + encode_name("resolver-failure.example.com")
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            # The reference resolver owns an approximately 15-second retry
            # window before synthesizing SERVFAIL. Leave delivery headroom
            # without changing that resolver policy.
            client.settimeout(25)
            client.sendto(query, ("127.0.0.1", proxy_port))
            try:
                response, _ = client.recvfrom(65535)
                outcome = "response"
            except TimeoutError:
                outcome = "timeout"
        time.sleep(.2)
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
        "client_outcome": outcome,
        "wire": None if response is None else parse_response(response),
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference DNS error behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
