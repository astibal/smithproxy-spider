"""Measure local DNS error responses in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import time

from addon_dns_error_probe import parse_response
from addon_dns_transport_probe import encode_name, reserve_port, wait_for_proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 53))
    upstream.setblocking(False)

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_local_error_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "--set", "dns_use_hosts_file=false",
        "--set", "dns_name_servers=127.0.0.1",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    response = None
    upstream_contact = False
    try:
        wait_for_proxy(proxy_port, process)
        query = (
            struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
            + encode_name("local-error.example.com")
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(query, ("127.0.0.1", proxy_port))
            response, _ = client.recvfrom(65535)

        readable, _, _ = select.select([upstream], [], [], .25)
        upstream_contact = bool(readable)
        time.sleep(.1)
    finally:
        upstream.close()
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
        "upstream_contact": upstream_contact,
        "wire": parse_response(response),
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference local DNS error behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
