"""Measure DNS flow.kill behavior in mitmproxy 12.3.1."""

import argparse
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
import time

from addon_dns_forward_probe import answer_for, parse_query
from addon_dns_error_probe import parse_response as parse_error_response
from addon_dns_transport_probe import (
    encode_name,
    parse_response as parse_success_response,
    reserve_port,
    wait_for_proxy,
)


def parse_wire(packet):
    result = parse_error_response(packet)
    if result["counts"][1]:
        result["answer"] = parse_success_response(packet)["answer"]
    return result


def run_case(reference, case):
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 53))
    upstream.settimeout(5)
    upstream_questions = []
    upstream_errors = []

    def serve():
        try:
            for _ in range(2):
                query, peer = upstream.recvfrom(65535)
                upstream_questions.append(parse_query(query)["question"])
                upstream.sendto(answer_for(query), peer)
        except Exception as error:
            upstream_errors.append(repr(error))

    server = None
    if case == "upstream-response-kill":
        server = threading.Thread(target=serve, daemon=True)
        server.start()
    else:
        upstream.setblocking(False)

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_control_addon.py")
    environment = dict(os.environ)
    environment["DNS_CONTROL_CASE"] = case
    process = subprocess.Popen([
        reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "--set", "dns_use_hosts_file=false",
        "--set", "dns_name_servers=127.0.0.1",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
       env=environment)

    response = None
    try:
        wait_for_proxy(proxy_port, process)
        query = (
            struct.pack("!HHHHHH", 0x789A, 0x0100, 1, 0, 0, 0)
            + encode_name("control.example.com")
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(query, ("127.0.0.1", proxy_port))
            try:
                response, _ = client.recvfrom(65535)
            except socket.timeout:
                pass

        if server is not None:
            server.join(5)
        else:
            readable, _, _ = select.select([upstream], [], [], .25)
            if readable:
                packet, _ = upstream.recvfrom(65535)
                upstream_questions.append(parse_query(packet)["question"])
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
    if upstream_errors:
        raise RuntimeError(
            "Upstream failed: " + repr(upstream_errors) + "\n" + output
        )
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    return {
        "case": case,
        "client_outcome": "timeout" if response is None else "response",
        "wire": None if response is None else parse_wire(response),
        "upstream_questions": upstream_questions,
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
        "cases": [
            run_case(args.reference, "request-kill"),
            run_case(args.reference, "request-local-kill"),
            run_case(args.reference, "local-response-kill"),
            run_case(args.reference, "upstream-response-kill"),
        ],
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference DNS control behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
