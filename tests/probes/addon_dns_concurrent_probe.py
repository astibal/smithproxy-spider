"""Measure concurrent same-ID DNS behavior in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import threading
import time

from addon_dns_forward_probe import answer_for, parse_query
from addon_dns_transport_probe import encode_name, parse_response, reserve_port, wait_for_proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 53))
    upstream.settimeout(5)
    upstream_result = {"queries": []}
    upstream_errors = []
    first_lookup_ready = threading.Event()

    def serve():
        pending = []
        try:
            for _ in range(4):
                query, peer = upstream.recvfrom(65535)
                parsed = parse_query(query)
                pending.append((query, peer, parsed))
                upstream_result["queries"].append({
                    "question": parsed["question"],
                })
                if len(pending) == 2:
                    first_lookup_ready.set()

            # Return the complete second lookup before the first. The reference
            # must associate them by its own exchange state, not by the shared
            # client-visible DNS ID.
            for wanted in ("second.example.com", "first.example.com"):
                matching = [
                    item for item in pending
                    if item[2]["question"][0] == wanted
                ]
                if len(matching) != 2:
                    raise RuntimeError(
                        "Expected A and AAAA queries for " + wanted
                    )
                for query, peer, _ in matching:
                    upstream.sendto(answer_for(query), peer)
        except Exception as error:
            upstream_errors.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_concurrent_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "--set", "dns_use_hosts_file=false",
        "--set", "dns_name_servers=127.0.0.1",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    clients = []
    received = []
    try:
        wait_for_proxy(proxy_port, process)
        for name in ("first.example.com", "second.example.com"):
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            client.setblocking(False)
            clients.append(client)

        for index, name in enumerate(("first.example.com", "second.example.com")):
            query = (
                struct.pack("!HHHHHH", 0xCAFE, 0x0100, 1, 0, 0, 0)
                + encode_name(name)
                + struct.pack("!HH", 1, 1)
            )
            clients[index].sendto(query, ("127.0.0.1", proxy_port))
            if index == 0 and not first_lookup_ready.wait(5):
                raise TimeoutError("First DNS lookup did not reach the resolver")

        deadline = time.monotonic() + 5
        pending_clients = set(clients)
        while pending_clients:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for concurrent DNS responses")
            readable, _, _ = select.select(list(pending_clients), [], [], remaining)
            if not readable:
                continue
            for client in readable:
                packet, _ = client.recvfrom(65535)
                received.append(parse_response(packet))
                pending_clients.remove(client)

        server.join(5)
        time.sleep(.1)
    finally:
        for client in clients:
            client.close()
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
    hooks.sort(key=lambda hook: (
        hook["hook"] != "dns_request",
        hook["question"],
    ))
    result = {
        "reference": "mitmproxy 12.3.1",
        "upstream": upstream_result,
        "responses": sorted(received, key=lambda response: response["question"][0]),
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference concurrent DNS behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
