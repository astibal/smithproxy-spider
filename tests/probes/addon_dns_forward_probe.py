"""Measure forwarded UDP DNS mutation behavior in mitmproxy 12.3.1."""

import argparse
import ipaddress
import json
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

from addon_dns_transport_probe import (
    encode_name,
    parse_response,
    read_name,
    reserve_port,
    wait_for_proxy,
)


def parse_query(packet):
    message_id, flags, questions, answers, authorities, additionals = (
        struct.unpack_from("!HHHHHH", packet, 0)
    )
    name, offset = read_name(packet, 12)
    query_type, query_class = struct.unpack_from("!HH", packet, offset)
    return {
        "id": message_id,
        "flags": flags,
        "counts": [questions, answers, authorities, additionals],
        "question": [name, query_type, query_class],
        "question_end": offset + 4,
    }


def answer_for(query):
    parsed = parse_query(query)
    question = query[12:parsed["question_end"]]
    query_type = parsed["question"][1]
    if query_type == 1:
        address = ipaddress.IPv4Address("192.0.2.10").packed
    elif query_type == 28:
        address = ipaddress.IPv6Address("2001:db8::10").packed
    else:
        raise ValueError("Unexpected resolver query type " + str(query_type))
    return (
        struct.pack("!HHHHHH", parsed["id"], 0x8180, 1, 1, 0, 0)
        + question
        + b"\xc0\x0c"
        + struct.pack("!HHIH", query_type, 1, 30, len(address))
        + address
    )


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
    upstream_ids = []
    upstream_errors = []

    def serve():
        try:
            for _ in range(2):
                query, peer = upstream.recvfrom(65535)
                parsed = parse_query(query)
                upstream_ids.append(parsed["id"])
                upstream_result["queries"].append({
                    "flags": parsed["flags"],
                    "counts": parsed["counts"],
                    "question": parsed["question"],
                })
                upstream.sendto(answer_for(query), peer)
            upstream_result["query_ids_distinct"] = (
                len(set(upstream_ids)) == len(upstream_ids))
            upstream_result["query_ids_differ_from_client"] = all(
                message_id != 0x2345 for message_id in upstream_ids)
        except Exception as error:
            upstream_errors.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_forward_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "--set", "dns_use_hosts_file=false",
        "--set", "dns_name_servers=127.0.0.1",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_error = None
    response = None
    try:
        wait_for_proxy(proxy_port, process)
        query = (
            struct.pack("!HHHHHH", 0x2345, 0x0100, 1, 0, 0, 0)
            + encode_name("probe.example.com")
            + struct.pack("!HH", 1, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(query, ("127.0.0.1", proxy_port))
            try:
                response, _ = client.recvfrom(65535)
            except Exception as error:
                client_error = repr(error)
        server.join(5)
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
    if client_error is not None:
        raise RuntimeError(
            "Client failed: " + client_error
            + "\nupstream=" + repr(upstream_result)
            + "\nupstream_errors=" + repr(upstream_errors)
            + "\n" + output)
    if upstream_errors:
        raise RuntimeError(
            "Upstream failed: " + repr(upstream_errors) + "\n" + output)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "upstream": upstream_result,
        "client": parse_response(response),
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference forwarded DNS behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
