"""Measure a complex DNS message lifecycle in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import time

from addon_dns_transport_probe import read_name, reserve_port, wait_for_proxy


def compressed_query():
    first_question = (
        b"\x05alpha\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    second_question = b"\x04beta\xc0\x12" + struct.pack("!HH", 28, 1)
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 10, 4)
        + socket.inet_aton("192.0.2.10")
    )
    authority_data = b"\x02ns\xc0\x12"
    authority = (
        b"\xc0\x12"
        + struct.pack("!HHIH", 2, 1, 20, len(authority_data))
        + authority_data
    )
    additional_name = b"\x02ns\xc0\x12"
    additional = (
        additional_name
        + struct.pack("!HHIH", 1, 1, 30, 4)
        + socket.inet_aton("192.0.2.20")
    )
    return (
        struct.pack("!HHHHHH", 0x6789, 0x27F7, 2, 1, 1, 1)
        + first_question
        + second_question
        + answer
        + authority
        + additional
    )


def parse_wire(packet):
    message_id, flags, question_count, answer_count, authority_count, additional_count = (
        struct.unpack_from("!HHHHHH", packet, 0)
    )
    offset = 12
    questions = []
    for _ in range(question_count):
        name, offset = read_name(packet, offset)
        record_type, record_class = struct.unpack_from("!HH", packet, offset)
        offset += 4
        questions.append([name, record_type, record_class])

    def parse_records(count):
        nonlocal offset
        result = []
        for _ in range(count):
            name, offset = read_name(packet, offset)
            record_type, record_class, ttl, size = struct.unpack_from(
                "!HHIH", packet, offset
            )
            offset += 10
            data = packet[offset:offset + size]
            offset += size
            result.append([
                name,
                record_type,
                record_class,
                ttl,
                data.hex(),
            ])
        return result

    result = {
        "id": message_id,
        "flags": flags,
        "questions": questions,
        "answers": parse_records(answer_count),
        "authorities": parse_records(authority_count),
        "additionals": parse_records(additional_count),
        "fully_consumed": offset == len(packet),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_dns_complex_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--mode", f"dns@{proxy_port}",
        "--listen-host", "127.0.0.1",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    response = None
    try:
        wait_for_proxy(proxy_port, process)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(compressed_query(), ("127.0.0.1", proxy_port))
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
        "input_hex": compressed_query().hex(),
        "hooks": hooks,
        "wire": parse_wire(response),
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference complex DNS behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
