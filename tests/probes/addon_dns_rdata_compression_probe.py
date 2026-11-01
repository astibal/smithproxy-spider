"""Record compressed DNS RDATA normalization in mitmproxy 12.3.1."""

import argparse
import json
from pathlib import Path
import struct

from mitmproxy import dns


POINTER = b"\xc0\x0c"


def character_string(value):
    return bytes((len(value),)) + value


def packet(record_type, data):
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    answer = (
        POINTER
        + struct.pack("!HHIH", record_type, 1, 30, len(data))
        + data
    )
    return struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + question + answer


def observed(record_type, data):
    try:
        record = dns.DNSMessage.unpack(packet(record_type, data)).answers[0]
        return {
            "input": data.hex(),
            "output": record.data.hex(),
        }
    except Exception as error:
        return {
            "input": data.hex(),
            "error": type(error).__name__,
            "message": str(error),
        }


def cases():
    single_name = {
        "NS": 2,
        "MD": 3,
        "MF": 4,
        "CNAME": 5,
        "MB": 7,
        "MG": 8,
        "MR": 9,
        "PTR": 12,
        "DNAME": 39,
    }
    result = {
        name: observed(record_type, POINTER)
        for name, record_type in single_name.items()
    }
    result.update({
        "SOA": observed(
            6,
            POINTER + POINTER + struct.pack("!IIIII", 1, 2, 3, 4, 5),
        ),
        "MINFO": observed(14, POINTER + POINTER),
        "MX": observed(15, struct.pack("!H", 10) + POINTER),
        "RP": observed(17, POINTER + POINTER),
        "AFSDB": observed(18, struct.pack("!H", 10) + POINTER),
        "RT": observed(21, struct.pack("!H", 10) + POINTER),
        "PX": observed(26, struct.pack("!H", 10) + POINTER + POINTER),
        "SRV": observed(33, struct.pack("!HHH", 1, 2, 443) + POINTER),
        "NAPTR": observed(
            35,
            struct.pack("!HH", 1, 2)
            + character_string(b"S")
            + character_string(b"SIP+D2U")
            + character_string(b"")
            + POINTER,
        ),
        "KX": observed(36, struct.pack("!H", 10) + POINTER),
        "RRSIG": observed(
            46,
            struct.pack("!HBBIIIH", 1, 8, 2, 300, 4, 3, 10)
            + POINTER
            + b"signature",
        ),
        "NSEC": observed(47, POINTER + b"\x00\x01\x40"),
        "SVCB": observed(64, struct.pack("!H", 1) + POINTER),
        "HTTPS": observed(65, struct.pack("!H", 1) + POINTER),
        "TKEY": observed(
            249,
            POINTER + struct.pack("!IIHHH", 1, 2, 3, 0, 0) + b"\x00\x00",
        ),
        "TSIG": observed(
            250,
            POINTER
            + b"\x00\x00\x00\x00\x00\x01"
            + struct.pack("!HHHHH", 300, 0, 1, 0, 0),
        ),
    })
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    args = parser.parse_args()

    result = {
        "reference": "mitmproxy 12.3.1",
        "records": cases(),
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference DNS RDATA compression behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
