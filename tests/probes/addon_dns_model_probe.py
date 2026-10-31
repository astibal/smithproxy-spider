"""Record the public mitmproxy 12.3.1 DNS object contract.

This opt-in black-box probe imports only documented public objects from an
independently installed reference package. It records observations as a corpus;
the production adapter never imports or depends on that package.
"""

import argparse
import copy
import ipaddress
import json
from pathlib import Path

from mitmproxy import connection
from mitmproxy import dns


def normalized(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, tuple):
        return {"tuple": [normalized(item) for item in value]}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalized(item) for key, item in value.items()}
    return value


def observed(call):
    try:
        return {"value": normalized(call())}
    except Exception as error:
        return {"error": type(error).__name__, "message": str(error)}


def message():
    return dns.DNSMessage(
        id=0x1234,
        query=True,
        op_code=0,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=True,
        recursion_available=False,
        reserved=0,
        response_code=0,
        questions=[dns.Question("example.test", dns.types.A, dns.classes.IN)],
        answers=[],
        authorities=[],
        additionals=[],
        timestamp=123.5,
    )


def pack_invalid_id():
    value = message()
    value.id = 70000
    return value.packed


def consumed_state(value):
    state = value.get_state()
    value.set_state(state)
    return state


def assign_content(value):
    value.content = value.packed


def assign_https_alpn(record, value):
    record.https_alpn = value
    return record.get_state()


def assign_https_ech(record, value):
    record.https_ech = value
    return record.get_state()


def public_constants(module):
    return {
        name: getattr(module, name)
        for name in dir(module)
        if name.isupper() and isinstance(getattr(module, name), int)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    records = [
        dns.ResourceRecord.A("a.test", ipaddress.IPv4Address("192.0.2.1"), ttl=10),
        dns.ResourceRecord.AAAA("aaaa.test", ipaddress.IPv6Address("2001:db8::1"), ttl=20),
        dns.ResourceRecord.CNAME("alias.test", "target.test", ttl=30),
        dns.ResourceRecord.PTR("1.2.0.192.in-addr.arpa", "ptr.test", ttl=40),
        dns.ResourceRecord.TXT("txt.test", "hello", ttl=50),
        dns.ResourceRecord("unknown.test", 65000, dns.classes.IN, 60, b"\x00\xff"),
    ]
    request = message()
    success = request.succeed(records[:2])
    failure = request.fail(dns.response_codes.NXDOMAIN)
    success.timestamp = 200.0
    failure.timestamp = 201.0
    packed = success.packed
    long_txt = dns.ResourceRecord.TXT("long.test", "x" * 256, ttl=5)
    long_txt_wire = request.succeed([long_txt]).packed
    long_txt_roundtrip = dns.DNSMessage.unpack(long_txt_wire).answers[0]
    copied = request.copy()
    https_value = dns.HTTPSRecord(
        1,
        "svc.example",
        {
            dns.SVCParamKeys.ALPN.value: b"\x02h2\x08http/1.1",
            dns.SVCParamKeys.ECH.value: b"echdata",
            dns.SVCParamKeys.PORT.value: b"\x01\xbb",
        },
    )
    https_record = dns.ResourceRecord.HTTPS(
        "example.test", https_value, ttl=12
    )
    https_alpn_mutation = https_record.copy()
    https_ech_mutation = https_record.copy()
    prefixed = b"prefix" + request.packed + b"suffix"
    unpacked_offset, unpacked_message = dns.DNSMessage.unpack_from(
        prefixed, len(b"prefix"), timestamp=456.0
    )

    client = connection.Client(peername=("client", 53000), sockname=("proxy", 53),
                               transport_protocol="udp")
    server = connection.Server(address=("resolver", 53), transport_protocol="udp")
    flow = dns.DNSFlow(client, server, live=True)
    flow.request = request
    flow.response = success
    flow.timestamp_created = 100.0
    flow.id = "dns-flow"
    flow_state = flow.get_state()
    flow_state["client_conn"]["id"] = "client-id"
    flow_state["server_conn"]["id"] = "server-id"
    flow_state["client_conn"]["timestamp_start"] = 10.0
    flow_state["server_conn"]["timestamp_start"] = 11.0

    result = {
        "reference": "mitmproxy 12.3.1",
        "constants": {
            "types": public_constants(dns.types),
            "classes": public_constants(dns.classes),
            "op_codes": public_constants(dns.op_codes),
            "response_codes": public_constants(dns.response_codes),
        },
        "constant_conversions": {
            "type_a": observed(lambda: dns.types.to_str(dns.types.A)),
            "type_unknown": observed(lambda: dns.types.to_str(65000)),
            "type_from_a": observed(lambda: dns.types.from_str("A")),
            "type_from_number": observed(lambda: dns.types.from_str("65000")),
            "class_in": observed(lambda: dns.classes.to_str(dns.classes.IN)),
            "opcode_query": observed(lambda: dns.op_codes.to_str(dns.op_codes.QUERY)),
            "rcode_nxdomain": observed(lambda: dns.response_codes.to_str(dns.response_codes.NXDOMAIN)),
            "rcode_status": observed(lambda: dns.response_codes.http_equiv_status_code(dns.response_codes.NXDOMAIN)),
        },
        "question": {
            "state": normalized(request.questions[0].get_state()),
            "text": str(request.questions[0]),
            "json": normalized(request.questions[0].to_json()),
        },
        "records": [
            {
                "state": normalized(record.get_state()),
                "text": str(record),
                "json": normalized(record.to_json()),
            }
            for record in records
        ],
        "request": {
            "state": normalized(request.get_state()),
            "json": normalized(request.to_json()),
            "text": str(request),
            "size": request.size,
            "question_is_first": request.question is request.questions[0],
            "content_matches_packed": request.content == request.packed,
            "packed": request.packed.hex(),
        },
        "success": {
            "state": normalized(success.get_state()),
            "json": normalized(success.to_json()),
            "packed": packed.hex(),
            "roundtrip_state": normalized(dns.DNSMessage.unpack(packed, timestamp=456.0).get_state()),
        },
        "failure": {
            "state": normalized(failure.get_state()),
            "json": normalized(failure.to_json()),
        },
        "errors": {
            "succeed_none": observed(lambda: request.succeed(None).get_state()),
            "fail_noerror": observed(lambda: request.fail(dns.response_codes.NOERROR)),
            "unpack_trailing": observed(lambda: dns.DNSMessage.unpack(request.packed + b"x")),
            "invalid_id": observed(pack_invalid_id),
        },
        "model_edges": {
            "type_from_unknown_label": observed(lambda: dns.types.from_str("TYPE(65000)")),
            "type_from_lowercase": observed(lambda: dns.types.from_str("a")),
            "question_set_state_remaining": observed(
                lambda: consumed_state(dns.Question("state.test", dns.types.A,
                                                    dns.classes.IN))),
            "record_set_state_remaining": observed(
                lambda: consumed_state(records[0].__class__.from_state(
                    copy.deepcopy(records[0].get_state())))),
            "message_set_state_remaining": observed(
                lambda: consumed_state(dns.DNSMessage.from_state(
                    copy.deepcopy(request.get_state())))),
            "content_assignment": observed(lambda: assign_content(request)),
            "copy_changes_id": copied.id != request.id,
            "copy_preserves_timestamp": copied.timestamp == request.timestamp,
            "rcode_http_statuses": {
                str(value): dns.response_codes.http_equiv_status_code(value)
                for value in range(16)
            },
            "long_txt": {
                "public_data_size": len(long_txt.data),
                "wire_data_suffix": long_txt_wire[-260:].hex(),
                "roundtrip_data_size": len(long_txt_roundtrip.data),
                "roundtrip_matches": long_txt_roundtrip.data == long_txt.data,
            },
            "question_copy": normalized(request.questions[0].copy().get_state()),
            "question_from_json": normalized(
                dns.Question.from_json(request.questions[0].to_json()).get_state()
            ),
            "record_copy": normalized(records[0].copy().get_state()),
            "record_from_json": normalized(
                dns.ResourceRecord.from_json(records[0].to_json()).get_state()
            ),
            "message_from_json": normalized(
                dns.DNSMessage.from_json(request.to_json()).get_state()
            ),
            "unpack_from": {
                "offset": unpacked_offset,
                "state": normalized(unpacked_message.get_state()),
            },
        },
        "https": {
            "value_json": normalized(https_value.to_json()),
            "value_from_json": normalized(
                vars(dns.HTTPSRecord.from_json(https_value.to_json()))
            ),
            "record_state": normalized(https_record.get_state()),
            "record_json": normalized(https_record.to_json()),
            "record_text": str(https_record),
            "record_from_json": normalized(
                dns.ResourceRecord.from_json(https_record.to_json()).get_state()
            ),
            "alpn": normalized(https_record.https_alpn),
            "ech": https_record.https_ech,
            "set_alpn": normalized(assign_https_alpn(
                https_alpn_mutation, (b"h3", b"h2")
            )),
            "set_ech": normalized(assign_https_ech(
                https_ech_mutation, "bmV3LWVjaA=="
            )),
            "constants": {
                name: getattr(dns.SVCParamKeys, name).value
                for name in dns.SVCParamKeys.__members__
            },
        },
        "flow_state": normalized(flow_state),
    }

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference DNS model behavior changed")
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
