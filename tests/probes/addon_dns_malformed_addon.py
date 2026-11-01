"""Reference-only addon for malformed DNS boundary evidence."""

import ipaddress
import json

from mitmproxy import dns


def dns_request(flow):
    question = flow.request.question
    name = None if question is None else question.name
    print("PROBE " + json.dumps({
        "hook": "dns_request",
        "question": name,
        "message_id": flow.request.id,
    }, sort_keys=True), flush=True)

    if question is not None:
        flow.response = flow.request.succeed([
            dns.ResourceRecord.A(
                question.name,
                ipaddress.IPv4Address("192.0.2.77"),
                ttl=30,
            ),
        ])


def dns_response(flow):
    print("PROBE " + json.dumps({
        "hook": "dns_response",
        "question": flow.request.question.name,
        "message_id": flow.response.id,
    }, sort_keys=True), flush=True)
