"""Reference-only addon for the live DNS lifecycle probe."""

import ipaddress
import json

from mitmproxy import dns


def report(name, flow, before=None):
    question = flow.request.question
    answer = None
    if flow.response and flow.response.answers:
        answer = str(flow.response.answers[0].ipv4_address)

    print("PROBE " + json.dumps({
        "hook": name,
        "flow_type": flow.type,
        "question": None if question is None else question.name,
        "request_query": flow.request.query,
        "response_present": flow.response is not None,
        "response_code": None if flow.response is None else flow.response.response_code,
        "answer_before": before,
        "answer_after": answer,
    }), flush=True)


def dns_request(flow):
    report("dns_request", flow)
    question = flow.request.question
    flow.response = flow.request.succeed([
        dns.ResourceRecord.A(
            question.name,
            ipaddress.IPv4Address("192.0.2.10"),
            ttl=30,
        ),
    ])


def dns_response(flow):
    before = str(flow.response.answers[0].ipv4_address)
    flow.response.answers[0].ipv4_address = ipaddress.IPv4Address("192.0.2.99")
    report("dns_response", flow, before)
