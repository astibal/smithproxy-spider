"""Reference-only addon for forwarded DNS request and response mutation."""

import ipaddress
import json


flow_identity = None


def dns_request(flow):
    global flow_identity
    flow_identity = id(flow)
    before = flow.request.question.name
    flow.request.questions[0].name = "mutated.example.com"
    print("PROBE " + json.dumps({
        "hook": "dns_request",
        "same_flow": True,
        "before": before,
        "after": flow.request.question.name,
        "response_present": flow.response is not None,
    }, sort_keys=True), flush=True)


def dns_response(flow):
    answer = flow.response.answers[0]
    before = [answer.ttl, str(answer.ipv4_address)]
    answer.ttl = 90
    answer.ipv4_address = ipaddress.IPv4Address("192.0.2.99")
    print("PROBE " + json.dumps({
        "hook": "dns_response",
        "same_flow": id(flow) == flow_identity,
        "question": flow.request.question.name,
        "before": before,
        "after": [answer.ttl, str(answer.ipv4_address)],
    }, sort_keys=True), flush=True)
