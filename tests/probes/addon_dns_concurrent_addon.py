"""Reference-only addon for concurrent DNS flow identity evidence."""

import ipaddress
import json


flow_numbers = {}
request_order = 0


def flow_number(flow):
    identity = id(flow)
    if identity not in flow_numbers:
        flow_numbers[identity] = len(flow_numbers) + 1
    return flow_numbers[identity]


def dns_request(flow):
    global request_order

    request_order += 1
    print("PROBE " + json.dumps({
        "hook": "dns_request",
        "flow": flow_number(flow),
        "order": request_order,
        "question": flow.request.question.name,
        "message_id": flow.request.id,
    }, sort_keys=True), flush=True)


def dns_response(flow):
    question = flow.request.question.name
    if question == "first.example.com":
        replacement = ipaddress.IPv4Address("192.0.2.101")
    elif question == "second.example.com":
        replacement = ipaddress.IPv4Address("192.0.2.102")
    else:
        raise RuntimeError("Unexpected question " + question)

    flow.response.answers[0].ipv4_address = replacement
    print("PROBE " + json.dumps({
        "hook": "dns_response",
        "flow": flow_number(flow),
        "question": question,
        "message_id": flow.response.id,
        "answer": str(replacement),
    }, sort_keys=True), flush=True)
