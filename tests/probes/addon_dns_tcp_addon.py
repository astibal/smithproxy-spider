"""Reference-only addon for DNS-over-TCP message framing evidence."""

import ipaddress
import json

from mitmproxy import dns


flow_numbers = {}
client_connection = None


def flow_number(flow):
    identity = id(flow)
    if identity not in flow_numbers:
        flow_numbers[identity] = len(flow_numbers) + 1
    return flow_numbers[identity]


def report(hook, flow):
    global client_connection

    if client_connection is None:
        client_connection = id(flow.client_conn)

    answer = None
    if flow.response is not None and flow.response.answers:
        answer = str(flow.response.answers[0].ipv4_address)

    print("PROBE " + json.dumps({
        "hook": hook,
        "flow": flow_number(flow),
        "same_client_connection": id(flow.client_conn) == client_connection,
        "question": flow.request.question.name,
        "answer": answer,
    }, sort_keys=True), flush=True)


def dns_request(flow):
    report("dns_request", flow)
    number = flow_number(flow)
    question = flow.request.question
    flow.response = flow.request.succeed([
        dns.ResourceRecord.A(
            question.name,
            ipaddress.IPv4Address("192.0.2." + str(10 + number)),
            ttl=30,
        ),
    ])


def dns_response(flow):
    number = flow_number(flow)
    flow.response.answers[0].ipv4_address = ipaddress.IPv4Address(
        "192.0.2." + str(90 + number)
    )
    report("dns_response", flow)
