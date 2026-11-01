"""Reference-only addon for complex DNS message evidence."""

import ipaddress
import json


def snapshot(message):
    return {
        "id": message.id,
        "query": message.query,
        "op_code": message.op_code,
        "authoritative_answer": message.authoritative_answer,
        "truncation": message.truncation,
        "recursion_desired": message.recursion_desired,
        "recursion_available": message.recursion_available,
        "reserved": message.reserved,
        "response_code": message.response_code,
        "questions": [
            [question.name, question.type, question.class_]
            for question in message.questions
        ],
        "answers": records(message.answers),
        "authorities": records(message.authorities),
        "additionals": records(message.additionals),
    }


def records(values):
    return [
        [record.name, record.type, record.class_, record.ttl, record.data.hex()]
        for record in values
    ]


def dns_request(flow):
    print("PROBE " + json.dumps({
        "hook": "dns_request",
        "message": snapshot(flow.request),
    }, sort_keys=True), flush=True)

    response = flow.request.copy()
    response.id = flow.request.id
    response.query = False
    flow.response = response


def dns_response(flow):
    flow.response.answers[0].ttl = 99
    flow.response.additionals[0].ipv4_address = ipaddress.IPv4Address(
        "192.0.2.99"
    )
    print("PROBE " + json.dumps({
        "hook": "dns_response",
        "message": snapshot(flow.response),
    }, sort_keys=True), flush=True)
