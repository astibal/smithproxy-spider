"""Reference-only addon for DNS flow control evidence."""

import ipaddress
import json
import os

from mitmproxy import dns


CASE = os.environ["DNS_CONTROL_CASE"]


def state(flow):
    return {
        "live": flow.live,
        "error": None if flow.error is None else flow.error.msg,
        "response_present": flow.response is not None,
    }


def dns_request(flow):
    before = state(flow)
    if CASE == "request-kill":
        flow.kill()
    elif CASE in ("local-response-kill", "request-local-kill"):
        flow.response = flow.request.succeed([
            dns.ResourceRecord.A(
                flow.request.question.name,
                ipaddress.IPv4Address("192.0.2.10"),
                ttl=30,
            ),
        ])
        if CASE == "request-local-kill":
            flow.kill()
    print("PROBE " + json.dumps({
        "hook": "dns_request",
        "case": CASE,
        "before": before,
        "after": state(flow),
    }, sort_keys=True), flush=True)


def dns_response(flow):
    before = state(flow)
    if CASE == "local-response-kill":
        flow.response.answers[0].ipv4_address = ipaddress.IPv4Address(
            "192.0.2.91"
        )
        flow.kill()
    elif CASE == "upstream-response-kill":
        flow.response.answers[0].ipv4_address = ipaddress.IPv4Address(
            "192.0.2.92"
        )
        flow.kill()
    print("PROBE " + json.dumps({
        "hook": "dns_response",
        "case": CASE,
        "before": before,
        "after": state(flow),
    }, sort_keys=True), flush=True)
