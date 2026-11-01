"""Reference-only addon for local DNS error-response evidence."""

import json

from mitmproxy import dns


flow_identity = None


def dns_request(flow):
    global flow_identity

    flow_identity = id(flow)
    print("PROBE " + json.dumps({
        "hook": "dns_request",
        "question": flow.request.question.name,
        "response_present": flow.response is not None,
    }, sort_keys=True), flush=True)
    flow.response = flow.request.fail(dns.response_codes.NXDOMAIN)


def dns_response(flow):
    before = flow.response.response_code
    flow.response.response_code = dns.response_codes.REFUSED
    print("PROBE " + json.dumps({
        "hook": "dns_response",
        "same_flow": id(flow) == flow_identity,
        "before": before,
        "after": flow.response.response_code,
    }, sort_keys=True), flush=True)
