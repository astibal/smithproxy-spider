"""Reference-only addon for DNS resolver failure behavior."""

import json


def report(hook, flow):
    print("PROBE " + json.dumps({
        "hook": hook,
        "live": flow.live,
        "question": flow.request.question.name,
        "response_present": flow.response is not None,
        "response_code": (
            None if flow.response is None else flow.response.response_code),
        "error": None if flow.error is None else flow.error.msg,
    }, sort_keys=True), flush=True)


def dns_request(flow):
    report("dns_request", flow)


def dns_response(flow):
    report("dns_response", flow)


def dns_error(flow):
    report("dns_error", flow)
