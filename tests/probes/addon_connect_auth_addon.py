"""Reference-only addon for HTTP CONNECT proxy-authentication probes."""

import json


def report(hook, flow):
    print("PROBE " + json.dumps({
        "hook": hook,
        "flow_id": flow.id,
        "response_status": (
            flow.response.status_code if flow.response is not None else None
        ),
        "proxy_authorization_present": (
            "proxy-authorization" in flow.request.headers
        ),
    }), flush=True)


def http_connect(flow):
    report("http_connect", flow)


def http_connected(flow):
    report("http_connected", flow)


def http_connect_error(flow):
    report("http_connect_error", flow)
