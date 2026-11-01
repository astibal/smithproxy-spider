"""Reference-only addon for upstream HTTP CONNECT control probes."""

import json
import os

from mitmproxy import http


ACTION = os.environ["CONNECT_ACTION"]


def report(hook, flow, phase="after"):
    print("PROBE " + json.dumps({
        "hook": hook,
        "phase": phase,
        "flow_id": flow.id,
        "host": flow.request.host,
        "port": flow.request.port,
        "response_status": (
            flow.response.status_code if flow.response is not None else None
        ),
        "error": str(flow.error) if flow.error is not None else None,
        "live": flow.live,
    }), flush=True)


def http_connect(flow):
    report("http_connect", flow)


def http_connected(flow):
    report("http_connected", flow)


def http_connect_upstream(flow):
    report("http_connect_upstream", flow, "before")

    if ACTION == "reroute":
        flow.request.host = "rewritten.invalid"
        flow.request.port = 9443
    elif ACTION == "kill":
        try:
            flow.kill()
        except BaseException as exception:
            print("PROBE_EXCEPTION " + json.dumps({
                "type": type(exception).__name__,
                "module": type(exception).__module__,
                "message": str(exception),
            }), flush=True)
            raise
    elif ACTION == "local-response":
        flow.response = http.Response.make(418, b"blocked")

    report("http_connect_upstream", flow)


def http_connect_error(flow):
    report("http_connect_error", flow)
