"""Reference-only addon for HTTP CONNECT control-semantics probes."""

import json
import os

from mitmproxy import http


ACTION = os.environ["CONNECT_ACTION"]


def report(hook, flow):
    print("PROBE " + json.dumps({
        "hook": hook,
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
    if ACTION == "local-response":
        flow.response = http.Response.make(418, b"blocked")
    elif ACTION == "kill":
        flow.kill()
    elif ACTION == "reroute":
        flow.request.host = "127.0.0.1"
        flow.request.port = int(os.environ["CONNECT_REROUTE_PORT"])

    report("http_connect", flow)


def http_connected(flow):
    if ACTION == "mutate-connected":
        flow.response.status_code = 299
    elif ACTION == "kill-connected":
        flow.kill()

    report("http_connected", flow)


def http_connect_error(flow):
    if ACTION == "mutate-error":
        flow.response.status_code = 599
    elif ACTION == "kill-error":
        flow.kill()

    report("http_connect_error", flow)
