"""Reference-only addon for response-side flow.kill probes."""

import json


def report(name, flow):
    print("PROBE " + json.dumps({
        "hook": name,
        "path": flow.request.path if flow.request is not None else None,
        "live": flow.live,
        "killable": flow.killable,
        "error": None if flow.error is None else flow.error.msg,
    }), flush=True)


def requestheaders(flow):
    report("requestheaders", flow)


def request(flow):
    report("request", flow)


def responseheaders(flow):
    report("responseheaders", flow)
    if flow.request.path == "/kill-response-headers":
        flow.kill()
        report("responseheaders-after-kill", flow)


def response(flow):
    report("response", flow)
    if flow.request.path == "/kill-response":
        flow.kill()
        report("response-after-kill", flow)


def error(flow):
    report("error", flow)
