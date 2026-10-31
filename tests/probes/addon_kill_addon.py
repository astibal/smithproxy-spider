"""Reference-only addon for the flow.kill lifecycle probe."""

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
    if flow.request.path == "/kill-headers":
        flow.kill()
        report("requestheaders-after-kill", flow)


def request(flow):
    report("request", flow)
    if flow.request.path in ("/kill-request", "/kill-h2"):
        flow.kill()
        report("request-after-kill", flow)


def responseheaders(flow):
    report("responseheaders", flow)


def response(flow):
    report("response", flow)


def error(flow):
    report("error", flow)
