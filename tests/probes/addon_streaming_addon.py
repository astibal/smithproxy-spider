"""Reference-only addon for the HTTP streaming lifecycle probe."""

import json


def report(name, flow, message):
    content = None if message is None else message.raw_content
    print("PROBE " + json.dumps({
        "hook": name,
        "path": flow.request.path if flow.request is not None else None,
        "content": None if content is None else content.decode("latin-1"),
        "stream": None if message is None else bool(message.stream),
    }), flush=True)


def requestheaders(flow):
    report("requestheaders-before", flow, flow.request)
    flow.request.stream = True
    report("requestheaders-after", flow, flow.request)


def request(flow):
    report("request", flow, flow.request)


def responseheaders(flow):
    report("responseheaders-before", flow, flow.response)
    flow.response.stream = True
    report("responseheaders-after", flow, flow.response)


def response(flow):
    report("response", flow, flow.response)

