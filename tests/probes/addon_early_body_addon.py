"""Reference-only addon for body assignment from HTTP header hooks."""

import json


def report(hook, flow, message):
    content = message.raw_content
    print("PROBE " + json.dumps({
        "hook": hook,
        "path": flow.request.path,
        "content": None if content is None else content.decode("latin-1"),
        "content_length": message.headers.get("content-length"),
    }), flush=True)


def requestheaders(flow):
    report("requestheaders-before", flow, flow.request)
    if flow.request.path == "/replace-request":
        # Keep framing length stable. Changing Content-Length before mitmproxy
        # has consumed the original body can make the reference wait for bytes
        # that the client was never asked to send.
        flow.request.content = b"new request!!!!"
    report("requestheaders-after", flow, flow.request)


def request(flow):
    report("request", flow, flow.request)


def responseheaders(flow):
    report("responseheaders-before", flow, flow.response)
    if flow.request.path == "/replace-response":
        flow.response.content = b"new response!!!"
    report("responseheaders-after", flow, flow.response)


def response(flow):
    report("response", flow, flow.response)
