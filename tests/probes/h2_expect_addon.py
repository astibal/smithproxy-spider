"""Our observation addon for the optional loopback reference probe."""

import json


def requestheaders(flow):
    print("PROBE " + json.dumps(["requestheaders", flow.request.headers.get("expect"), flow.request.content is None]))


def request(flow):
    print("PROBE " + json.dumps(["request", flow.request.headers.get("expect"), flow.request.content.decode()]))


def responseheaders(flow):
    print("PROBE " + json.dumps(["responseheaders", flow.response.status_code]))


def response(flow):
    print("PROBE " + json.dumps(["response", flow.response.status_code, flow.response.content.decode()]))
