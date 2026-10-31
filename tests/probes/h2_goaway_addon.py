"""Original observation addon for the optional GOAWAY reference probe."""

import json


def requestheaders(flow):
    print('PROBE ' + json.dumps(['requestheaders', flow.request.path]), flush=True)


def request(flow):
    print('PROBE ' + json.dumps(['request', flow.request.path]), flush=True)


def responseheaders(flow):
    print('PROBE ' + json.dumps(['responseheaders', flow.request.path,
                               flow.response.status_code]), flush=True)


def response(flow):
    print('PROBE ' + json.dumps(['response', flow.request.path,
                               flow.response.status_code]), flush=True)


def error(flow):
    print('PROBE ' + json.dumps(['error', flow.request.path,
                               str(flow.error)]), flush=True)
