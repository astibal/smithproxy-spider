"""Reference-only addon for the local-response lifecycle probe."""

import json

from mitmproxy import http


def report(name, flow):
    response = flow.response
    observation = {
        "hook": name,
        "path": flow.request.path,
        "status": None if response is None else response.status_code,
        "body": None if response is None else response.raw_content.decode("latin-1"),
    }
    if response is not None and response.trailers is not None:
        observation["trailers"] = [
            [field.decode("latin-1"), value.decode("latin-1")]
            for field, value in response.trailers.fields
        ]
    print("PROBE " + json.dumps(observation), flush=True)


def requestheaders(flow):
    report("requestheaders", flow)
    if flow.request.path == "/headers":
        flow.response = http.Response.make(
            201,
            b"from requestheaders",
            {
                "Connection": "close",
                "X-Origin": "requestheaders",
            },
        )


def request(flow):
    report("request", flow)
    if flow.request.path == "/request":
        flow.response = http.Response.make(
            202,
            b"from request",
            {
                "Connection": "close",
                "X-Origin": "request",
            },
        )
    elif flow.request.path == "/empty":
        flow.response = http.Response.make(
            204,
            b"body assigned to 204",
            {"Connection": "close"},
        )
    elif flow.request.path == "/h2":
        flow.response = http.Response.make(
            203,
            b"from HTTP/2 request",
            {"X-Origin": "request"},
        )
    elif flow.request.path == "/pipeline-first":
        flow.response = http.Response.make(
            200,
            b"first local response",
            {"X-Origin": "pipeline-first"},
        )
    elif flow.request.path == "/pipeline-second":
        flow.response = http.Response.make(
            201,
            b"second local response",
            {"X-Origin": "pipeline-second"},
        )
    elif flow.request.path == "/trailers":
        flow.response = http.Response.make(
            202,
            b"local response with trailers",
            {"X-Origin": "trailers"},
        )
        flow.response.trailers = http.Headers([
            (b"x-local-trailer", b"one"),
            (b"x-local-trailer", b"two"),
        ])
    elif flow.request.path == "/trailers-chunked":
        flow.response = http.Response.make(
            203,
            b"chunked local response",
            {
                "Transfer-Encoding": "chunked",
                "X-Origin": "trailers-chunked",
            },
        )
        flow.response.headers.pop("content-length", None)
        flow.response.trailers = http.Headers([
            (b"x-local-trailer", b"one"),
            (b"x-local-trailer", b"two"),
        ])


def responseheaders(flow):
    report("responseheaders", flow)
    flow.response.headers["X-Response-Headers"] = "seen"


def response(flow):
    report("response", flow)
    flow.response.headers["X-Response"] = "seen"
    if flow.response.trailers is not None:
        flow.response.trailers.add("X-Response-Trailer", "seen")
    if flow.response.status_code != 204:
        flow.response.content += b" | response hook"
