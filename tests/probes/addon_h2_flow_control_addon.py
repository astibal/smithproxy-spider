"""Reference addon for the bounded HTTP/2 flow-control observation."""

from mitmproxy import http


def request(flow):
    if flow.request.path == "/large":
        flow.response = http.Response.make(
            200,
            b"L" * (150 * 1024),
            {"X-Flow-Case": "large"},
        )
        return

    if flow.request.path == "/small":
        flow.response = http.Response.make(
            201,
            b"small sibling",
            {"X-Flow-Case": "small"},
        )

