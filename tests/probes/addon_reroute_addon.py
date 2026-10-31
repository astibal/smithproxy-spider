"""Reference-only addon for upstream destination mutation probes."""

import json

from mitmproxy import ctx


def report(name, flow):
    print("PROBE " + json.dumps({
        "hook": name,
        "path": flow.request.path,
        "host": flow.request.host,
        "port": flow.request.port,
        "host_header": flow.request.host_header,
    }), flush=True)


def load(loader):
    loader.add_option("probe_destination_port", int, 0,
                      "Disposable destination used by the compatibility probe")


def reroute(flow):
    flow.request.host = "127.0.0.1"
    flow.request.port = ctx.options.probe_destination_port


def requestheaders(flow):
    report("requestheaders-before", flow)
    if flow.request.path == "/headers":
        reroute(flow)
        report("requestheaders-after", flow)


def request(flow):
    report("request-before", flow)
    if flow.request.path == "/request":
        reroute(flow)
        report("request-after", flow)


def response(flow):
    report("response", flow)

