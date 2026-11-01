"""Reference-only addon for the live HTTP CONNECT lifecycle probe."""

import json


servers = {}


def report(name, flow):
    request = flow.request
    response = flow.response
    error = flow.error
    server = flow.server_conn
    first_server = servers.setdefault(flow.id, server)
    print("PROBE " + json.dumps({
        "hook": name,
        "flow_type": flow.type,
        "flow_id": flow.id,
        "method": request.method,
        "host": request.host,
        "port": request.port,
        "response_present": response is not None,
        "response_status": None if response is None else response.status_code,
        "error": None if error is None else error.msg,
        "server_address": server.address,
        "server_peername_present": server.peername is not None,
        "server_object_preserved": server is first_server,
        "server_id_preserved": server.id == first_server.id,
    }), flush=True)


def http_connect(flow):
    report("http_connect", flow)


def http_connect_upstream(flow):
    report("http_connect_upstream", flow)


def http_connected(flow):
    report("http_connected", flow)


def http_connect_error(flow):
    report("http_connect_error", flow)


def requestheaders(flow):
    report("requestheaders", flow)


def request(flow):
    report("request", flow)


def responseheaders(flow):
    report("responseheaders", flow)


def response(flow):
    report("response", flow)


def error(flow):
    report("error", flow)
