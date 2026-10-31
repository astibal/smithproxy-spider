"""Reference-only addon for the live TLS hook probe."""

import json


def connection_report(name, data):
    connection = data.conn
    print("PROBE " + json.dumps({
        "hook": name,
        "connection": type(connection).__name__,
        "transport": connection.transport_protocol,
        "sni": connection.sni,
        "tls": connection.tls,
        "tls_established": connection.tls_established,
        "tls_version": connection.tls_version,
        "alpn": None if connection.alpn is None else connection.alpn.decode("latin-1"),
    }), flush=True)


def tls_clienthello(data):
    print("PROBE " + json.dumps({
        "hook": "tls_clienthello",
        "sni": data.client_hello.sni,
        "alpn_offers": [value.decode("latin-1") for value in data.client_hello.alpn_protocols],
        "ignore_connection": data.ignore_connection,
        "establish_server_tls_first": data.establish_server_tls_first,
    }), flush=True)


def tls_start_client(data):
    connection_report("tls_start_client", data)


def tls_start_server(data):
    connection_report("tls_start_server", data)


def tls_established_client(data):
    connection_report("tls_established_client", data)


def tls_established_server(data):
    connection_report("tls_established_server", data)


def tls_failed_client(data):
    connection_report("tls_failed_client", data)


def tls_failed_server(data):
    connection_report("tls_failed_server", data)
