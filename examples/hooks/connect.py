#!mitmproxy
"""Content/flow deployment for regular HTTP/1 CONNECT and TCP lifecycle."""
import logging

from mitmproxy import http


def http_connect(flow):
    # This is a local response before opening a target connection.
    if flow.request.host == "blocked.example":
        flow.response = http.Response.make(403, b"Blocked by CONNECT policy\n")


def server_connected(data):
    # TCP completion is distinct from TLS establishment.
    logging.info(f"TCP connected: {data.server.peername}")


def http_connected(flow):
    logging.info(f"CONNECT accepted: {flow.request.host}")


def http_connect_error(flow):
    logging.warning(f"CONNECT failed: {flow.response.status_code}")
