#!mitmproxy
"""Content/flow deployment; enable tls_clienthello and tls_start_server."""
import logging


def tls_clienthello(data):
    # Observe the original client offer. Do not change the client descriptor.
    logging.info(f"ClientHello SNI: {data.client_hello.sni}")


def tls_start_server(data):
    # Restrict this example to a lab target; certificate checks still apply.
    if data.conn.sni == "example.test":
        data.conn.alpn_offers = [b"http/1.1"]
        data.conn.cipher_list = ["ECDHE+AESGCM"]


def tls_established_server(data):
    logging.info(f"Upstream TLS established: {data.conn.sni}")


def tls_failed_server(data):
    logging.warning(f"Upstream TLS failed: {data.conn.error}")
