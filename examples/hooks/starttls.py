#!mitmproxy
"""Lifecycle-only STARTTLS observer; enable both TLS start subscriptions.

Use a deployment scope/filter matching the plaintext service under test.
The native proxy must recognize and accept its STARTTLS upgrade.
"""
import logging


def server_connected(data):
    logging.info("TCP connected: %s", data.server.peername)


def tls_start_server(data):
    # The descriptor and TCP setup timestamp survive the plaintext upgrade.
    logging.info("Upstream TLS start on TCP connection %s", data.conn.id)


def tls_start_client(data):
    logging.info("Client-facing TLS start on connection %s", data.conn.id)


def tls_established_server(data):
    logging.info("Upstream TLS accepted: %s", data.conn.tls_version)


def tls_established_client(data):
    logging.info("Client-facing TLS accepted: %s", data.conn.tls_version)
