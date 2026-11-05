#!mitmproxy
"""Content/flow deployment; enable quic_start_server. IPv4 QUIC only."""
import logging


def quic_start_server(data):
    # QUIC uses TLS 1.3 wire identifiers, not TCP's legacy cipher expression.
    if data.conn.sni == "example.test":
        data.settings.alpn_protocols = ["h3"]
        data.settings.cipher_suites = [0x1301]  # TLS_AES_128_GCM_SHA256

    # To veto, set data.conn.error to a nonempty reason instead.
    # SNI may be changed, but certificate verification keeps the native identity.


def tls_established_server(data):
    # Outcomes belong to the QUIC parent, not to each HTTP/3 stream.
    if data.conn.transport_protocol == "udp":
        logging.info(f"QUIC upstream established: {data.conn.sni}")


def tls_failed_server(data):
    if data.conn.transport_protocol == "udp":
        logging.warning(f"QUIC upstream failed: {data.conn.error}")
