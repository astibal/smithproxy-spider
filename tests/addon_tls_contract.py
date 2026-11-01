"""Shared black-box observations for public TLS addon values."""

import dataclasses
import struct


def extension(extension_type, payload):
    return struct.pack("!HH", extension_type, len(payload)) + payload


def tls_client_hello(*, sni=True, alpn=True, extension_length=True):
    extensions = b""
    if sni:
        hostname = b"example.test"
        names = b"\x00" + struct.pack("!H", len(hostname)) + hostname
        extensions += extension(0, struct.pack("!H", len(names)) + names)
    if alpn:
        protocols = b"\x02h2\x08http/1.1"
        extensions += extension(16, struct.pack("!H", len(protocols)) + protocols)
    extensions += extension(0x1234, b"\x01\x02")

    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", 4)
        + b"\x13\x01\xc0\x2f"
        + b"\x01\x00"
    )
    if extension_length:
        body += struct.pack("!H", len(extensions)) + extensions
    return body


def dtls_client_hello():
    return (
        b"\xfe\xfd"
        + bytes(range(32))
        + b"\x00"
        + b"\x03abc"
        + struct.pack("!H", 2)
        + b"\xc0\x2f"
        + b"\x01\x00"
        + b"\x00\x00"
    )


def normalize(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    return value


def outcome(callback):
    try:
        value = callback()
    except Exception as error:
        return {
            "ok": False,
            "type": type(error).__name__,
            "message": str(error),
        }
    return {"ok": True, "value": normalize(value)}


def inspect_hello(tls, raw, *, dtls=False):
    try:
        hello = tls.ClientHello(raw, dtls=dtls)
    except Exception as error:
        return {
            "constructor": {
                "ok": False,
                "type": type(error).__name__,
                "message": str(error),
            }
        }

    return {
        "constructor": {"ok": True},
        "raw_bytes": outcome(hello.raw_bytes),
        "cipher_suites": outcome(lambda: hello.cipher_suites),
        "sni": outcome(lambda: hello.sni),
        "alpn_protocols": outcome(lambda: hello.alpn_protocols),
        "extensions": outcome(lambda: [
            [extension_type, payload.hex()]
            for extension_type, payload in hello.extensions
        ]),
        "repr": repr(hello),
    }


def collect(tls, connection, options, context):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 443),
        id="client-1",
    )
    proxy_context = context.Context(client, options.Options())
    forked = proxy_context.fork()

    hello = tls.ClientHello(tls_client_hello())
    client_hello_data = tls.ClientHelloData(proxy_context, hello)
    tls_data = tls.TlsData(client, proxy_context)
    data_defaults = {
        "client_hello_context_identity": client_hello_data.context is proxy_context,
        "client_hello_identity": client_hello_data.client_hello is hello,
        "ignore_connection": client_hello_data.ignore_connection,
        "establish_server_tls_first": (
            client_hello_data.establish_server_tls_first
        ),
        "tls_conn_identity": tls_data.conn is client,
        "tls_context_identity": tls_data.context is proxy_context,
        "ssl_conn": tls_data.ssl_conn,
        "is_dtls": tls_data.is_dtls,
    }
    client_hello_data.ignore_connection = True
    client_hello_data.establish_server_tls_first = True
    tls_data.is_dtls = True

    return {
        "surface": {
            "client_hello": sorted(
                name for name in dir(tls.ClientHello)
                if not name.startswith("_")
            ),
            "client_hello_data_fields": [
                field.name for field in dataclasses.fields(client_hello_data)
            ],
            "tls_data_fields": [
                field.name for field in dataclasses.fields(tls_data)
            ],
            "context": sorted(
                name for name in dir(context.Context)
                if not name.startswith("_")
            ),
        },
        "hello": {
            "complete": inspect_hello(tls, tls_client_hello()),
            "without_sni": inspect_hello(
                tls, tls_client_hello(sni=False)
            ),
            "without_alpn": inspect_hello(
                tls, tls_client_hello(alpn=False)
            ),
            "without_extensions_length": inspect_hello(
                tls,
                tls_client_hello(
                    sni=False,
                    alpn=False,
                    extension_length=False,
                ),
            ),
            "dtls": inspect_hello(tls, dtls_client_hello(), dtls=True),
            "truncated": inspect_hello(tls, b"\x03\x03short"),
        },
        "context": {
            "client_identity": proxy_context.client is client,
            "options_identity": forked.options is proxy_context.options,
            "server_identity": forked.server is proxy_context.server,
            "layers_independent": forked.layers is not proxy_context.layers,
            "fork_client_identity": forked.client is proxy_context.client,
        },
        "data_defaults": data_defaults,
        "data_mutated": {
            "ignore_connection": client_hello_data.ignore_connection,
            "establish_server_tls_first": (
                client_hello_data.establish_server_tls_first
            ),
            "is_dtls": tls_data.is_dtls,
        },
    }
