"""Shared black-box observations for public QUIC TLS hook values."""

import dataclasses


def collect(quic, tls, connection, options, context):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 443),
        id="client-1",
    )
    proxy_context = context.Context(client, options.Options())

    first = quic.QuicTlsSettings()
    second = quic.QuicTlsSettings()
    custom = quic.QuicTlsSettings(
        alpn_protocols=["h3"],
        certificate="leaf",
        certificate_chain=["intermediate"],
        certificate_private_key="private-key",
        cipher_suites=[4865],
        ca_path="/ca/path",
        ca_file="/ca/file",
        verify_mode="required",
    )
    data = quic.QuicTlsData(client, proxy_context)
    client_hook = quic.QuicStartClientHook(data)
    server_hook = quic.QuicStartServerHook(data)

    defaults = {
        field.name: getattr(first, field.name)
        for field in dataclasses.fields(first)
    }
    custom_values = {
        field.name: getattr(custom, field.name)
        for field in dataclasses.fields(custom)
    }

    return {
        "surface": {
            "settings_module": quic.QuicTlsSettings.__module__,
            "data_module": quic.QuicTlsData.__module__,
            "client_hook_module": quic.QuicStartClientHook.__module__,
            "server_hook_module": quic.QuicStartServerHook.__module__,
            "settings_fields": [
                field.name for field in dataclasses.fields(first)
            ],
            "data_fields": [field.name for field in dataclasses.fields(data)],
            "data_is_tls_data": isinstance(data, tls.TlsData),
        },
        "settings": {
            "defaults": defaults,
            "equal_defaults": first == second,
            "independent_certificate_chain": (
                first.certificate_chain is not second.certificate_chain
            ),
            "custom": custom_values,
        },
        "data": {
            "conn_identity": data.conn is client,
            "context_identity": data.context is proxy_context,
            "ssl_conn": data.ssl_conn,
            "is_dtls": data.is_dtls,
            "settings": data.settings,
        },
        "hooks": {
            "client_name": client_hook.name,
            "server_name": server_hook.name,
            "client_blocking": client_hook.blocking,
            "server_blocking": server_hook.blocking,
            "client_arg_identity": client_hook.args()[0] is data,
            "server_arg_identity": server_hook.args()[0] is data,
            "client_equal_other": (
                client_hook == quic.QuicStartClientHook(data)
            ),
            "server_equal_other": (
                server_hook == quic.QuicStartServerHook(data)
            ),
        },
    }
