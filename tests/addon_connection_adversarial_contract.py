"""Black-box contract for detached connection-model edge cases."""

from __future__ import annotations

import warnings


def _json_value(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    return value


def _outcome(callback):
    try:
        value = callback()
    except Exception as error:
        return {
            "status": "error",
            "type": type(error).__name__,
            "message": str(error),
        }
    return {
        "status": "ok",
        "value": _json_value(value),
    }


def _warning(callback):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value = callback()
    return {
        "value": _json_value(value),
        "warnings": [
            {
                "category": warning.category.__name__,
                "message": str(warning.message),
            }
            for warning in caught
        ],
    }


def _client_state(client):
    state = client.get_state()
    return {
        "peername": state["peername"],
        "transport_protocol": state["transport_protocol"],
    }


def collect(connection):
    cases = {}

    required = (
        ("missing_peername", None, ("proxy", 8080), False),
        ("missing_sockname", ("client", 1234), None, False),
        ("missing_proxy_mode", ("client", 1234), ("proxy", 8080), True),
    )
    for name, peername, sockname, clear_proxy_mode in required:
        client = connection.Client(peername=peername, sockname=sockname)
        if clear_proxy_mode:
            client.proxy_mode = None
        cases[name] = _outcome(client.get_state)

    invalid_fields = (
        ("peername_shape", "client"),
        ("peername_empty", ()),
        ("peername_single", ("client",)),
        ("peername_length", ("client", 1234, "extra")),
        ("peername_extended", ("client", 1234, 5678)),
        ("peername_host", (1234, 1234)),
        ("peername_port", ("client", "1234")),
        ("transport_protocol", 1),
        ("transport_protocol_literal", "quic"),
        ("timestamp_start", "now"),
        ("tls", 1),
        ("alpn", "h2"),
        ("alpn_offers", [b"h2", "http/1.1"]),
        ("cipher_list", ["cipher", b"other"]),
    )
    for name, value in invalid_fields:
        client = connection.Client(peername=("client", 1234), sockname=("proxy", 8080))
        if name.startswith("peername_"):
            field_name = "peername"
        elif name.startswith("transport_protocol_"):
            field_name = "transport_protocol"
        else:
            field_name = name
        setattr(client, field_name, value)
        cases["invalid_" + name] = _outcome(lambda client=client: _client_state(client))

    server = connection.Server(
        address=("target.example", 443),
        peername=("192.0.2.10", 443),
        alpn=b"h2",
        cipher="TLS_AES_128_GCM_SHA256",
    )
    cases["legacy_alpn"] = _warning(lambda: server.alpn_proto_negotiated)
    cases["legacy_ip_address"] = _warning(lambda: server.ip_address)
    cases["legacy_empty_cert"] = _warning(lambda: server.cert)

    client = connection.Client(
        peername=("192.0.2.20", 1234),
        sockname=("192.0.2.1", 8080),
        cipher="TLS_AES_128_GCM_SHA256",
    )
    cases["legacy_address"] = _warning(lambda: client.address)
    cases["legacy_cipher_name"] = _warning(lambda: client.cipher_name)
    cases["legacy_empty_clientcert"] = _warning(lambda: client.clientcert)

    cases["equality_other_type"] = server == object()
    cases["connection_state_values"] = {
        name: state.value
        for name, state in connection.ConnectionState.__members__.items()
    }
    return cases
