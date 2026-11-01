"""Shared black-box observations for public SOCKS5 authentication values."""

import dataclasses
import inspect


def collect(modes, connection):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 1080),
        id="client-1",
    )
    data = modes.Socks5AuthData(client, "alice", "secret")
    same = modes.Socks5AuthData(client, "alice", "secret")
    different = modes.Socks5AuthData(client, "alice", "other")
    hook = modes.Socks5AuthHook(data)

    before = {
        "client_identity": data.client_conn is client,
        "username": data.username,
        "password": data.password,
        "valid": data.valid,
        "equal_same": data == same,
        "equal_different": data == different,
        "match_args": list(modes.Socks5AuthData.__match_args__),
    }
    data.valid = True

    return {
        "surface": {
            "data_signature": str(inspect.signature(modes.Socks5AuthData)),
            "hook_signature": str(inspect.signature(modes.Socks5AuthHook)),
            "data_fields": [field.name for field in dataclasses.fields(data)],
            "hook_fields": [field.name for field in dataclasses.fields(hook)],
            "data_module": modes.Socks5AuthData.__module__,
            "hook_module": modes.Socks5AuthHook.__module__,
            "hook_name": hook.name,
        },
        "before": before,
        "after": {
            "valid": data.valid,
            "hook_data_identity": hook.data is data,
            "hook_args_identity": hook.args()[0] is data,
            "hook_equal_self": hook == hook,
            "hook_equal_other": hook == modes.Socks5AuthHook(data),
        },
    }
