"""Shared black-box observations for connection lifecycle hook values."""

import dataclasses


def collect(server_hooks, connection):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 443),
        id="client-1",
    )
    server = connection.Server(
        address=("example.test", 443),
        id="server-1",
    )
    data = server_hooks.ServerConnectionHookData(server, client)

    cases = (
        (server_hooks.ClientConnectedHook, client),
        (server_hooks.ClientDisconnectedHook, client),
        (server_hooks.ServerConnectHook, data),
        (server_hooks.ServerConnectedHook, data),
        (server_hooks.ServerConnectErrorHook, data),
        (server_hooks.ServerDisconnectedHook, data),
    )
    hooks = {}
    for hook_type, argument in cases:
        hook = hook_type(argument)
        hooks[hook_type.__name__] = {
            "name": hook.name,
            "blocking": hook.blocking,
            "argument_identity": hook.args()[0] is argument,
            "equal_other": hook == hook_type(argument),
            "fields": [field.name for field in dataclasses.fields(hook)],
        }

    return {
        "data": {
            "fields": [field.name for field in dataclasses.fields(data)],
            "server_identity": data.server is server,
            "client_identity": data.client is client,
            "equal_other": (
                data == server_hooks.ServerConnectionHookData(server, client)
            ),
        },
        "hooks": hooks,
    }
