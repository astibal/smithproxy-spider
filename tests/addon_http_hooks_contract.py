"""Shared black-box observations for public HTTP hook values."""

import dataclasses


def collect(http_hooks, private_http_hooks, http, connection):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 443),
        id="client-1",
    )
    server = connection.Server(
        address=("example.test", 443),
        id="server-1",
    )
    flow = http.HTTPFlow(client, server, live=True)

    hook_types = (
        http_hooks.HttpConnectHook,
        http_hooks.HttpConnectErrorHook,
        private_http_hooks.HttpConnectUpstreamHook,
        http_hooks.HttpConnectedHook,
        http_hooks.HttpRequestHeadersHook,
        http_hooks.HttpRequestHook,
        http_hooks.HttpResponseHeadersHook,
        http_hooks.HttpResponseHook,
        http_hooks.HttpErrorHook,
    )

    hooks = {}
    for hook_type in hook_types:
        hook = hook_type(flow)
        hooks[hook_type.__name__] = {
            "name": hook.name,
            "blocking": hook.blocking,
            "argument_identity": hook.args()[0] is flow,
            "equal_other": hook == hook_type(flow),
            "fields": [field.name for field in dataclasses.fields(hook)],
            "module": hook_type.__module__,
        }

    return hooks
