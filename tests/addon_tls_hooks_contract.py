"""Shared black-box observations for public TLS hook values."""

import dataclasses

from addon_tls_contract import tls_client_hello


def collect(tls_hooks, tls, connection, options, context):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 443),
        id="client-1",
    )
    proxy_context = context.Context(client, options.Options())
    hello_data = tls.ClientHelloData(
        proxy_context,
        tls.ClientHello(tls_client_hello()),
    )
    tls_data = tls.TlsData(client, proxy_context)

    cases = (
        (tls_hooks.TlsClienthelloHook, hello_data),
        (tls_hooks.TlsStartClientHook, tls_data),
        (tls_hooks.TlsStartServerHook, tls_data),
        (tls_hooks.TlsEstablishedClientHook, tls_data),
        (tls_hooks.TlsEstablishedServerHook, tls_data),
        (tls_hooks.TlsFailedClientHook, tls_data),
        (tls_hooks.TlsFailedServerHook, tls_data),
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
            "module": hook_type.__module__,
        }
    return hooks
