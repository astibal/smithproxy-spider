"""TLS start interception without transferring native SSL ownership."""

from addon_clienthello_native import (
    cipher_reply, read_upstream, reject_tls_changes, tls_settings, upstream_reply,
)
from addon_proxy_context import Context
from addon_runtime import AddonRuntimeError
from addon_tls import TlsData
from addon_tls_native import NativeSSLUnavailable, optional_text


async def dispatch(adapter, observation):
    envelope = observation['envelope']
    identity = adapter._identity(envelope['connection_id'])
    attempt = envelope['attempt']
    side = envelope.get('side')
    if (
        type(envelope.get('version')) is not int
        or envelope['version'] != 1
        or type(attempt) is not int
        or attempt < 1
        or side not in ('client', 'server')
        or envelope.get('event') != 'start'
    ):
        raise AddonRuntimeError('Invalid TLS start envelope')

    registered = adapter._connections.get(identity)
    if registered is None:
        raise AddonRuntimeError('TLS start requires an existing addon setup')

    key = (identity, side)
    previous = adapter._tls_starts.get(key)
    if previous is not None and attempt <= previous:
        raise AddonRuntimeError('Duplicate or stale TLS start')
    if attempt <= adapter._tls.get(key, 0):
        raise AddonRuntimeError('TLS start arrived after its outcome')

    server = registered.server
    conn = registered.client if side == 'client' else server
    upstream = None
    if side == 'server':
        upstream = read_upstream(observation)
        if upstream is None:
            raise AddonRuntimeError('TLS start requires native upstream settings')

        expression = observation['upstream'].get('openssl_cipher_list')
        if expression is not None and not isinstance(expression, str):
            raise AddonRuntimeError('Invalid native OpenSSL cipher expression')

        server.sni, server.alpn_offers = upstream
        server.cipher_list = expression.split(':') if expression is not None else []
    else:
        # Client start carries observations only, before SSL_accept. Negotiated
        # values and the establishment timestamp belong to the later outcome.
        conn.sni = optional_text(observation, 'sni', 255)

    conn.tls = True

    snapshots = (
        ('client', registered.client, tls_settings(registered.client)),
        ('server', server, tls_settings(server)),
    )
    context = Context(registered.client, adapter.generation.options)
    context.server = server
    ssl_view = NativeSSLUnavailable()
    data = TlsData(conn, context, ssl_conn=ssl_view)
    target = server.address

    # Claim the attempt before user code. The same descriptor is later used
    # for established/failed; start does not invent a successful handshake.
    adapter._tls_starts[key] = attempt
    try:
        failures = await adapter.generation.dispatch('tls_start_' + side, data)
    finally:
        reject_tls_changes(snapshots, allow_upstream=side == 'server', allow_ciphers=side == 'server')

    if failures:
        raise AddonRuntimeError('TLS start callback failed')
    if data.ssl_conn is not ssl_view:
        raise AddonRuntimeError('Native TLS callbacks cannot replace ssl_conn')

    if server.address != target:
        server.address = target
        raise AddonRuntimeError('TLS start cannot reroute the native transport')

    if (data.conn is not conn or data.context is not context or data.is_dtls
            or context.client is not registered.client or context.server is not server):
        raise AddonRuntimeError('TLS start cannot replace native context or transport')

    if conn.error:
        return {'proceed': False}

    if side == 'client':
        return {'proceed': True}

    settings = upstream_reply(server, upstream)
    settings['openssl_cipher_list'] = cipher_reply(server.cipher_list)
    return {'proceed': True, 'upstream': settings}
