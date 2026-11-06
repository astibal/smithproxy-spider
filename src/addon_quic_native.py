"""QUIC parent handshakes, separate from HTTP/3 stream inspection."""


from addon_proxy_context import Context
from addon_clienthello_native import tls_settings, reject_tls_changes
from addon_quic import QuicTlsData, QuicTlsSettings
from addon_runtime import AddonRuntimeError
from addon_tls_native import NativeSSLUnavailable, dispatch as dispatch_outcome
from inspection_tls import TlsView, TlsTransport, TlsDecision


# QUIC uses TLS 1.3 suites. Translate wire IDs here, never in native transport.
CIPHERS = {
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x1304: 'TLS_AES_128_CCM_SHA256',
    0x1305: 'TLS_AES_128_CCM_8_SHA256',
}


async def dispatch(adapter, observation):
    # Handshake callbacks belong to the parent session, not an HTTP/3 stream.
    envelope = observation['envelope']
    identity = adapter._identity(envelope['connection_id'])
    registered = adapter._connections.get(identity)
    if registered is None or registered.kind != 'quic':
        raise AddonRuntimeError('QUIC event requires its parent transport setup')

    # Established/failed events use the shared TLS outcome contract. Adapt
    # QUIC's textual ALPN to that contract without changing the hook names.
    if envelope.get('event') != 'start':
        return await dispatch_outcome(adapter, observation, transport=TlsTransport.QUIC)

    if (envelope.get('version') != 1 or envelope.get('side') != 'server'
            or type(envelope.get('attempt')) is not int or envelope['attempt'] < 1):
        raise AddonRuntimeError('Invalid QUIC start envelope')

    # Each upstream attempt may start once. Reject delayed or repeated events
    # before invoking addon code or changing its connection descriptors.
    key = (identity, 'server')
    attempt = envelope['attempt']
    if attempt <= adapter._tls_starts.get(key, 0) or attempt <= adapter._tls.get(key, 0):
        raise AddonRuntimeError('Duplicate or stale QUIC start')

    # Seed the addon settings from the current native offer. This also preserves
    # mutations accepted from an earlier addon in the deployment chain.
    draft = TlsView.from_observation(observation, TlsTransport.QUIC).start
    server = registered.server
    server.sni = draft.sni
    server.tls = True
    context = Context(registered.client, adapter.generation.options)
    context.server = server
    cipher_suites = None
    expression = draft.openssl_ciphersuites
    if expression is not None:
        reverse = {name: value for value, name in CIPHERS.items()}
        try:
            cipher_suites = [reverse[name] for name in expression.split(':')] if expression else []
        except (KeyError, AttributeError) as error:
            raise AddonRuntimeError('Invalid native QUIC cipher expression') from error

    settings = QuicTlsSettings(alpn_protocols=[draft.alpn_offers[0].decode('ascii')], cipher_suites=cipher_suites)
    ssl_view = NativeSSLUnavailable()
    data = QuicTlsData(server, context, ssl_conn=ssl_view, settings=settings)
    target = server.address
    snapshots = (
        ('client', registered.client, tls_settings(registered.client)),
        ('server', server, tls_settings(server)),
    )

    adapter._tls_starts[key] = attempt
    try:
        failures = await adapter.generation.dispatch('quic_start_server', data)
    finally:
        # SNI is the sole supported descriptor mutation. QUIC offer settings
        # belong to data.settings; observations on either leg stay read-only.
        snapshots[1][2]['sni'] = server.sni
        reject_tls_changes(snapshots)
    if failures:
        raise AddonRuntimeError('QUIC start callback failed')
    if (data.ssl_conn is not ssl_view or data.conn is not server
            or data.context is not context or data.is_dtls
            or context.client is not registered.client or context.server is not server):
        raise AddonRuntimeError('QUIC start cannot replace native transport objects')
    if server.address != target:
        server.address = target
        raise AddonRuntimeError('QUIC start cannot reroute the native transport')
    if server.error:
        draft.decision = TlsDecision.TERMINATE
        return draft.publish(draft.commit())

    # Only offer mutations can cross back into the native transport. Certificate
    # ownership and trust policy remain outside this hook's supported surface.
    settings = data.settings
    if not isinstance(settings, QuicTlsSettings):
        raise AddonRuntimeError('QUIC start requires QuicTlsSettings')
    if (settings.certificate is not None or settings.certificate_chain
            or settings.certificate_private_key is not None
            or settings.ca_path is not None or settings.ca_file is not None
            or settings.verify_mode is not None):
        raise AddonRuntimeError('QUIC certificates and trust policy remain native')

    # The adapter translates mitmproxy defaults and cipher IDs. Shared native
    # drafts own validation, immutable snapshots and response publication.
    if settings.alpn_protocols is not None:
        if not isinstance(settings.alpn_protocols, list) or any(
            not isinstance(value, str) for value in settings.alpn_protocols
        ):
            raise AddonRuntimeError('Native QUIC requires one ALPN protocol')
        draft.alpn_offers = [value.encode('ascii') for value in settings.alpn_protocols]
    if server.sni is not None:
        draft.sni = server.sni

    draft.openssl_ciphersuites = None
    if settings.cipher_suites is not None:
        if not isinstance(settings.cipher_suites, list):
            raise AddonRuntimeError('QUIC cipher_suites must be a list')
        try:
            draft.openssl_ciphersuites = ':'.join(CIPHERS[value] for value in settings.cipher_suites)
        except (KeyError, TypeError) as error:
            raise AddonRuntimeError('Unsupported QUIC TLS cipher suite') from error

    try:
        result = draft.commit()
    except ValueError as error:
        raise AddonRuntimeError(str(error)) from error
    return draft.publish(result)
