"""QUIC parent handshakes, separate from HTTP/3 stream inspection."""

import base64

from addon_proxy_context import Context
from addon_clienthello_native import tls_settings, reject_tls_changes
from addon_quic import QuicTlsData, QuicTlsSettings
from addon_runtime import AddonRuntimeError
from addon_tls_native import NativeSSLUnavailable, dispatch as dispatch_outcome


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
        observed = dict(observation)
        observed['alpn_base64'] = base64.b64encode(
            observation.get('alpn', '').encode('ascii')).decode('ascii')
        return await dispatch_outcome(adapter, observed)

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
    offer = observation['upstream']
    server = registered.server
    server.sni = offer['sni']
    server.tls = True
    context = Context(registered.client, adapter.generation.options)
    context.server = server
    cipher_suites = None
    expression = offer.get('ciphers')
    if expression is not None:
        reverse = {name: value for value, name in CIPHERS.items()}
        try:
            cipher_suites = [reverse[name] for name in expression.split(':')] if expression else []
        except (KeyError, AttributeError) as error:
            raise AddonRuntimeError('Invalid native QUIC cipher expression') from error

    settings = QuicTlsSettings(alpn_protocols=[offer['alpn']], cipher_suites=cipher_suites)
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
        return {'proceed': False}

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

    # Normalize the supported settings into the native wire representation.
    # None keeps the current SNI/ALPN; an explicit empty cipher list stays empty.
    protocols = settings.alpn_protocols
    if protocols is None:
        protocols = [offer['alpn']]
    if (not isinstance(protocols, list) or len(protocols) != 1
            or not isinstance(protocols[0], str) or not 1 <= len(protocols[0].encode('ascii')) <= 255):
        raise AddonRuntimeError('Native QUIC requires one ALPN protocol')
    sni = offer['sni'] if server.sni is None else server.sni
    if not isinstance(sni, str) or '\0' in sni:
        raise AddonRuntimeError('Invalid QUIC SNI')
    sni = sni.encode('idna').decode('ascii') if sni else ''
    if len(sni) > 255:
        raise AddonRuntimeError('Invalid QUIC SNI')

    ciphers = None
    if settings.cipher_suites is not None:
        if not isinstance(settings.cipher_suites, list):
            raise AddonRuntimeError('QUIC cipher_suites must be a list')
        try:
            ciphers = ':'.join(CIPHERS[value] for value in settings.cipher_suites)
        except (KeyError, TypeError) as error:
            raise AddonRuntimeError('Unsupported QUIC TLS cipher suite') from error

    return {'proceed': True, 'upstream': {
        'sni': sni, 'alpn': protocols[0], 'ciphers': ciphers,
    }}
