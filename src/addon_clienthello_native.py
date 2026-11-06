"""One synchronous ClientHello decision before native TLS startup."""

import base64

from addon_proxy_context import Context
from addon_runtime import AddonRuntimeError
from addon_tls import ClientHello, ClientHelloData
from inspection_tls import TlsView, TlsDecision


def tls_settings(connection):
    # Copy sequence values as well: an addon may modify a list in place.
    fields = ('tls', 'sni', 'alpn', 'alpn_offers', 'cipher', 'cipher_list', 'tls_version')
    settings = {}
    for name in fields:
        value = getattr(connection, name)
        settings[name] = tuple(value) if isinstance(value, list) else value

    return settings


def reject_tls_changes(snapshots, allow_upstream=False, allow_ciphers=False):
    changed = []
    for side, connection, previous in snapshots:
        current = tls_settings(connection)
        for name, value in previous.items():
            if allow_upstream and side == 'server' and name in ('sni', 'alpn_offers'):
                continue
            if allow_ciphers and side == 'server' and name == 'cipher_list':
                continue
            if current[name] != value:
                setattr(connection, name, value)
                changed.append(side + '.' + name)

    # Restore both descriptors before reporting any unsupported change.
    # These values are observations until the native bridge can apply them.
    if changed:
        raise AddonRuntimeError('Native TLS interception cannot change ' + ', '.join(changed))


def read_upstream(observation):
    settings = observation.get('upstream')
    if settings is None:
        return None

    if not isinstance(settings, dict) or not isinstance(settings.get('sni'), str):
        raise AddonRuntimeError('Invalid native upstream settings')
    encoded = settings.get('alpn_base64')
    if not isinstance(encoded, str) or len(encoded) > 87380:
        raise AddonRuntimeError('Invalid native ALPN offer')

    raw = base64.b64decode(encoded, validate=True)
    offers = []
    offset = 0
    while offset < len(raw):
        length = raw[offset]
        offset += 1
        if not length or offset + length > len(raw):
            raise AddonRuntimeError('Invalid native ALPN protocol')
        offers.append(raw[offset:offset + length])
        offset += length

    return settings['sni'], tuple(offers)


def cipher_reply(value):
    # mitmproxy's TCP TLS configuration treats an empty list as unspecified.
    # Nonempty lists are joined verbatim: OpenSSL owns expression semantics.
    if value is None or value == [] or value == ():
        return None
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise AddonRuntimeError('Upstream cipher_list must be a list or tuple of strings')

    expression = ':'.join(value)
    if '\0' in expression or len(expression.encode('utf-8')) > 65535:
        raise AddonRuntimeError('Invalid OpenSSL cipher expression')

    return expression


async def dispatch(adapter, observation):
    envelope = observation['envelope']
    identity = adapter._identity(envelope['connection_id'])
    attempt = envelope['attempt']
    if (
        type(envelope.get('version')) is not int
        or envelope['version'] != 1
        or type(attempt) is not int
        or attempt < 1
        or envelope.get('side') != 'client'
        or envelope.get('event') != 'client-hello'
    ):
        raise AddonRuntimeError('Invalid ClientHello envelope')

    registered = adapter._connections.get(identity)
    if registered is None:
        raise AddonRuntimeError('ClientHello requires an existing addon setup')

    previous = adapter._tls_hellos.get(identity)
    if previous is not None and attempt <= previous:
        raise AddonRuntimeError('Duplicate or stale ClientHello')

    try:
        draft = TlsView.from_observation(observation).client_hello
    except (ValueError, TypeError) as error:
        raise AddonRuntimeError(str(error)) from error

    encoded = observation.get('client_hello_base64')
    if not isinstance(encoded, str) or not encoded or len(encoded) > 512 * 1024:
        raise AddonRuntimeError('Invalid ClientHello body')

    hello = ClientHello(base64.b64decode(encoded, validate=True))
    # Match the public ClientHello boundary: parsed offers already belong to
    # the shared client descriptor, while no TLS result has been published yet.
    registered.client.sni = hello.sni
    registered.client.alpn_offers = tuple(hello.alpn_protocols)
    upstream = read_upstream(observation)
    if upstream is not None:
        registered.server.sni, registered.server.alpn_offers = upstream

    native_settings = observation.get('upstream') or {}
    allow_ciphers = 'openssl_cipher_list' in native_settings
    if allow_ciphers:
        expression = native_settings['openssl_cipher_list']
        if expression is not None and not isinstance(expression, str):
            raise AddonRuntimeError('Invalid native OpenSSL cipher expression')

        # Carry earlier deployments' accepted settings into this addon.
        if expression is not None:
            registered.server.cipher_list = expression.split(':')

    snapshots = (
        ('client', registered.client, tls_settings(registered.client)),
        ('server', registered.server, tls_settings(registered.server)),
    )

    context = Context(registered.client, adapter.generation.options)
    context.server = registered.server
    data = ClientHelloData(context, hello)
    target = registered.server.address

    # Reserve before calling user code, just like the terminal TLS observations.
    # No SSL object or borrowed native memory crosses this boundary.
    adapter._tls_hellos[identity] = attempt
    try:
        failures = await adapter.generation.dispatch('tls_clienthello', data)
    finally:
        reject_tls_changes(snapshots, allow_upstream=upstream is not None, allow_ciphers=allow_ciphers)

    if failures:
        raise AddonRuntimeError('ClientHello callback failed')

    if registered.server.address != target:
        registered.server.address = target
        raise AddonRuntimeError('ClientHello cannot reroute the native transport')

    if (data.context is not context or data.client_hello is not hello
            or context.client is not registered.client or context.server is not registered.server):
        raise AddonRuntimeError('ClientHello cannot replace native context or handshake data')

    if type(data.ignore_connection) is not bool or type(data.establish_server_tls_first) is not bool:
        raise AddonRuntimeError('ClientHello decisions must be booleans')

    # Native scheduling is unchanged. Do not pretend that a remote addon can
    # already force the order in which the two OpenSSL handshakes are driven.
    if data.establish_server_tls_first:
        raise AddonRuntimeError('Native ClientHello cannot override TLS handshake ordering')

    # Compatibility mutations enter the same native draft/commit path as
    # first-class scripts. Only addon-specific default semantics live here.
    if registered.client.error:
        draft.decision = TlsDecision.TERMINATE
    elif data.ignore_connection:
        draft.decision = TlsDecision.BYPASS

    if upstream is not None and draft.decision is TlsDecision.CONTINUE:
        draft.sni = upstream[0] if registered.server.sni is None else registered.server.sni
        if not isinstance(registered.server.alpn_offers, (list, tuple)):
            raise AddonRuntimeError('Upstream ALPN offers must be a list or tuple')
        draft.alpn_offers = registered.server.alpn_offers or upstream[1]
        if allow_ciphers:
            draft.openssl_cipher_list = cipher_reply(registered.server.cipher_list)

    try:
        result = draft.commit()
    except (ValueError, TypeError) as error:
        raise AddonRuntimeError(str(error)) from error

    if upstream is not None:
        registered.server.sni = result.sni
        registered.server.alpn_offers = result.alpn_offers
    reply = draft.publish(result)
    if not allow_ciphers and 'upstream' in reply:
        reply['upstream'].pop('openssl_cipher_list', None)
    return reply
