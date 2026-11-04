"""One synchronous ClientHello decision before native TLS startup."""

import base64
import ipaddress
import re

from addon_proxy_context import Context
from addon_runtime import AddonRuntimeError
from addon_tls import ClientHello, ClientHelloData


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
        raise AddonRuntimeError('Native ClientHello cannot change ' + ', '.join(changed))


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


def upstream_reply(server, original):
    # None/empty offers retain native defaults, as the reference tlsconfig
    # fills in unspecified values. An empty SNI string explicitly omits SNI.
    sni = original[0] if server.sni is None else server.sni
    if not isinstance(sni, str):
        raise AddonRuntimeError('Upstream SNI must be a hostname')
    if sni != original[0] and sni:
        try:
            sni = sni.encode('idna').decode('ascii')
        except UnicodeError as error:
            raise AddonRuntimeError('Invalid upstream SNI hostname') from error

        try:
            ipaddress.ip_address(sni)
        except ValueError:
            pass
        else:
            raise AddonRuntimeError('Upstream SNI cannot be an IP literal')

        labels = sni.removesuffix('.').split('.')
        if len(sni) > 253 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
                                 for label in labels):
            raise AddonRuntimeError('Invalid upstream SNI hostname')

    offers = server.alpn_offers
    if not isinstance(offers, (list, tuple)):
        raise AddonRuntimeError('Upstream ALPN offers must be a list or tuple')
    offers = tuple(offers) or original[1]
    if any(not isinstance(value, bytes) or not 1 <= len(value) <= 255
           or value not in original[1] for value in offers):
        raise AddonRuntimeError('Upstream ALPN must select from the native offer')

    wire = b''.join(bytes([len(value)]) + value for value in offers)
    if len(wire) > 65535:
        raise AddonRuntimeError('Upstream ALPN offer is too large')

    server.sni = sni
    server.alpn_offers = offers
    return {'sni': sni, 'alpn_base64': base64.b64encode(wire).decode('ascii')}


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

    decision = {
        'proceed': not bool(registered.client.error),
        'ignore_connection': data.ignore_connection,
    }
    if upstream is not None and decision['proceed'] and not data.ignore_connection:
        decision['upstream'] = upstream_reply(registered.server, upstream)
        if allow_ciphers:
            decision['upstream']['openssl_cipher_list'] = cipher_reply(registered.server.cipher_list)

    return decision
