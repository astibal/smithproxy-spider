"""Native TLS outcomes with shared descriptors and explicit SSL limitations.

These are delayed handshake observations, not interception points. The native
transport owns OpenSSL; no live SSL object crosses the worker boundary.
"""

import base64
import time

from addon_certs import Cert
from addon_proxy_context import Context
from addon_runtime import AddonRuntimeError
from addon_tls import TlsData


HOOKS = frozenset({
    'tls_established_client',
    'tls_established_server',
    'tls_failed_client',
    'tls_failed_server',
})


class NativeSSLUnavailable:
    """Reject live OpenSSL operations instead of pretending to implement them."""

    def __getattr__(self, name):
        raise AddonRuntimeError(
            'Native TLS callbacks expose connection metadata, not live ssl_conn operations'
        )


def optional_text(observation, name, limit):
    value = observation.get(name)
    if value is not None and (not isinstance(value, str) or len(value) > limit):
        raise AddonRuntimeError('Invalid TLS metadata: ' + name)
    return value


async def dispatch(adapter, observation):
    envelope = observation['envelope']
    identity = adapter._identity(envelope['connection_id'])
    attempt = envelope['attempt']
    side = envelope['side']
    event = envelope['event']
    if (
        type(envelope.get('version')) is not int
        or envelope['version'] != 1
        or type(attempt) is not int
        or attempt < 1
        or side not in ('client', 'server')
        or event not in ('established', 'failed')
    ):
        raise AddonRuntimeError('Invalid TLS lifecycle envelope')

    registered = adapter._connections.get(identity)
    if registered is None:
        raise AddonRuntimeError('TLS outcome requires an existing addon setup')

    key = (identity, side)
    previous = adapter._tls.get(key)
    if previous is not None and attempt <= previous:
        raise AddonRuntimeError('Duplicate or stale TLS outcome')

    # Validate the complete observation before modifying shared descriptors.
    sni = optional_text(observation, 'sni', 255)
    cipher = optional_text(observation, 'cipher', 256)
    version = optional_text(observation, 'tls_version', 32)
    error = optional_text(observation, 'error', 1024)
    encoded_alpn = optional_text(observation, 'alpn_base64', 344)
    alpn = None
    if encoded_alpn is not None:
        alpn = base64.b64decode(encoded_alpn, validate=True)
        if len(alpn) > 255:
            raise AddonRuntimeError('Invalid negotiated ALPN')
    if event == 'failed' and not error:
        raise AddonRuntimeError('TLS failure requires an error')

    certificate_values = observation.get('certificates', [])
    if (not isinstance(certificate_values, list) or len(certificate_values) > 64
            or any(not isinstance(value, str) or len(value) > 65536
                   for value in certificate_values)):
        raise AddonRuntimeError('Invalid peer certificate chain')
    certificates = tuple(Cert.from_pem(value.encode('ascii')) for value in certificate_values)

    conn = registered.client if side == 'client' else registered.server
    conn.tls = True
    conn.certificate_list = certificates
    conn.sni = sni
    conn.alpn = alpn
    conn.cipher = cipher
    conn.tls_version = version
    conn.timestamp_tls_setup = time.time() if event == 'established' else None
    conn.error = error or None

    context = Context(registered.client, adapter.generation.options)
    context.server = registered.server
    ssl_view = NativeSSLUnavailable()
    data = TlsData(conn, context, ssl_conn=ssl_view)

    # Reserve before dispatch: a failing addon must not replay a callback.
    adapter._tls[key] = attempt
    target = registered.server.address
    failures = await adapter.generation.dispatch('tls_' + event + '_' + side, data)
    if failures:
        raise AddonRuntimeError('TLS lifecycle callback failed')

    if data.ssl_conn is not ssl_view:
        raise AddonRuntimeError('Native TLS callbacks cannot replace ssl_conn')

    if registered.server.address != target:
        registered.server.address = target
        raise AddonRuntimeError('TLS callbacks cannot reroute an established transport')

    return {'proceed': event == 'failed' or not bool(conn.error)}
