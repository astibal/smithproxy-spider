"""Native TLS outcomes with shared descriptors and explicit SSL limitations.

These are delayed handshake observations, not interception points. The native
transport owns OpenSSL; no live SSL object crosses the worker boundary.
"""

import time

from addon_certs import Cert
from addon_proxy_context import Context
from addon_runtime import AddonRuntimeError
from addon_tls import TlsData
from inspection_tls import TlsView, TlsDecision, TlsTransport
from inspection_tls_outcome import optional_text


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



async def dispatch(adapter, observation, *, transport=TlsTransport.TLS):
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

    # Native scripts and addons consume the same validated observation.
    view = TlsView.from_observation(observation, transport)
    outcome = view.outcome
    certificates = tuple(Cert.from_pem(value) for value in outcome.certificates)

    conn = registered.client if side == 'client' else registered.server
    conn.tls = True
    conn.certificate_list = certificates
    conn.sni = outcome.sni
    conn.alpn = outcome.alpn
    conn.cipher = outcome.cipher
    conn.tls_version = outcome.tls_version
    conn.timestamp_tls_setup = time.time() if event == 'established' else None
    conn.error = outcome.error or None

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

    if event == 'established' and conn.error:
        outcome.decision = TlsDecision.TERMINATE
    return outcome.publish(outcome.commit())
