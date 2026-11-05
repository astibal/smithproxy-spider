# TLS session resumption and hooks

Resumption creates a new transport connection using previously negotiated TLS
session material. It does not reuse the old Spider Client/Server objects or
suppress the new connection's lifecycle hooks. Downstream and upstream resume
independently; success on one leg is not evidence of reuse on the other.

## Hook contract

For each new connection, normal TCP lifecycle events still apply. An explicitly
subscribed TLS start hook runs for a resumed handshake as well as a full one.
Each successful leg emits one established event with that connection's attempt
identity. The same addon generation can observe several consecutive connections,
but each connection has its own identity.

Changing upstream SNI in the start hook invalidates the selected cached session
and requires a full upstream handshake. This does not invalidate the independent
client-facing session. Certificate validation and native cache eligibility remain
native decisions; addons do not receive a live SSL object or session ticket.

Do not infer resumption from a short handshake, callback count or matching
certificate. The integration test checks `session_reused` independently on its
origin and client TLS sockets. It does not claim an addon-visible resumption flag.

## Integration test

```sh
python3 tests/connect_proxy_integration.py --resumption-only \
  --proxy /path/to/smithproxy --spider /path/to/smithproxy-spider \
  --native-source /path/to/smithproxy-source \
  --fixture /path/to/smithproxy-source/etc/smithproxy.cfg
```

The fixture uses a disposable trusted CA and origin certificate, with certificate
and hostname verification enabled. OCSP and CT are disabled for this isolated
origin. It retains each TLS context across three orderly connections, including
TLS close notifications, and keeps the proxy and addon generation alive.

The matrix covers TLS 1.2 and TLS 1.3, with start subscriptions disabled and enabled:

| Case | Upstream handshakes | Client-facing handshakes |
|---|---|---|
| Baseline | full, resumed, resumed | full, resumed, resumed |
| Subscribed; third start changes SNI | full, resumed, full | full, resumed, resumed |

The test also checks lifecycle event counts, per-leg start-before-established
ordering, attempt identity and successful webhook delivery. A missing upstream
resume fails the test even when the client-facing leg resumes correctly.

This test does not cover QUIC resumption, 0-RTT, cache expiry, ticket rotation,
certificate changes or resumed STARTTLS. Those are separate coverage areas.

## Native TLS 1.3 cache prerequisite

The client OpenSSL context must enable `SSL_SESS_CACHE_CLIENT` alongside
`SSL_SESS_CACHE_NO_INTERNAL`. The former enables new-session callbacks; the
latter keeps storage in Smithproxy's external cache. Without the client flag,
our integration baseline resumed TLS 1.2 but never resumed upstream TLS 1.3.
The independent downstream leg resumed in both versions.

With the client flag enabled, all four matrix cases passed, including SNI
mutation forcing a fresh upstream handshake in both TLS versions. This is a
native cache fix, not a change to hook ordering or handshake scheduling.
