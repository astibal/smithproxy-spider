# ClientHello upstream options

This follow-up extends the explicitly subscribed native ClientHello callback.
An addon can set `data.context.server.sni` and `data.context.server.alpn_offers`
before the native upstream SSL object is initialized.

The observation includes an `upstream` object with `sni` and `alpn_base64` (the
length-prefixed ALPN wire list). These are effective native defaults, including
routing SNI and the ALPN-block policy. Older producers omit this object; their
addons continue to receive an explicit error when attempting these mutations.
Older receivers may omit it from their reply, preserving native defaults.

SNI changes accept DNS names, with IDNA normalization in the adapter. IP literals
and malformed names are rejected. `None` retains the native default; an empty
string omits SNI. The existing native certificate verification uses the updated
upstream identity (or the target IP when SNI is absent). The client-facing name
and SNI-based bypass policy retain the original ClientHello identity.

ALPN changes may narrow or reorder the effective native offer. Each identifier
must be bytes, 1–255 bytes long, and the total encoded offer must fit 65535 bytes.
An empty list retains defaults, following the reference's unspecified-offer
behavior. This patch does not introduce protocol translation and cannot enable
ALPN when the native policy blocks it.

Deployments run in their existing order; later participants receive earlier
participants' accepted upstream settings. Only a complete successful response
can update native settings. Invalid SNI/ALPN cannot cause a partial update, and
veto or bypass takes precedence. Existing strict/fail-open behavior is retained.

Client-side TLS settings, TLS-version overrides, SSL object
replacement and forced handshake ordering remain unsupported. They are not
silently translated into native settings by this patch.

## Upstream cipher expressions

When the native upstream object includes `openssl_cipher_list`, the adapter
supports `data.context.server.cipher_list` at the ClientHello boundary. Spider
joins a nonempty list/tuple of strings with colons, preserving OpenSSL operators
and ordering. It does not filter the expression against native cipher policy.
The wire contains an OpenSSL string, never addon-specific cipher semantics.

An empty list/tuple or None means unspecified, retaining native defaults. This
matches the reference's default-selection behavior, but defaults themselves
remain Smithproxy's configuration rather than mitmproxy's built-in cipher list.
A nonempty list containing an empty string produces an explicit empty expression;
OpenSSL rejects it. Unknown names and expressions selecting no legacy cipher
also fail initialization, with the existing TLS failure observation and log.
There is no retry with the original cipher policy after an OpenSSL rejection.
Malformed control replies retain the existing fail-open/strict transport policy.

The pinned mitmproxy 12.3.1 TCP implementation calls `set_cipher_list`, so this
field controls TLS 1.2 and earlier only. It does not select TLS 1.3 suites, change
protocol-version bounds, or replace an SSL context. A TLS 1.3 cipher name alone
is therefore an invalid legacy expression, as in the reference. Native TLS 1.3
policy remains separate. This bridge still does not implement tls_start_server
as a live SSL-context replacement hook.

Each participating deployment receives an earlier accepted expression; an empty
list can return to native defaults. Producers without the capability field keep
rejecting cipher-list mutations explicitly. The native transport stores an
override only for subscribed handshakes that actually request one.

## Upstream start interception

A content addon deployment may explicitly enable `tls_start_server: true`.
This subscription is independent of ClientHello, defaults to false, and also
covers hooks registered dynamically after setup. Native code invokes it once
before the first upstream TCP TLS handshake call, after creating the SSL object.
The existing TLS lifecycle envelope uses `side: server`, `event: start`, and the
same attempt identity as its later outcome. Downstream start, DTLS and QUIC are
not enabled by this subscription.

### Ordering

Before dispatching `tls_start_server`, Smithproxy checks the existing TCP
readiness observation. If TCP has connected since the previous observation,
it delivers the missing `server_connected` first, without duplicating it.
This does not delay TLS, change socket monitoring, or fabricate a connection.
If TCP is still pending at the native start boundary, the native order remains:
`tls_start_server` may precede `server_connected`. The shared descriptor reflects
only confirmed TCP metadata. Exact reference ordering is not guaranteed in that
case; transport scheduling takes precedence over addon compatibility.

The callback receives `TlsData`: `conn` is the shared upstream descriptor,
`context` retains both sides, and `ssl_conn` is the explicit unsupported-operation
sentinel. Passing the event is valid; using live SSL methods or replacing
`ssl_conn` fails the callback. This is not support for arbitrary PyOpenSSL code.

The addon may change `conn.sni`, `conn.alpn_offers`, and `conn.cipher_list` using
the same native semantics described above, or set `conn.error` to veto. Accepted
offers pass through deployments in order. Invalid/unavailable control replies
retain the existing strict/fail-open policy. OpenSSL rejection terminates the
handshake and logs a warning, without retrying native defaults.

Changes apply only to the connection's SSL object. A changed offer clears the
session previously selected for resumption; unchanged offers preserve it.
Shared SSL contexts, protocol bounds, verification policy and TLS 1.3 suites
are unchanged. Certificate verification uses the accepted upstream identity.

## Client-facing start interception

A content addon deployment may independently enable `tls_start_client: true`.
It defaults to false and includes hooks registered dynamically after setup.
Smithproxy uses the existing Socle callback immediately before the first
`SSL_accept`, without changing TCP readiness, certificate selection or native
handshake scheduling. DTLS and QUIC remain outside this subscription.

The hook receives `TlsData` with the shared client descriptor, both sides in
`context`, and the same unsupported-operation `ssl_conn` sentinel as upstream
start. Available SNI is an observation; negotiated values and the establishment
timestamp still belong to the later outcome. Setting `data.conn.error` vetoes
the handshake through the existing native termination path and warning.
Changes to TLS parameters on either descriptor, live SSL operations, replacement
of the SSL sentinel, and rerouting are rejected explicitly. This hook does not
configure a certificate or replace the native SSL context.

Each side reserves its own start attempt and shares that identity with its later
outcome. Native nesting can deliver client start before the upstream established
observation is sampled. This bridge preserves that native order; it does not
reschedule either handshake to reproduce a universal cross-side ordering.
