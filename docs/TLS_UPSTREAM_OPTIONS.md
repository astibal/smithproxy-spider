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
