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

Client-side TLS settings, cipher configuration, TLS-version overrides, SSL object
replacement and forced handshake ordering remain unsupported. They are not
silently translated into native settings by this patch.
