# Native ClientHello subscription

A content deployment using the `mitmproxy` script API can set
`"tls_clienthello": true`. The default is false; an omitted field preserves the
existing value when updating a deployment. The option is independent of hook
introspection, so dynamically registered addon hooks remain supported.

Successful connection setup advertises `control.tls_clienthello = 1` if at least
one participating deployment requested it. Only those existing setup owners
receive ClientHello. A replacement deployment cannot adopt an older session.
The native observer is disabled unless this capability was negotiated.

The version-1 `tls-lifecycle` envelope adds `event: "client-hello"`, with
`side: "client"` and the same attempt identity as the subsequent client TLS
outcome. `client_hello_base64` contains the complete ClientHello body, without
TLS record or handshake headers. Socle normalizes fragments before dispatch.
This boundary currently covers TLS over TCP, not DTLS or QUIC.

The adapter dispatches `tls_clienthello(ClientHelloData)` using shared client
and server descriptors. Parsed SNI and ALPN offers are already on the client.
No native pointers or live OpenSSL objects cross the worker boundary.

Supported decisions:

- Leave the data unchanged to continue with native TLS scheduling.
- Set `ignore_connection = True` to bypass TLS interception on both sides.
- Set `data.context.client.error` to a nonempty string to terminate the attempt.

The reply echoes action, connection ID and envelope, plus boolean `proceed`
and `ignore_connection`. A veto wins over bypass; bypass requests from the
participating deployments are combined. No partial decision is applied when
a reply is malformed or a participant is unavailable. The native fallback is
fail-open, or terminate when strict control was negotiated.

Replacing the context/ClientHello, changing the target or unsupported TLS settings
(client-side settings, TLS flag or version),
and setting `establish_server_tls_first = True` are unsupported and rejected.
This patch does not provide SSL-context replacement or handshake scheduling
control. A callback failure follows the existing addon invalidation policy.

Validation includes native CTest, Spider CTest, adapter decision tests and the
live CONNECT/TLS integration fixture on Rhino. The live cases cover disabled
subscription, TLS 1.2/1.3, fragmented ClientHello, bypass with the origin's real
certificate, veto before upstream TLS bytes, and malformed replies in regular
and strict modes. These suites are not the full P3 corpus.

ClientHello.raw_bytes(wrap_in_record=False) returns the unwrapped handshake body;
the default remains a synthetic TLS record. DTLS raw_bytes remains unsupported,
matching the pinned reference. Unsupported TLS setting changes are restored on
both shared descriptors before the callback error is reported.

A bounded subset of upstream mutations is supported when
native `upstream` defaults are present. See [TLS_UPSTREAM_OPTIONS.md](TLS_UPSTREAM_OPTIONS.md)
for SNI, ALPN, policy constraints and compatibility with older producers.
