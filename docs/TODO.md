# TODO

## Scripting

- **Protocol state API:** opt-in H1/H2 snapshots now use bounded, host-owned
  connection checkpoints and native hold provenance. Next, consume these views
  in header-hook interception and audit observations for remaining protocols;
  do not invent transport states. See `PROTOCOL_STATE_API_PROPOSAL.md` for the
  implemented boundary and broader design.

- **Opaque coverage diagnostics (after the state API):** discuss receive-byte
  accounting for recognized Parts, Opaque ranges and pending reassembly. Count
  original bytes once, not nested views, replacements or resumed data. Preserve
  bounded offset/length/reason diagnostics without logging payloads by default.
  This is a separate deferred task, not part of state integration.

- **Flow suspension coverage:** completed H2 request/response interception now
  uses retained logical Parts in native Translate. Resume or kill is published
  on a subsequent callback of the owning connection, from either direction;
  hooks are not replayed. Extend coverage to header-hook and generated-response
  interception, then scope H1 and raw transport suspension. Keep the remaining
  gaps explicit and compare new behavior against the reference. The current
  contract is in `FLOW_SUSPENSION_API_PROPOSAL.md`.
  Idle wakeup and a possible downstream signaling channel are deliberately
  deferred; do not add a Smithproxy timer, management API endpoint or persistent
  channel as part of the callback-driven implementation.

- **mitmproxy server lifecycle:** add truthful `server_connect`,
  `server_connected`, `server_connect_error` and `server_disconnected` hooks once
  Smithproxy publishes ordered target-selected, upstream-connected,
  upstream-connect-failed and upstream-disconnected observations. Preserve one
  Server object per upstream connection and verify synchronous hook ordering
  against the mitmproxy 12.3.1 reference corpus. Do not synthesize these events
  from connection setup in the meantime. The detailed integration contract is
  recorded in `docs/ADDON_COMPATIBILITY.md`.
- **HTTP CONNECT producer (cross-project approval required):** review
  `HTTP_CONNECT_PRODUCER_PROPOSAL.md`. Separate mitmproxy 12.3.1 wire corpora
  now fix regular success/failure, the lazy upstream-proxy lifecycle and
  ordinary local-response/kill/reroute/outcome-mutation behavior. A fourth
  corpus fixes built-in proxy-authentication ordering and request sanitization.
  A fifth fixes the late, non-live upstream hook: only authority mutation is
  transport-effective, while kill raises and local response replacement is too
  late. The reference lifecycle evidence is complete. A dormant Spider adapter
  now preserves flow/server identity, validates sequence and returns only the
  proven decisions with full branch coverage; native producer integration
  remains implementation work. Until its wire gates pass,
  recognized `http_connect*` and `http_connected` hooks must fail deployment
  rather than load as inert callbacks.
- **Raw TCP/UDP producer (cross-project approval required):** review
  `RAW_TRANSPORT_PRODUCER_PROPOSAL.md`. The basic transport corpora and the new
  control corpus fix message history, mutation, empty TCP-chunk suppression,
  zero-length UDP datagrams and the surprising state-only raw flow controls of
  mitmproxy 12.3.1. The Spider adapter matches those observations;
  Smithproxy still needs to publish the strict setup/content/terminal envelope
  and preserve UDP datagram boundaries before live hooks may be enabled.
- **SOCKS5 authentication producer (cross-project approval required):** review
  `SOCKS5_AUTH_PRODUCER_PROPOSAL.md`. A reference wire corpus proves that the
  hook may override the built-in auth policy in either direction and that
  arbitrary credential bytes use escaped text. Until the producer is complete,
  `socks5_auth` must remain fail-closed at registration. The dormant
  Spider-side decision adapter is implemented with full branch coverage;
  native producer integration remains approval-gated.
- **WebSocket producer (cross-project approval required):** review
  `WEBSOCKET_PRODUCER_PROPOSAL.md`. Phase 1 delivers complete logical messages
  through synchronous pass/replace/drop decisions while Smithproxy retains
  framing, fragmentation, masking and compression ownership. Treat active
  message injection as a separate authorized host command after the ordinary
  producer passes its wire gates. Do not approximate WebSocket callbacks with
  raw TCP chunks. The dormant Spider-side envelope/lifecycle adapter is
  implemented with full branch coverage. Two real HTTP/1 wire corpora now
  cover the basic lifecycle plus bidirectional fragmentation, control-frame
  interleaving, text/binary/empty replacement, explicit drop, clean and abrupt
  termination, bidirectional invalid text, kill state and negotiated
  permessage-deflate. Valid compressed fragmentation is observed to close with
  1007 in mitmproxy 12.3.1; choose explicitly whether compatibility mode keeps
  that boundary or accepts Smithproxy's complete logical message. Native
  concurrent-producer backpressure and producer-failure gates remain. Native
  producer integration remains
  approval-gated and the loader continues to reject live WebSocket hooks.
- **DNS producer (cross-project approval required):** review
  `DNS_PRODUCER_PROPOSAL.md`. Smithproxy must explicitly classify complete DNS
  messages and retain UDP/TCP transport ownership; Spider may convert only
  complete units through its existing clean-room model. Real UDP corpora now
  cover both a local response and forwarded request/response mutation through
  a local resolver. An unreachable resolver is also fixed as a synthesized
  SERVFAIL through `dns_response`, not `dns_error`. A real TCP corpus covers a
  split length prefix, split payload and two pipelined messages on one client
  connection, with one independent flow per complete message. A concurrent UDP
  corpus also proves that equal DNS IDs and nondeterministic completion order do
  not merge flows or cross response mutations. Malformed UDP evidence fixes
  empty, truncated, compression-loop and trailing-byte input as pre-hook drops.
  Local NXDOMAIN-to-REFUSED mutation proves the local error lifecycle and zero
  resolver contact. A complex compressed message covers two questions, every
  section, non-default flags and deterministic normalized output.
  A dedicated control corpus fixes the DNS-specific `flow.kill()` contract:
  request kill without a response synthesizes SERVFAIL without a response hook
  or resolver contact, while an existing local or upstream response still
  reaches the client after response-hook kill.
  Do not infer DNS from ports or route arbitrary UDP through DNS hooks. The dormant Spider-side lifecycle adapter is
  implemented with full branch coverage; native producer integration remains
  approval-gated and the loader continues to reject live DNS hooks.
- **Destination routing (approval required):** review
  `DESTINATION_ROUTING_API_PROPOSAL.md`. The successful HTTP/1 reference corpus
  is recorded, but implementation needs an atomic Spider control result and a
  Smithproxy-owned upstream-selection boundary. Verify actual per-stream H2
  ownership before approving code changes in either project.
- **Hold + fail-open (deliberately deferred):** after `need-more`, only Spider
  owns earlier bytes. Spider/proxy failure, timeout, queue overload or deployment
  changes can release the current fragment without the held prefix. Protect order
  and completeness for HOLD/REWRITE as well as TRANSLATE; retain fail-open for now.
  Design strict/drop control and data ownership recovery/acknowledgement, not just
  disk-backed buffers. Also cover disable/redeploy, filter changes, automatic
  suspension, idle expiry, limits and connection termination while holding data.
- Extend live hold from the last enabled flow deployment to any position in the
  chain; resolve prefix transactions and rollback between scripts.
- Extend typed H1 Parts to start lines or headers split across producer
  callbacks. Keep parsing ownership in Smithproxy annotations instead of
  adding a second HTTP parser in Spider. Chunked and compressed bodies,
  pipelining, and H2 frame headers split across callbacks are covered already.
- Implement true incremental HTTP streaming in the two phases described by
  `STREAMING_API_PROPOSAL.md`: structured producer completion observations for
  pass-through first, then a generic native callback-local transform operation.
  Do not replace either phase with complete-message buffering.

- Stabilize a richer, typed Python API without exposing raw webhook JSON.
- Add a browsable cookbook ranging from simple payload logging to stateful session analysis.
- Support replaying complete captured sessions through scripts.
- Add explicit script capabilities and separate observe, transform, control, and offline modes.
- Persist backend inspection deployments and traffic rules across server restarts; introduce reusable Python workers after measuring per-callback process overhead.
