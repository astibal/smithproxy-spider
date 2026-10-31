# Native message termination design

Status: HTTP/1 and HTTP/2 are implemented and covered through Spider's native
transactions. HTTP/1 uses the approved callback-local Smithproxy capability and
strict close reply described below.

## Problem

An addon may call `flow.kill()` while a request or response hook is running.
The public action is protocol-neutral, but its transport result is not. The
checked HTTP/1 and multiplexed HTTP/2 corpora now cover all four HTTP hooks:

- HTTP/1 closes the client connection without sending an HTTP response;
- HTTP/2 resets only the selected stream with `INTERNAL_ERROR` and keeps the
  multiplexed connection available;
- killing from `requestheaders`, `request`, or `responseheaders` produces one
  later `error()` callback with `Connection killed.`;
- killing from the terminal `response` hook changes the flow state but does
  not produce a later `error()` callback.

The compatibility adapter can model the state change, but it cannot safely
produce either transport result. Closing an arbitrary socket in the facade
would lose protocol context. Injecting raw HTTP/2 bytes would bypass native
stream state, flow control and publication ordering.

## Proposed Spider operation

Expose one protocol-owned terminal decision on the current message:

```python
api.message.terminate(
    part,
    *,
    reason="Connection killed.",
    http2_error=2,  # INTERNAL_ERROR
)
```

This is a general Spider helper, not a mitmproxy-specific escape hatch. The
operation is available during a live H2 Translate transaction or typed H1
Rewrite transaction for an unpublished logical message. `part` must be that
message's interpreted initial header Part. Calling it stages a decision and
`translate()` or `commit()` publishes that decision atomically.

The method does not accept a connection ID or stream ID. The anchor Part owns
the group and, for HTTP/2, the stream. Requiring an object from the current
callback prevents a script from targeting unrelated traffic and also removes
an ambiguity when one native callback contains several multiplexed streams. A
second terminal decision for the same logical message is rejected. `reason` is
diagnostic state, never wire payload.

For HTTP/2 the anchor must contain exactly one initial `:method` or `:status`.
For HTTP/1 it must own one interpreted request or response group. Detached,
saved, already-published, opaque, trailer, and cross-message anchors fail before
the transaction checkpoint changes.

## Protocol ownership

For HTTP/2, Translate already owns stream state, cancelled ranges, queued DATA,
input ownership, reverse output, and WINDOW_UPDATE refunds. The new operation
is therefore an admission and staging API over that machinery, not a second
HTTP/2 engine.

Publication depends on the anchored direction:

- terminating a request suppresses the retained request and emits the reset in
  reverse, toward the client;
- terminating a response suppresses the retained response and emits the reset
  forward, also toward the client;
- both cases mark the stream cancelled in both native directional ledgers so
  later source DATA is discarded and credited without another wire reset.

Termination must:

1. discard unpublished replacement bytes for the selected stream;
2. suppress the selected logical header/body/trailer group before the output
   HPACK encoder observes it;
3. emit one client-facing `RST_STREAM(INTERNAL_ERROR)`;
4. retire only that stream;
5. preserve sibling streams, both HPACK contexts and connection windows;
6. ignore duplicate or late termination without emitting a second reset.

The HPACK distinction is essential. The source decoder must consume the input
header block because later source blocks may refer to it. The destination
encoder must not consume a header group that is never sent: doing so would make
later output depend on a dynamic-table entry the destination peer never saw.
This differs from a peer-originated reset received after output HEADERS were
already queued, where those encoded headers may still need to drain to preserve
the destination table. Local termination is known before assembly and must use
the earlier suppression boundary.

For HTTP/1, no request or response bytes from the terminated logical message
are emitted. The current Spider callback result cannot close the underlying
Smithproxy connection, so this path requires a small negotiated producer
capability. The capability should be scoped to the current callback connection
and carry only a terminal boolean plus a diagnostic reason. It must not expose
arbitrary socket handles or a generic close-by-ID control plane.

Spider must reject HTTP/1 termination before publication when the producer did
not negotiate that capability. It must not silently translate the action into
an empty replacement, synthetic status response or ordinary half-close.

### HTTP/1 producer envelope

The current producer advertises transport features in
`event.details.info.webhook_control`. Extend that existing capability map with
one boolean:

```json
{
  "version": 1,
  "content-reverse": true,
  "connection-close": true
}
```

Presence with the literal value `true` is required on the callback that stages
termination. Missing, false, non-boolean, or disappearing capability rejects
termination. A held callback must revalidate it before publishing the terminal
decision. This is additive capability negotiation; it does not reinterpret the
existing version, rewrite, mode, sequence, or content-reverse fields.

After the worker has atomically committed the terminal decision, Spider's
webhook endpoint should return a distinct producer action:

```json
{
  "action": "close",
  "control": {"mode": "strict"},
  "reason": "Connection killed."
}
```

`close` means: publish no callback payload in either direction and close the
current transport connection. It has no content field, no reverse-content
field, and no target identifier. `reason` is bounded diagnostic text; the
producer must not send it on the wire. A producer that does not advertise
`connection-close` can therefore never receive this action from Spider.

The successful terminal result retires only the callback-local flow checkpoint
and its held bytes. It does not restart the persistent addon worker or discard
unrelated script state. The ordinary connection-stop path remains idempotent and
must tolerate the flow already being retired. Validation failure publishes
neither `action: close` nor a modified checkpoint.

Smithproxy advertises this capability only on the synchronous, callback-local
TCP content path. It validates the complete close reply, clears forward and
reverse output, and closes only the current proxy connection. Malformed
close-shaped replies fail closed without forwarding callback bytes.

## Atomic state and addon mapping

The compatibility adapter maps a hook with `flow.live == False` and the kill
error to `api.message.terminate(binding.header, ...)`. The binding already owns
the exact native anchor; the facade never reconstructs a stream identifier.
Native publication succeeds before the adapter retires its binding.

After successful publication, the lifecycle driver dispatches `error()` only
when the reference contract has another lifecycle edge: kills in
`requestheaders`, `request`, and `responseheaders`. A kill in the terminal
`response` hook retires the flow without dispatching `error()`. If publication
fails, the worker generation is invalidated; the callback is never replayed.

Termination is distinct from long-lived interception. It does not create a
suspension token, wait beyond the callback deadline or add a second control
channel.

## Implementation split

The implementation should remain in the existing transaction layers:

1. `inspection_api.Message.terminate()` validates only the public arguments and
   delegates to the active H2 Translate or typed H1 transaction.
2. H2 `_Translation` validates the anchor and stages a data-only terminal
   record. Its pre-assembly preparation mirrors the existing local-response
   suppression: identify the complete logical group before output encoding,
   suppress every group Part, and preserve only source-decoder progress.
   `_TranslationFlow` then cancels the stream in both ledgers and queues the one
   client-facing reset without creating a synthetic HEADERS Part. Existing
   checkpoint and encoder copies provide rollback.
3. H1 `_H1ResponseTransaction` validates the typed group and stages the same
   protocol-neutral decision. Commit emits no message bytes and records a
   connection-close result rather than inventing serialization.
4. `inspection_worker.py` requires the corresponding `translate()` or
   `commit()` return, publishes only validated checkpoint state, and exports a
   bounded internal terminal marker. It never exports a socket or stream ID.
5. Spider's C++ inspection boundary validates that the current callback
   advertised `connection-close`. `webhook.cpp` is the only Spider location
   that maps the internal marker to the proposed producer `action: close`.
6. The addon H1/H2 drivers pass `binding.header` as the anchor, retire the flow
   after native assembly succeeds, and reproduce the checked per-hook error
   lifecycle.

No new mode, parser, frame loop, worker, or side channel is introduced. The H1
producer change is confined to capability publication, strict reply validation
and the existing per-connection shutdown path.

### Exact HTTP/2 patch boundary

The current Translate implementation confirms that the H2 change can remain a
small protocol-owned extension. It should touch only these existing layers:

1. `inspection_api.Message` gains the documented staging method. It delegates
   to the callback-local `_Translation` exactly as `respond()` and the message
   replacement helpers already do. It performs no stream lookup itself.
2. `_Translation` has a `terminations` staging table keyed by the identity of
   the selected initial HEADERS Part. Anchor validation follows
   `stage_message_edit()` and group validation follows
   `stage_local_response()`: current message identity, complete initial
   `:method` or final `:status`, complete retained group, and unpublished stream.
3. `_prepare_terminations()` runs before output encoding and local-response
   assembly. It can cancel a complete initial header whose DATA is still
   incomplete or retained; this is required for header-hook termination. It
   returns the identities of the callback-local logical group to suppress and
   one terminal record per selected stream. Every suppressed input
   HEADERS block has already passed through the source decoder in
   `_Translation.__init__`; none is passed to the private output encoder.
4. `_TranslationFlow` has one local `terminate()` operation. It records the
   stream as cancelled and closed in both existing directional ledgers, invokes
   the existing queued-DATA discard and credit settlement, and appends one
   four-byte-error-code RST_STREAM frame to the client-facing directional
   output. No new persistent ledger or frame parser is required.
5. `addon_parts.py` and `addon_h2_events.py` map the exact killed-flow state to
   the staging call and deliver the checked lifecycle edge only after native
   reset assembly succeeds.

The existing `_TranslationFlow.reset(part)` must **not** be reused as the public
staging operation. It models a reset received from a peer, derives direction
from that input Part, and deliberately suppresses a reset for a locally
initiated stream whose headers were never published. Local termination has the
opposite responsibility: suppress the unpublished logical group and still send
exactly one reset toward the client. Both paths may share private cancellation,
queue-discard and credit-settlement helpers after their distinct validation and
wire-direction decisions.

The H2 result needs no additional public return variant. Its ordinary Translate
result already carries forward bytes, reverse bytes, directional checkpoints
and control state atomically. Termination changes the existing control
checkpoint and one directional byte result. Since it emits no HPACK block, it
must not mark the peer HPACK checkpoint as changed.

The HTTP/1 producer action was approved separately and remains gated by the
literal callback-local `connection-close: true` capability.

Two existing native regressions validate the mechanisms this boundary reuses:

- `test_local_response_uses_reverse_transport_and_preserves_peer_hpack`
  suppresses a retained request, emits reverse protocol-owned output, and then
  decodes later indexed headers with both peers' real HPACK histories;
- `test_reset_in_same_callback_cancels_planned_output_and_preserves_input_hpack`
  cancels output planned earlier in the callback while retaining source HPACK
  progress for a later indexed block.

Both focused tests pass on the current branch. Termination still needs its own
combined regression because neither existing test alone proves the required
client-facing reset plus complete logical-group suppression.

## Safety limits

- only the currently executing live flow can be terminated;
- no arbitrary connection or stream selector is exposed;
- the anchor must belong to the callback-local native Parts collection;
- already-published logical messages cannot be retroactively terminated;
- the action is unavailable for detached and saved flows;
- HTTP/2 uses a fixed validated error-code range, with `INTERNAL_ERROR` as the
  compatibility default;
- HTTP/1 requires an explicitly negotiated producer capability;
- publication remains serialized with the existing flow instance transaction;
- generation retirement and connection teardown discard an unpublished action;
- errors are visible in the normal deployment diagnostics.

## Required tests

### Native Spider

- HTTP/1 request-header and completed-request termination close the connection
  with no response bytes;
- HTTP/1 response-header and completed-response termination close the
  connection with no response bytes;
- HTTP/1 rejection is atomic when the producer capability is absent;
- HTTP/1 rejects false, non-boolean and disappearing `connection-close`
  capability values;
- the accepted producer reply is exactly `action: close` with no forward or
  reverse content, and its diagnostic reason never appears on the wire;
- connection-stop after an accepted close is idempotent and does not retire the
  persistent addon generation or unrelated flows;
- HTTP/2 request-header and completed-request termination emit exactly one
  `RST_STREAM(INTERNAL_ERROR)`;
- HTTP/2 response-header and completed-response termination emit exactly one
  client-facing `RST_STREAM(INTERNAL_ERROR)`;
- two multiplexed HTTP/2 streams prove that only the selected stream is reset;
- the next sibling header block decodes with the destination peer's real HPACK
  state, proving that suppressed headers created no phantom output-table entry;
- a later source header block may reference the suppressed input block and is
  still decoded correctly, proving that source HPACK history was retained;
- an incomplete response body arriving after response-header termination is
  discarded and credited without a second reset or sibling-stream damage;
- reset, GOAWAY, disconnect and duplicate-termination races do not duplicate
  output or leak retained body credit;
- quota and validation failures leave the native checkpoint unchanged;
- packaged-worker and C++ deployment tests preserve the decision through the
  real IPC boundary without exposing it in persisted public state.

### Compatibility adapter

- hook order, flow flags and error text match the checked-in HTTP/1 and HTTP/2
  reference corpora;
- terminal `response()` kill does not invent a later `error()` callback;
- no origin request is observed for a flow killed in either request hook;
- sibling HTTP/2 flows finish normally on the same connection;
- a failed native publication invalidates the generation and never reruns the
  addon callback.

## Project boundary

The HTTP/2 portion is confined to smithproxy-spider and reuses existing
Translate flow state. The approved HTTP/1 Smithproxy change uses the existing
content-webhook and per-connection shutdown boundaries. Capability negotiation
keeps older producers from acquiring new behavior implicitly.

## Reference evidence

- `tests/corpus/addon_kill_v12.json` covers request-side HTTP/1 termination.
- `tests/corpus/addon_kill_h2_multiplex_v12.json` covers request-side H2 stream
  isolation.
- `tests/corpus/addon_kill_h2_requestheaders_late_data_v12.json` covers a
  requestheaders kill followed by a valid fragmented body already in flight.
  No killed-stream bytes reach the origin and the sibling completes normally.
- `tests/corpus/addon_kill_response_v12.json` covers both response-side HTTP/1
  hooks.
- `tests/corpus/addon_kill_response_h2_v12.json` covers both response-side H2
  hooks on one multiplexed connection, including a responseheaders kill whose
  upstream response body remains incomplete.
- `tests/corpus/addon_kill_response_h2_late_data_v12.json` repeats the
  response-side H2 matrix with fragmented bodies and valid late DATA after the
  responseheaders kill. The late body remains invisible downstream, siblings
  complete normally, and the reference emits no upstream reset.

The H2 response corpus groups hooks per flow. Cross-stream callback scheduling
is intentionally not part of the compatibility contract; strict order within
each flow is.
