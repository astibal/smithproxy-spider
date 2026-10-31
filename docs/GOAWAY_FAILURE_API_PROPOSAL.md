# Native HTTP/2 pending-request failure proposal

Status: approved and implemented on the development branch. The additive
native API, adapter mapping and regression evidence described here are present;
the standalone upstream RST_STREAM transport gap remains documented separately.

## Problem

An upstream HTTP/2 GOAWAY is a connection-level event, while the current native
response and termination helpers are anchored to one callback-local message.
The addon adapter can identify its retained `HTTPFlow` objects, but it cannot
safely turn several older pending request streams into client-facing responses.
Doing that in the facade would require a second HPACK encoder, output scheduler,
flow-control ledger and stream lifecycle implementation.

The checked mitmproxy 12.3.1 black-box matrix establishes these observable
rules for two complete GET requests on streams 1 and 3:

- a final response for stream 1 received before GOAWAY remains successful;
- stream 3 receives an HTTP 502 and an `error` hook before stream 1's
  `response` hook;
- if stream 1 is still pending, both streams receive HTTP 502 responses;
- a valid final response for stream 1 sent shortly after GOAWAY is not accepted;
  both streams have already failed;
- NO_ERROR and PROTOCOL_ERROR have the same selection and response behavior,
  while the diagnostic reason preserves the actual error code;
- each synthetic response ends its stream, no stream reset is sent, and the
  upstream GOAWAY is not forwarded to the client;
- no retry connection is opened in the bounded observation window.

The twelve exact corpora live in `tests/corpus/addon_goaway_*_v12.json` and are
replayed by `tests/probes/h2_goaway_probe.py` against mitmproxy 12.3.1.

## Proposed API

Add one connection-scoped, protocol-owned operation:

```python
stream_ids = api.connection.http2.fail_pending_requests(
    goaway_part,
    status=502,
    headers=[
        (b"server", b"compatibility-adapter"),
        (b"content-type", b"text/html"),
    ],
    body=b"complete error document",
    trailers=[],
    include_content_length=False,
)
return api.message.translate()
```

The returned tuple is the ordered set of streams staged by this transaction.
It is useful for correlating protocol decisions with higher-level lifecycle
objects, but it does not mean that bytes were published before `translate()`
succeeds.

This is a general gateway primitive, not a mitmproxy object or compatibility
escape hatch. A native script may use it to replace an upstream connection
failure with bounded local responses while keeping the client connection alive.

## Selection contract

The `goaway_part` anchor must be the one complete, unedited GOAWAY Part in the
current server-to-client callback. It must have stream ID zero and at least the
standard eight-byte payload. Detached Parts, a client-originated GOAWAY,
duplicate staging and an already published transaction are rejected.

The native connection ledger selects client-initiated streams that have an
observed request and no final response published before the anchored GOAWAY.
Selection is deliberately not limited to IDs above GOAWAY's last-stream ID:
the reference also fails an accepted ID whose response was not complete before
the control frame. Informational responses do not count as final responses.

Wire order inside the callback matters. Final response headers before the
anchor exclude that stream. Final response headers after the anchor are
suppressed as part of the failed connection lifecycle. Already reset, locally
answered, terminated or fully retired streams are never selected twice.

The implementation must also support a request whose initial headers have been
published but whose body is incomplete. The checked streaming corpus proves
that this flow receives `requestheaders` and `error`, but no completed `request`
hook, while the client still receives a complete 502. Late source DATA for a
failed stream is silently consumed: the checked late-DATA corpus observes no
reset, second hook or client connection termination. The native flow ledger
must discard and credit those bytes without forwarding them upstream.

## Native publication

Staging records only validated response data and the callback-local GOAWAY
anchor. `translate()` owns the atomic protocol result:

1. consume the upstream GOAWAY without forwarding it to the client;
2. preserve source-side control state and the GOAWAY diagnostic payload;
3. suppress any later final response in the same callback for a selected
   stream;
4. encode one response HEADERS block per selected stream through the existing
   client-facing peer encoder;
5. queue body and trailer frames through the existing directional flow-control
   scheduler;
6. end every selected stream exactly once and retire both directional ledger
   entries after queued output drains;
7. preserve sibling streams that already received a final response before the
   GOAWAY;
8. publish forward bytes, reverse bytes, both HPACK checkpoints, holds and the
   connection-control checkpoint as one existing Translate transaction.

No raw frame bytes, stream selector, encoder checkpoint or connection handle is
exposed to the script. The facade receives only the ordered selected stream IDs
and maps those IDs to its already retained flows.

`include_content_length` defaults to `True` for ordinary native use. The
compatibility adapter selects `False` because the checked mitmproxy 12.3.1 H2
502 response contains `server` and `content-type`, but no Content-Length. This
option changes only responses created by this new operation and has no effect
on the existing `message.respond()` contract.

## State extension

The existing `_TranslationFlow` checkpoint already owns bounded per-direction
stream records, output queues, closed ranges and GOAWAY state. Extend each live
stream record with data-only lifecycle fields:

- whether initial request headers were observed;
- whether request END_STREAM was observed;
- whether final response headers were published;
- whether a pending-failure response was staged.

Old checkpoints omit these fields and therefore retain their current behavior.
The fields are populated only from interpreted native Parts during explicit
Translate callbacks. No addon object, Python callable or arbitrary metadata is
stored in the checkpoint.

The response body is staged once and shared until assembly, but emitted bytes
are charged once per selected stream. Existing 1 MiB transaction output,
384 KiB pending-output, 1,024-stream and HPACK checkpoint limits remain hard
atomic failure boundaries. A large fan-out that cannot fit is rejected before
any checkpoint or wire result is published.

## Compatibility adapter mapping

The H2 addon driver observes the complete GOAWAY payload and computes the
reference diagnostic reason. It stages the exact 502 response once, receives
the selected stream IDs, dispatches `error()` for the matching retained flows
in stream order, and calls `translate()`. A final response Part preceding the
GOAWAY is still dispatched normally after those error hooks, matching the
checked reference hook order.

If native publication fails after callbacks have run, the addon generation is
invalidated and no callback is replayed. The adapter never emits a synthetic
addon-only error while leaving different bytes on the wire.

## Risks

### Incorrect stream selection

The largest semantic risk is failing a stream that already has a valid final
response, or preserving a stream whose response arrived only after GOAWAY.
Selection must therefore use ordered interpreted Parts plus the persistent
native ledger, not only the last-stream ID or facade state.

### HPACK divergence

Suppressing the upstream GOAWAY is simple; suppressing later response headers
is not. Their source header blocks must still advance the upstream decoder, but
must not advance the client-facing encoder. Synthetic responses must use the
client-facing encoder in global header order. The existing local-response path
already demonstrates this split and should provide the private assembly helper.

### Flow-control and memory amplification

One connection failure may select hundreds of streams. Repeating a body can
amplify output and retain window-blocked DATA. Existing aggregate quotas must be
applied to the complete fan-out before publication, with no special larger
limit for compatibility mode.

### Partial request bodies

If a request upload is still arriving, failing it must release reserved input
ownership and reject later DATA without a second response. This needs explicit
fragmentation and window-credit tests; treating only complete requests would be
a behavioral gap.

### Reference-specific error rendering

The native operation accepts response fields and bytes but does not know how a
particular compatibility layer formats an error page. Exact HTML, diagnostic
escaping and optional compatibility branding remain adapter data. Native code
owns only validation, framing, scheduling and lifecycle.

## Required evidence

- exact replay of the six checked GET corpora and the incomplete POST corpus
  against mitmproxy 12.3.1;
- the checked informational-response corpus, proving that an upstream 103
  immediately before GOAWAY produces neither a response hook nor client headers;
- every two-fragment split of the GOAWAY frame and representative response
  HEADERS/DATA boundaries;
- accepted response before GOAWAY, pending response, and response after GOAWAY;
- NO_ERROR, PROTOCOL_ERROR and an unknown error code;
- multiplexed output with one selected stream blocked by its window while a
  sibling response can progress;
- HPACK dynamic-table continuity in both directions after the fallback;
- late DATA, duplicate GOAWAY, RST_STREAM races and repeated staging;
- quota and malformed-anchor failures proving atomic rollback;
- packaged-worker and native C++ transaction boundary coverage;
- a live TLS/ALPN integration test with an independent origin and client.

The implementation has this evidence. Native tests cover selection on both
sides of the GOAWAY anchor, incomplete request bodies, late DATA, repeated
monotonic GOAWAY, RST_STREAM before and after the anchor, independent stream
windows, dynamic-table continuity, malformed anchors and atomic fan-out quota
failure. The packaged worker and the production C++ state boundary each run the
operation. `tests/probes/h2_goaway_native_probe.py` places the native byte bridge
between independent TLS/ALPN H2 peers and observes stream 3 receive 502 while a
completed stream 1 response remains 200, without forwarding GOAWAY.

The two additional reference corpora fix RST_STREAM immediately before and
after GOAWAY. GOAWAY followed by RST_STREAM is matched by consuming both controls
and using the reference connection-level diagnostic for every pending flow.
RST_STREAM before GOAWAY retains correct hook ordering and native atomicity, but
the reset stream still uses Spider's native reset transport instead of the
reference's synthetic 502. Fixing that standalone reset behavior requires a
separate general server-side stream-failure API and is not hidden by this API.

## Approval boundary

Approval of this proposal authorized only the additive
`ConnectionHttp2.fail_pending_requests()` API and its Spider-owned native
Translate implementation. It would not authorize Smithproxy changes, a second
HTTP/2 implementation, a generic stream-ID control plane, or changes to the
existing `respond()` and `terminate()` behavior.
