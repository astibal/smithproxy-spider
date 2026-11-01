# Protocol-specific inspection state

Status: the initial Spider-local H1/H2 state API is wired into flow callbacks.
The core lives in `src/inspection_protocol_state.py`; sandbox-worker and C++
instance tests cover its lifecycle. No Smithproxy changes are required.

## Current implementation and boundaries

The core has independent immutable H1 message and H2 stream records, bounded
tables and candidate updates. It consumes native Parts rather than parsing
wire content. Reception, suspension and completed local publication are distinct
facts. A complete body does not automatically resume or publish its message.

Both tables now support detached JSON checkpoints and strict restoration into
fresh tables. Restoration validates versions, quotas, identifiers, directional
sequence bounds and consistent boolean flags. H1 sequence counters survive
message retirement. The host stores the checkpoint in its flow instance, charges
it against the deployment budget and removes it on connection retirement. This
private worker field is not returned in API responses or recent-event summaries.

Observation now supports native restored Parts explicitly. H1 Header/Body Parts
carry a directional message sequence; completed H2 units carry an observation
marker. Existing typed hold checkpoints preserve these private data fields.
Incomplete H2 units are observed only after native reassembly completes them.
Markers are attached only after the whole observation batch validates. A
restored unit with missing state or a different direction is rejected rather
than silently reassigned. The connection owner binds both tables to the event
connection ID and invokes observation before script edits.

Enable tracking explicitly during setup with `api.connection.track_protocols()`.
Later callbacks expose immutable tuples at `api.http1.state` and `api.http2.state`.
`None` means tracking is unavailable; an empty tuple means no retained observation.
No existing script gains tracking overhead or changes transport mode implicitly.
Partial units require existing native reassembly, not a new parser in the table.
H1 sequence numbers identify directional messages, not paired exchanges;
informational responses retain their own identity.

Views describe callback entry. A successful callback commits local disposition
with its result, without changing the snapshot already held by the script.
`published` describes acceptance into native output processing, **not** a socket
write, drained flow-control queue or peer acknowledgement. Arbitrary replacement
and synthesized-response/termination paths leave input publication unknown
(`None`) rather than claiming those input messages reached the output.

Limits are 1,024 H1 records, 1,024 H2 streams and 512 KiB per checkpoint, within
the existing 4 MiB deployment state budget. Completed published H1 messages and
reset or fully published H2 streams retire on subsequent observation, except
when referenced by restored Parts. This is not a complete connection archive.
If a callback fails, the host disables tracking for that instance and logs the
loss of continuity. Reconnect to restart tracking; later input must not silently
fill gaps left by fail-open processing. Existing callback failure policy is unchanged.

No header-hook behavior changes yet. TCP/UDP and other protocol structures are
not implemented by this initial H1/H2 core. Do not advertise these tables as a
complete protocol API or full connection history.

## Intent

Expose protocol-specific processing state owned by Spider to native scripts.
Smithproxy supplies observations and protocol context; its internal parser and
socket states are not the public state machine proposed here. Spider tracks
what it has received, made available to scripts, retained and committed for
publication. Each protocol has its own structure and transition rules.

This is a native Spider facility, independent of mitmproxy compatibility. The
addon adapter consumes it and maps hooks to it; it must not own a second copy.
There is no common protocol-state enum. Existing producer states listed below
are contextual evidence, not a specification for copying their enums into Spider.

## Inspected sources

The producer inventory uses the sibling `smithproxy-http1-flow-kill` worktree;
the consumer inventory uses this Spider checkout. This is not an assertion
about every deployed binary or every protocol supported by Smithproxy.

| Layer | Existing owner and observations | Current exposure or gap |
| --- | --- | --- |
| HTTP/1 producer | `src/inspect/engine/http.hpp`: `v1::Http1Message`, `Http1Direction`, `Http1Connection`; directional parser phases and request-method FIFO | Parser phase is private; no complete public snapshot in the scripting API. |
| HTTP/2 producer | Same header: `v2::Http2Stream`, `Http2Connection`; directional end/invalid flags, body counts, final response headers, pending header blocks, SETTINGS, windows and GOAWAY | Native state exists, but the scripting views expose callback frame slices and decoded header blocks rather than this connection state. |
| Endpoint contexts | `src/inspect/protocol_views.hpp`: endpoint-local input/output contexts | Observation and emitted protocol state can diverge after hold, replacement or local response. |
| Spider H1 views | `src/inspection_api.py`: `Http1`, `Message`, `InspectionViews` | `Http1` exposes the first complete head in the callback, not all pipelined exchanges. `Message` means a callback fragment, not an HTTP message. |
| Spider H2 Translate | `src/inspection_translate.py`: `_TranslationInput`, `_TranslationFlow`, `_TranslationSuspension` | Input ownership, output windows/queues, HTTP lifecycle and suspension exist, but only in negotiated Translate mode; these are not a universal TCP or H2 observation source. |
| Addon dispatch | `src/addon_parts.py`: `MessageState` | Hook-delivery, publication and suspension flags belong to adapter execution. They must not be exported as authoritative protocol state. |
| Connection events | `src/inspection.cpp`, `src/inspection_worker.py`: start/stop dispatch, setup/content phases | Script lifecycle is not proof of socket connect, FIN, half-close or TLS handshake state. Offline execution can synthesize lifecycle events. |
| DNS producer | `src/inspect/dnsengine.hpp`: `app_DNS` request/response pointers | Decoded DNS objects exist; a public exchange lifecycle is not established by these pointers. |
| Other addon protocols | Producer proposals and `COMPATIBILITY_RELEASE_GATES.md` | TCP/UDP, DNS, WebSocket, CONNECT, SOCKS5, TLS and QUIC adapters must not be mistaken for wired native producer support. |

TCP/UDP socket observations and remaining producer structures need a separate
source audit before their concrete fields are promised. In particular, do not
expose connected/half-closed states merely because the reference object model
has corresponding values.

## Public API shape

Keep each structure at its protocol-specific owner. Illustrative access paths:

```python
api.http1.state
api.http2.state
```

These two views are implemented. Possible transport-specific structures such as
`api.connection.tcp` and `api.connection.udp` remain proposals, not runtime APIs.
Existing `api.state` (user JSON storage) and `api.phase` remain unchanged.
The following sections describe the wider design, not a claim that all listed
protocol observations or compatibility hooks have already been implemented.

### HTTP/1

Track Spider's handling of each directional HTTP message: receiving a head,
head available to the script, receiving content, complete content and its local
publication lifecycle. These are provisional concepts, not final enum names.
Producer phases such as chunk delimiter are framing context; do not export them
as Spider processing states simply because they exist in the parser.

A parser returning to `headers` does not identify the completed exchange. Add
bounded exchange identity and completion observations before advertising an
exchange list. Handle pipelined requests, interim responses, HEAD and CONNECT
explicitly; one callback can cross several message boundaries. Header-hook
suspension needs a boundary-specific view, not only the final parser phase
after all bytes in the callback have been observed.

### HTTP/2

Track locally observed connection facts separately from a bounded stream map. Each stream has
request and response observations: headers availability/completion, body byte
count, end and invalid flags, including whether response headers are final.
Pending CONTINUATION state must not imply complete headers. GOAWAY is a
connection observation and must not be flattened into every stream being closed.

Do not label this as the full RFC stream-state machine unless every advertised
state has a proven mapping, including promised and reset streams. Reuse existing
native state; no adapter-maintained copy of HPACK or flow-control machinery.

### TCP, UDP and other protocols

Define separate types only from audited native producer observations. UDP must
not inherit TCP connect/half-close semantics. DNS needs message/exchange identity;
WebSocket needs handshake and message/close semantics; TLS needs actual handshake
observations. The current dormant adapters do not justify publishing guessed
values. Missing producer fields require a separately reviewed producer patch.

## Observation versus processing

Spider owns the local lifecycle, including reception, script visibility,
suspension and publication. Within each protocol structure, keep message
progress distinct from processing disposition: complete content can still be
suspended. Producer endpoint context provides evidence, not the authority for
whether Spider has dispatched a hook or retained a message.

Expose immutable callback snapshots. A snapshot must identify its endpoint and
input/output observation boundary. Input completion never implies output
completion, successful socket write or receipt by the peer. Do not expose live
mutable checkpoint dictionaries, buffers, keys or HPACK tables.

For the first version, reads describe the captured observation, not a speculative
post-commit state. Existing operations stage changes; failed publication must
not advance the committed observation. If pending operation status is exposed,
name it separately and document its transaction boundary.

## Implementation sequence

1. Agree on ownership, snapshot boundaries and protocol-specific access paths.
2. Map existing Spider Parts, enrichment, retention and publication events to
   local transitions. Identify missing evidence separately; producer changes
   are not a prerequisite by default and require separate review if necessary.
3. Implement bounded protocol-specific state ownership in native Spider and
   immutable script views with generated API documentation. Do not place the
   state machine in the compatibility adapter or mirror Smithproxy internals.
4. Test views in native scripts without the compatibility adapter loaded.
5. Use the native message/stream state to extend header-hook interception.

## Required tests

- Identical observations across every relevant byte split and coalescing of
  multiple messages into one callback.
- H1 pipelining, 1xx/final responses, bodyless messages, chunked trailers,
  until-close and opaque transitions.
- H2 CONTINUATION, END_STREAM without DATA, interleaved streams, reset, GOAWAY
  and request/response asymmetry.
- Complete input with held output; replacement and reverse local response;
  failed publication does not advance committed state.
- Unknown/unavailable versus false; offline preview without transport evidence.
- Bounded retention, stream retirement and reused connection identifiers.
- Snapshot immutability and unchanged existing API schema behavior.

No wakeup channel, timer, async worker redesign or new protocol parser belongs
to this proposal. No claim of universal protocol coverage precedes its audit.
