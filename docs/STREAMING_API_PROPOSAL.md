# Incremental HTTP streaming proposal

Status: design only; no native or producer API change is authorized by this file.

## Compatibility target

The mitmproxy 12 public contract has two distinct streaming forms:

- `message.stream = True` forwards body data without retaining the complete body;
- `message.stream = callable` invokes the callable for every observed body chunk
  and once with `b""` at message end. The callable may return bytes or an
  iterable of byte strings.

The choice must be made in `requestheaders` or `responseheaders`. A choice made
later in `request` or `response` is observable on the Python object, but cannot
retroactively change the already buffered transport. The official API documents
that completed streamed hooks receive unavailable body content, and that
trailers can still be changed before their publication:

- <https://docs.mitmproxy.org/stable/api/mitmproxy/http.html>
- <https://docs.mitmproxy.org/stable/api/events.html>
- <https://github.com/mitmproxy/mitmproxy/blob/main/examples/addons/http-stream-modify.py>

The checked-in HTTP/1 and HTTP/2 loopback corpora already fix the basic `True`
lifecycle and unchanged peer bytes. They do not yet cover callable transforms,
empty final output, trailers, early responses during a streamed request, or
failure behavior.

## What exists now

Spider owns the addon worker and message lifecycle. Native Parts owns framing,
content decoding, HPACK state, HTTP/2 flow control and atomic publication.
Buffered addon messages use a native hold and are complete before the final
hook. This is the correct default path and must remain unchanged.

A late `.stream` assignment is now an explicit compatibility no-op. Header-hook
streaming still fails before publication instead of pretending that a buffered
message was streamed.

HTTP/2 DATA Parts retain stream identity and END_STREAM state across callback
fragmentation. This is enough to identify incremental source data, but not to
publish every valid callable result. In particular, an end-of-message callable
may emit bytes after the last source DATA frame, including before trailers. The
current native API deliberately cannot insert or reorder arbitrary Parts.

HTTP/1 has a more fundamental boundary. Holding a message preserves the typed
header/body group and lets the native parser determine completion. Releasing the
header immediately discards that checkpoint. A later producer callback may
contain body bytes without the initial typed header annotation, and Spider must
not introduce a second HTTP parser merely to recover message identity, chunked
framing or trailer completion.

## Proposed split

### Phase 1: true pass-through streaming

Implement `stream = True` first, without a transform function.

The producer must supply a stable, structured HTTP message identity and an
explicit body/trailer/end observation on every incremental callback. The
observation must be independent of display labels and must not require Spider to
parse HTTP bytes. For HTTP/1 it must preserve pipeline order. For HTTP/2 it must
agree with the existing native stream identity.

The adapter can then:

1. run the header hook and publish the edited headers without holding the body;
2. forward each body callback through the ordinary native transaction;
3. retain only bounded flow metadata, not body bytes;
4. run the completed-message hook with `raw_content is None`;
5. publish any trailer edits before retiring the message.

This needs producer work in Smithproxy and therefore requires separate approval.
The Spider-side mapping should consume a versioned structured observation and
reject missing, repeated or contradictory phases.

### Phase 2: callable transforms

Callable transforms need one generic native operation in addition to the Phase 1
producer observations. It should replace one callback-local decoded body unit
with zero or more output byte strings while native code retains ownership of:

- content coding and HTTP/1 transfer framing;
- HTTP/2 DATA framing and source/destination flow-control accounting;
- final callable output before trailers or END_STREAM;
- output quotas and atomic rollback;
- exact source-credit settlement when output size differs from input size.

The operation must not expose frame insertion, stream IDs or webhook JSON to the
addon. Concatenating an iterable into one protocol unit is acceptable because
the public contract does not promise socket or DATA-frame boundaries. It is not
acceptable to buffer the complete message, silently discard final `b""` output,
or debit HTTP/2 source windows using transformed output length.

The exact native method signature should be proposed only after the Phase 1
producer observation is fixed. This prevents an API shaped around incomplete
HTTP/1 metadata or around HTTP/2 alone.

## State and scheduling

The streaming policy and callable belong to the persistent deployment worker.
All connections using a script continue to share that worker and script state.
The host must never create a per-flow Python worker.

An early upstream response may complete before a streamed request hook. The
flow table therefore cannot assume request-complete before response hooks. Each
direction needs its own bounded phase, while both directions retain one
`HTTPFlow` identity.

Worker retirement, connection loss, hook failure and quota failure must retire
the incremental state deterministically. They must not replay the header hook or
fall back from transformed data to original data after any prefix was published.

## Required acceptance gates

- HTTP/1 Content-Length, chunked bodies, trailers, pipelining and close-delimited
  rejection where no truthful completion observation exists.
- HTTP/2 fragmented frame headers, fragmented DATA, multiplexed streams,
  independent stream and connection windows, trailers, reset and GOAWAY.
- `True`, bytes-returning callables, iterable-returning callables, dropped chunks,
  size expansion, exceptions, invalid return items and non-empty final output.
- The same addon callable serving multiple connections in one persistent worker,
  with deterministic per-flow ordering and shared script state.
- Exact hook lifecycle and public message state against independent mitmproxy
  12.3.1 corpora; peer bytes compared by semantics rather than callback or DATA
  segmentation.
- Failure after a published prefix must close/reset the affected transport scope;
  it must never retry the callback or leak a mixed original/transformed suffix.

Until these gates pass, the compatibility table must continue to describe
header-hook streaming as unsupported.
