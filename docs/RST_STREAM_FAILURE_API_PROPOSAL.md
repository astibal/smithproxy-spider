# Native upstream stream-failure design

Status: approved as a general additive API and implemented in smithproxy-spider.

## Problem

An upstream HTTP/2 `RST_STREAM` is not always forwarded to the client by
mitmproxy 12.3.1. A new black-box matrix covers `NO_ERROR`, common protocol
errors, `REFUSED_STREAM`, `CANCEL`, `ENHANCE_YOUR_CALM`, and an unknown code.
Only `CANCEL` remains a downstream reset. Every other observed code produces a
complete local 502 response on the affected stream while its sibling stream
continues normally.

Spider currently publishes the native upstream reset for every code. The addon
receives the correct `error` hook and diagnostic, but most downstream transport
results therefore differ from the reference. This is also the remaining mismatch
when an upstream reset immediately precedes GOAWAY.

The adapter cannot repair this safely by injecting an encoded response. Native
Translate owns HPACK, stream state, output flow control, input credit, queued
DATA, and late-frame disposal.

## Proposed Spider operation

Add one callback-local operation next to `fail_pending_requests()`:

```python
stream = api.connection.http2.fail_reset_stream(
    reset_part,
    status=502,
    headers=[(b"content-type", b"text/plain")],
    body=b"upstream stream failed",
)
return api.message.translate()
```

The result is the selected stream ID. The operation accepts a complete,
unedited, server-to-client `RST_STREAM` Part from the current callback. It does
not accept an arbitrary stream ID and cannot target a sibling flow.

This is a generic native response policy, not a mitmproxy-specific decision.
The caller decides whether a particular reset should be converted. For the
compatibility adapter, `CANCEL` remains ordinary pass-through and every other
observed code uses this operation.

The response arguments and validation are deliberately identical to one member
of `fail_pending_requests()`:

- status is an integer in `400..599`;
- headers and trailers are ordered byte pairs;
- the body is bytes and at most 1 MiB;
- `include_content_length` controls native length insertion;
- existing header, HPACK, frame-size, output, and aggregate quotas apply.

## Native semantics

On successful Translate publication, the operation:

1. consumes the selected upstream reset instead of forwarding it;
2. verifies that the stream has an observed request and no final response;
3. marks the upstream side terminal and rejects later upstream response frames;
4. preserves client-side stream availability long enough to emit the response;
5. queues one protocol-owned response through the existing H2 scheduler;
6. closes the client-facing stream only after its response ends;
7. releases retained request and response-body ownership and returns due flow
   control credit without emitting another reset;
8. preserves sibling streams and both peers' HPACK histories.

The operation is staged data until `message.translate()` succeeds. Validation,
quota, encoder, or scheduler failure publishes neither reset consumption nor
response bytes and leaves the previous checkpoint reusable.

An already completed final response, a reset for an unknown or retired stream,
a client-originated reset, duplicate staging, an edited anchor, or a detached
Part is rejected. The method does not retry the upstream request, open a new
connection, or infer whether a reset is safe to convert.

## Why this is separate from GOAWAY

`fail_pending_requests()` represents a connection-level terminal event and
selects every pending stream from the native ledger. `fail_reset_stream()`
represents one stream-level terminal event and derives exactly one target from
its callback-local anchor. Combining them would make the GOAWAY API depend on
frame adjacency and would hide a generally useful stream-failure policy inside
a compatibility special case.

The two operations may share private response validation, response queuing,
failure-state bookkeeping, and late-frame disposal. Their public selection
contracts remain distinct.

## Reference contract

`tests/corpus/addon_reset_matrix_v12.json` records eight isolated black-box
observations against mitmproxy 12.3.1. Every case receives two complete client
requests, gives the sibling a successful upstream response, and resets the
selected upstream stream before any final response.

The stable callback contract without preceding response headers is:

```text
requestheaders(selected)
request(selected)
error(selected)
```

The sibling receives `responseheaders` and `response`. The client connection is
not terminated. Only code 8 emits downstream `RST_STREAM(8)`; the other seven
observations emit a 502 response whose body contains the matching reset reason.

Three additional observations fix response-header races. An informational 103
immediately before `REFUSED_STREAM` is not published and invokes no regular
response hook. Final 200 headers immediately before the reset invoke
`responseheaders`, but are not published and do not invoke `response`; the
client receives only the replacement 502. The same result is observed when the
final headers and reset arrive in separate reads. Native Translate therefore
keeps the incomplete response retained after `responseheaders` and releases its
body reservation atomically when the later reset is converted. It consumes
both source header blocks so later indexed upstream headers remain decodable,
while only actually published blocks advance the client-facing encoder.

## Required evidence

### Native Translate

- every two-fragment split of a reset frame delays the action until complete;
- all eight checked error codes select the expected adapter policy;
- the converted response survives one-byte output windows and resumes after
  credit without truncation;
- a multiplexed sibling completes while the selected stream is blocked;
- response HEADERS immediately before the reset preserve source HPACK history
  but do not leak a partial final response;
- late HEADERS, DATA, trailers, duplicate reset, GOAWAY, and disconnect races do
  not truncate or duplicate the local response;
- incomplete request DATA after conversion is discarded and credited;
- response headers for a sibling may reference source dynamic-table entries
  observed before the reset;
- the synthetic response advances only the client-facing encoder;
- malformed anchors and output quota failures roll back atomically;
- packaged-worker, production C++ state-boundary, and independent TLS/ALPN wire
  probes preserve the decision.

### Compatibility adapter

- the checked eight-code corpus matches hook order, error text, downstream
  status/reset, body, and sibling completion;
- the reset-before-GOAWAY corpus emits two complete 502 responses and no reset;
- reset-after-GOAWAY remains owned by the connection-level failure path;
- one `error` hook is delivered and flow state is retired only after successful
  native publication;
- failed native publication invalidates the addon generation without replaying
  the callback.

## Approval boundary

Approval authorized only the additive
`ConnectionHttp2.fail_reset_stream()` API and its Spider-owned Translate
implementation. It would not authorize Smithproxy changes, retry semantics,
arbitrary stream selection, changes to ordinary reset forwarding, or changes to
the existing GOAWAY and termination APIs.
