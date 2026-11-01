# WebSocket addon producer proposal

Status: the dormant Spider-side envelope validator and lifecycle adapter are
implemented and fully covered. No live producer exists, so registration remains
fail-closed. This document does not authorize or implement changes in
Smithproxy or another project.

## Goal

Deliver truthful mitmproxy-compatible `websocket_start`, `websocket_message`
and `websocket_end` callbacks without adding another WebSocket parser or proxy.
Smithproxy remains the sole owner of RFC 6455 framing, masking, fragmentation,
compression and transport state. Spider receives complete logical messages and
returns structured decisions through the existing synchronous inspection
boundary.

This proposal is intentionally separate from the raw TCP/UDP envelope. A
WebSocket message is not an arbitrary stream chunk: its public callback must
observe a complete reassembled message with a stable opcode and direction.

## Reference contract

The checked-in mitmproxy 12.3.1 wire corpora record real HTTP/1 upgrades and
fix the externally visible lifecycle:

```text
HTTP 101 accepted
    -> websocket_start
    -> websocket_message(client -> server)
    -> websocket_message(server -> client)
    -> websocket_end
```

Before each message callback, the new message is already appended to
`flow.websocket.messages`. Size-changing text mutations reach the opposite
peer. The ordinary closing handshake remains intact. The same flow and
`WebSocketData` identities survive for the complete upgraded connection.

The extended control corpus additionally proves that fragmented data with
interleaved ping frames produces one complete message callback, while ping,
pong and close frames produce none. Text, binary and initially empty messages
remain distinct. Size-changing and empty-to-nonempty replacements reach both
peers, and `message.drop()` consumes exactly one complete logical message in
either direction. Message history remains append-only and ordered even for
dropped messages. A clean `websocket_end` callback observes `flow.live` as
true; the adapter retires the flow only after that callback returns.

The destructive corpus fixes termination semantics separately. `flow.kill()`
at start or in either directional message callback changes public `live` and
`error` state but does not stop forwarding or replace the normal close
handshake. An abrupt client or origin disconnect produces `websocket_end` with
code 1006, no close reason and no `flow.error`; `closed_by_client` identifies
the observed side. Invalid text from either peer is rejected before a callback
for that message, closes both peers with code 1007, identifies the offending
side through `closed_by_client`, and exposes the UTF-8 diagnostic as the close
reason rather than a flow error.

The concurrency corpus keeps two upgraded connections live at the same time.
One addon module owns a single monotonically increasing counter across all
eight directional callbacks, while each flow's message history independently
grows from one through four entries. Mutations derived from that shared state
reach the correct peer in deterministic order. This proves the intended
one-worker-per-generation model without requiring a worker per flow.

The compression corpus negotiates `permessage-deflate` with no context takeover
in either direction. The addon observes complete decompressed plaintext,
changes each message's size, and both peers receive valid recompressed messages
with RSV1 set. Ping/pong remains outside the message callbacks. This proves the
public behavior while preserving the proposal's rule that the native proxy,
not Spider, owns compression state and wire framing.

Two additional corpora deliberately split the same valid compressed stream
across an initial data frame and a continuation frame, with a ping between
them. Mitmproxy 12.3.1 closes both directions with code 1007 before publishing
the fragmented compressed message. The equivalent unfragmented compressed
message succeeds. This observed reference boundary is recorded, but the native
producer must not silently copy it as a protocol policy: Smithproxy already
owns reassembly and can expose a complete logical message. Before live
integration, compatibility mode must explicitly choose whether to preserve the
12.3.1 close behavior or accept the standards-valid message as an intentional,
documented improvement.

The first producer phase targets this observation, mutation and drop contract.
Message injection is a separate capability because it creates traffic rather
than deciding the disposition of an observed message.

## Producer boundary

After a successful HTTP/1 upgrade, Smithproxy would publish a versioned
`websocket` object in the existing structured inspection metadata:

```json
{
  "websocket": {
    "version": 1,
    "connection_id": "bounded-opaque-id",
    "exchange_id": 1,
    "event": "start",
    "subprotocol": null,
    "extensions": []
  }
}
```

`start` is emitted only after the upgrade has been accepted and before any
application message is forwarded. The HTTP flow identity used for the upgrade
is retained through the explicit HTTP/1 exchange identity; Spider does not
guess which pending request upgraded. `connection_id` must equal the native
session identity already authenticated by the callback boundary. An
unsuccessful upgrade never creates a WebSocket lifecycle.

For each complete logical message:

```json
{
  "websocket": {
    "version": 1,
    "connection_id": "bounded-opaque-id",
    "event": "message",
    "sequence": 7,
    "direction": "client-to-server",
    "opcode": 1,
    "compressed_on_wire": false
  }
}
```

The ordinary base64 `content` field contains the complete unmasked,
decompressed application message. `opcode` is the logical data-message opcode:
text (`1`) or binary (`2`). Continuation frames, masking keys and compressed
frame bytes are never exposed as addon content. Ping, pong and close remain
protocol control frames, not `websocket_message` callbacks.

At termination Smithproxy publishes one terminal event:

```json
{
  "websocket": {
    "version": 1,
    "connection_id": "bounded-opaque-id",
    "event": "end",
    "close_code": 1000,
    "close_reason": "",
    "closed_by_client": true,
    "transport_error": null
  }
}
```

Unknown values are `null`; Spider does not derive them from log text. A
transport failure still produces exactly one `websocket_end`, with bounded
diagnostic text in `transport_error`. The close metadata reflects what was
observed before teardown, not a synthetic successful handshake.

## Synchronous decision path

Smithproxy awaits the message callback before forwarding that logical message.
Spider appends a `WebSocketMessage` to the persistent flow history first, runs
the registered addon hooks in the generation's stable worker, and returns one
of three decisions:

```text
pass       forward the original logical message
replace    forward the returned opcode and complete content
drop       consume this logical message without forwarding it
```

`replace` permits size changes, including an empty data message. It is not a
frame recipe. Smithproxy performs any UTF-8 validation required for a text
message and owns reframing, masking, fragmentation and negotiated compression.
An empty replacement therefore remains one empty text or binary message;
`drop` is explicit and distinct.

The producer must not forward the original message before the decision arrives.
A callback timeout, worker failure, malformed result, identity mismatch,
sequence gap, unsupported opcode or quota violation follows the configured
strict inspection policy and is logged as a producer failure. It must not leak
part of the original message and later append a replacement. The current
compatibility deployment remains fail-closed for active addon transport until a
separate, explicit fail-open policy owns the complete original message.

Multiple WebSocket connections may share one persistent worker. Each script
generation is nevertheless pinned to the same worker for its lifetime, so
module and addon-object state remains coherent across connections. There is no
worker per flow.

## Fragmentation and compression ownership

Smithproxy owns these protocol details end to end:

- reassembly of fragmented text and binary messages;
- validation of continuation ordering and control-frame interleaving;
- client masking and server unmasking;
- negotiated `permessage-deflate` decompression and recompression;
- output fragmentation and frame boundaries;
- ping, pong and close-handshake protocol behavior.

Spider sees one complete application message and returns one complete
application message. This is required for mitmproxy's public addon semantics and
prevents the adapter from becoming a second WebSocket stack.

HTTP/2 extended CONNECT is a separate producer path. Phase 1 may ship for
HTTP/1 upgrade only, but must reject rather than misclassify H2 WebSockets until
Smithproxy can expose the same logical-message contract per H2 stream.

## Message injection

`WebSocketMessage.injected` is a public value field; it does not by itself
authorize traffic creation. The official injection example needs a separate,
explicit host command such as `inject.websocket(flow, to_client, content)`.

That command requires:

- capability declaration and deployment-time authorization;
- resolution of a live WebSocket flow owned by the same generation;
- a bounded command queue and deterministic ordering against observed messages;
- protocol-owned framing and backpressure in Smithproxy;
- rejection after close, during retirement or for a foreign/stale flow;
- an injected message appended to public history before its callback-visible
  state is observed, matching the reference contract.

Phase 1 does not emulate injection by altering an unrelated observed message.
The ordinary message producer and the active injection command can therefore be
approved, implemented and tested independently.

## Limits and security

The existing generation admission and output limits remain in force. The live
producer additionally needs bounded per-flow and aggregate message history,
content size, pending callback count, callback time and injected queue size.
Closing or retiring a flow releases all of its accounting exactly once.

Opaque connection identifiers are never treated as credentials. Decisions are
accepted only from the generation and callback that owns the current message.
Late results, duplicate sequences and cross-flow results are rejected. Logs
must identify the workspace, deployment, flow and bounded failure reason
without recording message content by default.

## Required implementation work

After separate approval for cross-project changes:

1. **Smithproxy producer**
   - expose successful upgrade, complete logical messages and terminal state;
   - await one decision before forwarding each application message;
   - apply pass, size-changing replacement and explicit drop atomically;
   - retain exclusive ownership of framing, compression and control frames;
   - provide truthful ordering and backpressure for both directions.
2. **Spider adapter**
   - implemented: validate the versioned envelope and sequence;
   - implemented: retain one HTTP/WebSocket flow identity in the stable worker;
   - implemented: append messages before callbacks and return structured
     decisions;
   - implemented: bound histories, content and generation-wide accounting;
   - implemented: retire a live flow with exactly one terminal callback;
   - pending producer integration: resolve the upgraded HTTP exchange and map
     the structured decision to native transport publication.
3. **Optional host command**
   - add injection only after the ordinary producer is complete;
   - authorize, queue and test it as active traffic creation.

No public native scripting API needs to change for phase 1 unless implementation
reveals that the existing synchronous inspection result cannot represent an
explicit drop without ambiguity. In that case a small generic, zero-impact
decision helper should be proposed before adding adapter-specific glue.

## Acceptance gates

The checked-in mitmproxy 12.3.1 corpus remains the first wire target. Completion
also requires:

- exact start/message/end ordering and stable flow/data identities;
- message-list append-before-callback behavior in both directions;
- text and binary messages, including empty messages;
- larger, smaller and empty replacements without accidental drop semantics;
- explicit drop without forwarding any original bytes;
- every input frame fragmentation boundary and fragmented logical messages;
- ping/pong interleaving during fragmented data messages;
- valid and invalid UTF-8 behavior for text messages;
- client masking, server output and negotiated compression;
- normal close, peer-only close, close code/reason and transport failure;
- multiple concurrent connections sharing script state but not histories;
- worker timeout, crash, restart and generation retirement without duplicate
  forwarding, leaked content or duplicate terminal callbacks;
- malformed version, direction, sequence, opcode, identity and terminal data;
- mixed ordinary HTTP, raw TCP and WebSocket traffic without cross-classification;
- HTTP/1 wire tests first and explicit H2 rejection until H2 gates exist;
- packaged-worker, native boundary and end-to-end wire coverage.

The checked-in control and destructive corpora already cover bidirectional
fragmented text, binary and empty messages, control-frame interleaving,
replacement, explicit drop, normal and abrupt termination, invalid UTF-8 from
either peer, close metadata, callback-visible end liveness and negotiated
compression. The compressed-fragmentation reference boundary is measured but
needs the explicit compatibility policy above. Native concurrent-producer
backpressure and producer-failure gates remain required before live
registration.

For the later injection phase, add deterministic ordering, both directions,
backpressure, close races, stale-flow rejection, authorization and queue-limit
tests. Until both the producer and relevant wire gates pass, the facade must not
describe live WebSocket compatibility as supported.
