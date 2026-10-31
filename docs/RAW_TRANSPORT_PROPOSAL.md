# Raw TCP and UDP addon transport proposal

Status: the Spider-side adapter is implemented and unit tested behind this
explicit envelope. Smithproxy does not produce the envelope yet, so live raw
transport compatibility is not enabled. This document does not authorize or
implement Smithproxy changes.

## Purpose

The compatibility facade already provides the public `TCPFlow`, `TCPMessage`,
`UDPFlow`, and `UDPMessage` value models. Live `tcp_*` and `udp_*` hooks need a
producer contract before they can be enabled safely. Spider must not infer a
transport from a display label, payload contents, or an application-layer
classification.

The proposed boundary keeps Smithproxy as the only proxy and reuses the current
connection-start, connection-content, and connection-stop webhook lifecycle.
It does not add another transport engine or a transaction mode.

## Producer envelope

Smithproxy would add a versioned `raw_transport` object to the existing
`details.info` object. Its absence retains the current behavior.

At connection start:

```json
{
  "raw_transport": {
    "version": 1,
    "kind": "tcp",
    "delivery": "raw",
    "client": {
      "peername": ["192.0.2.10", 41000],
      "sockname": ["192.0.2.20", 443]
    },
    "server": {
      "address": ["198.51.100.30", 443],
      "peername": ["198.51.100.30", 443],
      "sockname": ["192.0.2.20", 52000]
    }
  }
}
```

`kind` is the observed outer socket transport. `delivery: raw` is a separate,
explicit producer decision that the payload belongs to raw addon hooks. A UDP
socket carrying decoded HTTP/3 traffic is not automatically a raw UDP addon
flow. Unknown endpoint fields are `null`; neither producer nor adapter derives
them from the human-readable session label.

At content delivery, the same object also contains:

```json
{
  "direction": "client-to-server",
  "sequence": 7,
  "unit": "stream-chunk"
}
```

For UDP, `unit` is `datagram`. Each original datagram creates exactly one
content event, including a zero-length datagram. Its existing base64 `content`
field contains that datagram and only that datagram. For TCP, each event is an
ordered observed byte chunk. Chunk boundaries are not advertised as
application-message boundaries.

At connection stop, `raw_transport` contains a terminal observation:

```json
{
  "terminal": {
    "state": "error",
    "message": "connection reset by peer"
  }
}
```

`state` is `closed` for an ordinary close and `error` for a transport failure.
The error text is bounded and diagnostic; addon decisions never depend on its
platform-specific wording.

## Adapter behavior

One raw flow is created during connection start and remains owned by the same
addon generation and worker for its complete lifetime. Multiple connections may
share that worker, preserving script-global state without a worker per flow.

The lifecycle is:

```text
TCP: tcp_start -> tcp_message* -> (tcp_end | tcp_error)
UDP: udp_start -> udp_message* -> (udp_end | udp_error)
```

Before each message hook, the adapter appends one directional message to the
flow's public `messages` list. After the hook:

- TCP publishes the possibly size-changing `message.content` as the replacement
  for that observed chunk.
- UDP publishes it as exactly one replacement datagram. `b""` means one empty
  datagram, not a dropped datagram.
- An unchanged message uses the ordinary pass-through result.
- Connection termination remains a separate capability; content mutation does
  not invent a hidden drop or kill sentinel.

The existing bounded callback, output, connection, and generation-state limits
remain in force. A malformed or inconsistent envelope fails closed for addon
execution and preserves the original payload. It never falls back to guessing
the transport.

Raw histories are additionally bounded to 4,096 messages and 16 MiB per flow,
with aggregate generation limits of 16,384 messages and 32 MiB. These defaults
bound the worst case across the 128-flow admission limit; closing or retiring a
flow releases its complete aggregate charge.

## Integration status

The Spider worker now validates this envelope, creates bounded generation-local
flows, dispatches the raw lifecycle hooks, and publishes mutations through the
existing native Rewrite transaction. It rejects identity changes, sequence
gaps, direction mismatches, unsupported control decisions, message-history
replacement and quota violations. No public native scripting API changed.

Live integration still requires separate approval because the remaining work
belongs to Smithproxy:

1. **Smithproxy producer**
   - publish the explicit versioned setup marker and structured endpoint data;
   - preserve ordered TCP delivery and every UDP datagram boundary;
   - invoke the webhook for an empty UDP datagram;
   - publish a bounded terminal state;
   - accept one size-changing TCP replacement or one replacement datagram using
     the existing rewrite response path.
The adapter deliberately remains dormant when `raw_transport` is absent. It
does not infer raw transport from opaque content or change existing HTTP
classification.

Spider-side tests cover direct adapter use and the production packaged worker,
including bidirectional TCP mutation and expansion of a zero-length UDP
datagram. They also cover simultaneous flow state, terminal errors, retirement,
classification changes, unsupported control decisions and malformed metadata.
The direct lifecycle tests compare hook records and resulting bytes with the
checked-in mitmproxy 12.3.1 TCP and UDP wire corpora.
The native C++ webhook integration additionally carries an explicitly
classified TCP lifecycle through `process_webhook()`, the deployed worker and
back to a size-changing replacement response.

## Acceptance gates

The checked-in mitmproxy 12.3.1 TCP and UDP wire corpora remain the behavioral
targets. Completion additionally requires:

- TCP output equality across multiple producer fragmentation patterns without
  promising equal callback counts;
- bidirectional, size-changing TCP mutation with ordered stream output;
- UDP ordering and identity across multiple datagrams in both directions;
- zero-length UDP input and replacement, distinguishable from no callback;
- mutation to larger, smaller, and empty datagrams without merging or splitting;
- clean close versus transport error hook ordering;
- two simultaneous flows sharing script state while retaining independent
  message histories;
- generation retirement with active raw flows and exactly one terminal hook;
- malformed version, direction, sequence, endpoint, and boundary metadata;
- mixed HTTP and raw connections without cross-classification;
- packaged-worker, native C++ boundary, and end-to-end wire tests.

Until the producer and end-to-end gates pass, the implemented adapter must not
be described as live raw transport compatibility.
