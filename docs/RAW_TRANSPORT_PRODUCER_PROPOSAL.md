# Raw TCP and UDP producer proposal

Status: Spider adapter and reference corpora implemented; Smithproxy producer
requires separate discussion and approval.

## Purpose

Deliver real TCP stream chunks and UDP datagrams to the existing Spider-owned
mitmproxy compatibility worker without adding another transport engine or
parser. Smithproxy remains responsible for sockets, routing, stream reads and
datagram boundaries. Spider receives one explicitly classified native callback,
runs the addon hook synchronously and returns rewritten bytes through the
existing Opaque Part transaction.

This proposal does not authorize a Smithproxy change.

## Reference behavior

The checked-in `addon_tcp_v12.json` and `addon_udp_v12.json` corpora establish
ordinary start/message/end ordering and bidirectional mutation against a real
mitmproxy 12.3.1 reverse proxy. `addon_raw_control_v12.json` adds eight scenarios
for each protocol and was reproduced exactly in a second isolated run:

- start, message history and end use one flow identity;
- message history is append-only and alternates according to actual arrival;
- changing TCP content to empty drops that stream chunk;
- changing UDP content to empty forwards a real zero-length datagram;
- separate UDP datagrams remain separate after mutation;
- `flow.kill()`, direct `live` edits and direct `error` edits are state-only for
  raw TCP and UDP in mitmproxy 12.3.1;
- a clean `*_end` preserves that public flow state rather than normalizing it.

These points are intentionally counterintuitive. A kill in `*_start` or either
direction's `*_message` sets `flow.live` to false and installs
`Connection killed.`, but the current and later bytes still pass. Setting only
`live` or a custom `error` behaves the same way. Normal `*_end`, not `*_error`,
is delivered with the resulting state. Spider preserves this behavior without
requesting a transport-close operation from Smithproxy.

`addon_raw_error_v12.json` fixes three socket-failure boundaries and also
reproduces exactly in a second isolated run. A refused reverse-TCP target creates
no raw flow or hook. An established upstream reset ends with ordinary
`tcp_end`, keeping `live=True` and no flow error. UDP sent to an unreachable
loopback target still delivers both datagrams to the addon and later receives
ordinary `udp_end`; the observed ICMP condition does not become `udp_error`.
The producer must therefore not translate connection refusal, TCP reset or UDP
unreachability mechanically into addon error hooks.

## Producer envelope

Setup must attach `info.raw_transport` with exactly:

```json
{
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
```

Unknown endpoint observations are represented by `null`; display labels must
not be parsed into addresses. Content callbacks repeat the identity fields and
add `direction`, a connection-local contiguous `sequence`, and `unit`:

- TCP uses `stream-chunk` and may not publish an empty input chunk;
- UDP uses `datagram`, including a zero-length datagram;
- callback side `L` is client-to-server and `R` is server-to-client.

Terminal callbacks repeat the identity and provide:

```json
{"terminal": {"state": "closed", "message": ""}}
```

The alternative state is `error` with bounded human-readable text, reserved for
a producer failure that is explicitly classified as an addon transport error.
Ordinary connection refusal, reset and UDP unreachability do not qualify in the
observed reference behavior. Spider validates the complete envelope, endpoint
identity and sequence before invoking any addon hook.

## Native integration boundary

The producer needs only three observations:

1. setup after both endpoint descriptors and transport kind are known and the
   raw flow actually exists; a failed TCP target connection creates no flow;
2. one callback per actual TCP read or UDP datagram, before forwarding;
3. exactly one clean or error terminal observation.

For each content callback, the native `Message` must contain either one Opaque
Part covering the complete unit, or no Part for an empty UDP datagram. Spider
commits the existing Rewrite transaction after the synchronous hook. It does
not buffer TCP into application messages, merge datagrams, infer protocols or
own a socket.

Raw flow-state edits require no native decision. Interception remains fail-closed:
supporting it later would require an explicit producer suspension and bounded
resume contract rather than retaining bytes only in Python.

## Limits and failure behavior

Spider currently enforces per-flow and per-generation history limits, bounded
endpoint strings, exact schemas and monotonic sequences. A malformed envelope,
identity change, ambiguous Part shape, history replacement, quota violation or
unsupported interception invalidates the addon generation before publication.

Addon callback exceptions retain ordinary mitmproxy behavior: mutations made
before the exception are published and the failure is logged. Producer or
adapter failure must use the existing native fail-open policy until the
separately deferred strict ownership protocol is designed.

## Acceptance gates

- replay both ordinary reference corpora and the expanded control corpus;
- exact TCP chunk order under coalesced and fragmented producer callbacks;
- exact UDP datagram count, order and zero-length preservation;
- two simultaneous connections with shared addon state but isolated histories;
- endpoint identity and contiguous sequence rejection before hook dispatch;
- clean and error terminal ordering around client lifecycle hooks;
- generation and history quota tests;
- malformed metadata and connection-classification fail-closed tests;
- complete Spider addon regression and branch coverage on Rhino;
- end-to-end Smithproxy wire tests before removing loader fail-closed guards.
