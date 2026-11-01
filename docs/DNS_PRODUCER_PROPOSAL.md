# DNS addon producer proposal

Status: the dormant Spider-side envelope validator and lifecycle adapter are
implemented and fully covered. No live producer exists, so registration remains
fail-closed. This document does not authorize or implement changes in
Smithproxy or another project.

## Goal

Deliver truthful mitmproxy-compatible `dns_request`, `dns_response` and
`dns_error` callbacks without making Spider a resolver or a second DNS proxy.
Smithproxy remains the sole owner of sockets, upstream selection, UDP datagram
boundaries, TCP framing, retries and transport failure. Spider receives one
complete DNS message, exposes it through the existing clean-room model, and
returns one atomic decision through native Rewrite/Translate publication.

The checked-in mitmproxy 12.3.1 wire corpus fixes the first required behavior:

```text
dns_request
    -> addon creates a local response
dns_response
    -> addon mutates that response
wire receives the final response
```

The request and response share one `DNSFlow`. The request hook sees no response;
the response hook sees the locally created response. Message ID, question,
flags, answer TTL and final address are verified from the wire.

A second real UDP corpus fixes the forwarded path. The request hook changes the
question name before resolution. Mitmproxy's resolver then issues independent
A and AAAA upstream queries with EDNS and resolver-owned IDs, receives the
local answers, restores the original client ID, and publishes one response on
the same flow. The response hook changes TTL and address, and those final
values reach the client. The producer contract therefore concerns complete
logical DNS messages and flow identity; it must not promise preservation of
reference resolver-internal upstream packet IDs.

A third corpus fixes configured-resolver failure. When the selected resolver is
unreachable, mitmproxy 12.3.1 applies its resolver retry policy, synthesizes a
SERVFAIL response, calls `dns_response`, and delivers that response with the
original client ID. It does not call `dns_error` and does not set `flow.error`.
The native producer must therefore publish a synthesized DNS response as a
response event; it must not mechanically turn every upstream timeout or refusal
into an error event.

A fourth corpus fixes the client-side TCP boundary. Mitmproxy accepts a length
prefix split across writes, a payload split across writes, and a second complete
message pipelined before either response is read. Each framed message creates an
independent `DNSFlow` with its own request/response hook pair, while both flows
truthfully share the same client connection. The two responses retain their
individual message IDs and are returned as separate length-prefixed messages.
Spider must therefore never expose a TCP read chunk as a DNS callback unit.

A fifth corpus fixes exchange identity under concurrency. Two UDP clients use
the same 16-bit DNS ID while the local resolver holds both lookups and returns
the second lookup first. Across repeated reference runs, completion order is
intentionally not stable: either flow may publish its response first. The
request and response nevertheless remain paired by flow, both client responses
retain the shared wire ID, and qname-specific response mutations never cross.
The producer's opaque `exchange_id` is therefore mandatory; neither wire ID nor
arrival order can own lifecycle lookup.

A sixth corpus fixes the malformed datagram boundary. Empty input, one byte, an
11-byte header, a header declaring a missing question, a compression-pointer
loop, and an otherwise valid query with trailing bytes all receive no response
and invoke no addon hook. A clean baseline immediately afterward still receives
the expected local response. Complete-message classification therefore includes
strict consumption of the entire DNS payload; trailing input is not ignored.

A seventh corpus fixes local DNS error responses and proves the no-upstream
boundary. The request hook creates NXDOMAIN with `request.fail()`, the response
hook observes the same flow and changes the response to REFUSED, and the client
receives that final code with the original ID and question. A sentinel resolver
bound to the selected upstream address receives no packet. Local error responses
therefore use the ordinary request/response lifecycle and must bypass upstream
selection completely.

An eighth corpus fixes complex whole-message conversion. One compressed UDP
query carries two questions and one record in every remaining section, plus a
non-default opcode, AA, TC, RD, RA, every reserved bit and response code 7. Both
hooks observe the complete logical message. The response hook changes an answer
TTL and additional A address; the client receives both mutations while every
other field and section survives. Serialization consumes the whole packet and
normalizes compressed names to deterministic uncompressed record data.

The complex corpus exposed and fixed a clean-room codec gap: compressed NS
RDATA remained as a pointer into the original packet. A dedicated public-model
corpus now fixes the exact mitmproxy 12.3.1 normalization set across 25 standard
record types. The codec expands embedded names for NS, MD, MF, CNAME, MB, MG,
MR, PTR, SOA, MINFO, MX, RP, AFSDB, RT, PX, SRV and NAPTR. Record formats the
reference treats as opaque remain opaque. This prevents a stale compression
pointer from being serialized into a newly laid-out message without claiming
broader behavior than the reference.

## Producer classification

Smithproxy would add a versioned `dns_transport` object to the existing
structured callback metadata. Its absence retains current behavior. A setup
event describes the observed connection without classifying arbitrary UDP as
DNS:

```json
{
  "dns_transport": {
    "version": 1,
    "delivery": "dns-message",
    "transport": "udp",
    "client": {
      "peername": ["192.0.2.10", 41000],
      "sockname": ["192.0.2.20", 53]
    },
    "server": {
      "address": ["198.51.100.53", 53],
      "peername": ["198.51.100.53", 53],
      "sockname": ["192.0.2.20", 52000]
    }
  }
}
```

`transport` is `udp` or `tcp`. For UDP, one callback is exactly one datagram.
For TCP, Smithproxy removes and later restores the two-byte message length: one
callback is one complete DNS message, never an arbitrary stream chunk. DoH,
DoT and decoded HTTP/3 are not inferred as DNS transport. They need an explicit
future producer path if their public addon behavior is required.

## Exchange envelope

Each request carries the setup identity plus a producer-owned positive exchange
identity:

```json
{
  "dns_transport": {
    "version": 1,
    "delivery": "dns-message",
    "transport": "udp",
    "event": "request",
    "exchange_id": 17
  }
}
```

The callback contains one complete DNS payload in one native Opaque Part. The
Spider adapter uses its existing independent RFC 1035 codec to create the public
`DNSMessage`; it does not inspect a session label, port or payload to decide
whether the transport is DNS.

The producer must preserve concurrent exchanges even when DNS IDs collide. The
opaque exchange identity, not the 16-bit wire ID, owns flow lookup. The same
identity is used by a later `response` or `error` event.

## Request decisions

Spider creates one live `DNSFlow`, sets `flow.request`, runs `dns_request`, and
returns one structured decision:

```text
forward         publish the possibly mutated request to the upstream
local-response  do not contact upstream; continue with flow.response
```

If the addon sets `flow.response`, Spider immediately runs `dns_response` on the
same flow before returning `local-response`. The returned payload is the final
possibly mutated response. It is never published before the response hook.

`flow.kill()` has DNS-specific reference semantics. When the request hook kills
a flow without creating a response, Spider returns a synthesized SERVFAIL as a
`local-response`, skips `dns_response`, and does not contact the resolver. When
a response already exists, it still runs through `dns_response` and is returned
even if either hook kills the flow. Killing records the public non-live/error
state; it is not a DNS packet-drop or transport-termination decision.

An empty byte string is not a DNS drop sentinel. Invalid model state, a packing
failure, a malformed producer envelope or an ambiguous decision fails closed.

## Response and error decisions

For an upstream response, Smithproxy supplies the same exchange identity and
one complete DNS payload. Spider sets `flow.response`, runs `dns_response`, and
returns `replace-response` with the final packed message. Smithproxy then owns
UDP delivery or TCP re-framing.

For an upstream or transport failure, Smithproxy publishes a bounded structured
error:

```json
{
  "dns_transport": {
    "version": 1,
    "delivery": "dns-message",
    "transport": "udp",
    "event": "error",
    "exchange_id": 17,
    "message": "upstream timeout"
  }
}
```

Spider sets `flow.error`, runs `dns_error`, and releases the exchange. It does
not synthesize a DNS response unless addon code has explicitly produced one and
the reference contract confirms that behavior.

Every response, local response or error releases the flow
exactly once. A late, duplicate or cross-connection event is rejected.

## Ownership and limits

Smithproxy owns:

- UDP datagram and TCP length-prefix framing;
- upstream selection and connection reuse;
- retry, timeout and truncation/fallback policy;
- transport errors and client delivery;
- classification of a callback as a complete DNS message.

Spider owns:

- strict envelope validation and exchange identity;
- clean-room DNS model conversion;
- ordered addon dispatch in the generation's stable worker;
- bounded state and atomic decision serialization.

One worker may serve many DNS exchanges. Script and addon-object state therefore
remains coherent across flows without a worker per query. Active flow count,
wire payload size, packed replacement size and callback time are bounded. A
generation retirement aborts every retained exchange exactly once.

Malformed wire content never reaches addon code. Invalid addon mutations never
produce a partial packet. Logs identify the workspace, deployment and exchange
without recording DNS payloads by default.

## Required implementation work

1. **Spider lifecycle adapter**
   - implemented: validate setup and exchange envelopes;
   - implemented: parse one complete message through the existing clean-room
     codec;
   - implemented: preserve one flow across request/response/error;
   - implemented: dispatch local responses through both request and response
     hooks;
   - implemented: return explicit forward/local-response/replace-response
     decisions;
   - implemented: bound concurrent exchanges and packed message sizes;
   - pending producer integration: map one classified Opaque Part and the
     structured decision to native publication.
2. **Smithproxy producer** — separate cross-project approval required
   - classify complete DNS traffic explicitly;
   - preserve UDP datagrams and assemble/re-frame TCP messages;
   - publish truthful endpoints, exchange identity and errors;
   - await and apply one atomic decision;
   - never infer DNS from a port alone.
3. **Native boundary**
   - use the existing Opaque Part and Rewrite/Translate publication where it
     can represent a complete unit;
   - if local-response direction needs a generic additive helper, propose that
     helper before adding adapter-specific glue.

## Acceptance gates

The checked-in mitmproxy 12.3.1 local-response and forwarded-response corpora
remain the first wire targets. Completion additionally requires:

- request mutation reaching a real upstream and response mutation reaching the
  client (covered for UDP);
- local success, local error response and no-upstream proof (covered by real
  UDP corpora and direct adapter replay);
- `dns_error` ordering for producer-classified failures. A configured-resolver
  timeout/refusal is covered separately and produces `dns_response` with
  SERVFAIL in the reference;
- UDP and TCP message boundaries, including multiple TCP messages per stream
  (covered for a split first frame and two pipelined local responses);
- zero-length, truncated and trailing input rejection (covered for UDP), plus
  oversized input rejection;
- every DNS header field, multiple questions and all record sections (covered
  by a real compressed UDP corpus and direct adapter replay);
- compressed input names and deterministic valid output (covered by the same
  complex corpus);
- larger, smaller and exact maximum-size replacements (covered directly by
  the dormant adapter); one byte beyond the boundary remains fail-closed;
- concurrent exchanges with identical DNS IDs and out-of-order responses
  (covered for two clients; completion order is explicitly non-contractual);
- multiple clients sharing script state without flow-state crossover (covered
  directly by the dormant adapter with equal per-connection exchange IDs and
  reversed response completion);
- request-hook kill without a response synthesizes SERVFAIL, skips the
  response hook and never contacts upstream; request-hook kill with an existing
  local response still runs `dns_response`; response-hook kill preserves both
  local and upstream responses (covered by a real reference corpus and direct
  adapter replay);
- worker timeout, crash, restart and generation retirement without leaked or
  duplicated responses;
- malformed version, transport, event, exchange and endpoint metadata;
- mixed raw UDP and DNS traffic without cross-classification;
- packaged-worker, native boundary and end-to-end UDP/TCP wire tests.

Until the producer and end-to-end gates pass, DNS hooks remain rejected at
registration and must not be described as live DNS compatibility.
