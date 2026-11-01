# Native request destination-routing proposal

Status: design only. Implementing this proposal changes both Spider's native
inspection contract and Smithproxy's upstream selection. Both changes require
explicit approval. Spider must never open an upstream socket itself; Smithproxy
remains the sole proxy and transport owner.

## Compatibility target

Mitmproxy addons may change `flow.request.host`, `port`, or `scheme` in either
`requestheaders` or `request`. The checked
`tests/corpus/addon_reroute_v12.json` observation against mitmproxy 12.3.1 proves
the minimum externally visible contract:

- the request is sent to the changed destination;
- the Host header reflects that destination;
- later hooks observe the changed endpoint;
- the original destination is never contacted;
- both the headers hook and the completed-request hook can make the choice.

This is upstream selection, not a byte-only header edit. The current adapter
therefore rejects such mutations before publication instead of falsely
reporting success.

## Proposed native operation

Add one callback-local operation on a retained request:

```python
api.message.select_upstream(
    request_part,
    host="destination.example",
    port=443,
    scheme="https",
)
```

The name is deliberately transport-oriented rather than mitmproxy-specific.
The operation stages a desired upstream endpoint on the current request; it
does not create a connection and does not publish bytes. The ordinary
`commit()` or `translate()` call publishes the request bytes and the staged
selection as one validated callback result.

For the compatibility adapter, users do not call this method. The adapter
compares the public Request endpoint with its original endpoint, updates the
native request draft, and stages `select_upstream()` when they differ.

The initial API should accept only DNS names or IP literals, integer ports from
1 through 65535, and `http` or `https`. A later protocol-independent endpoint
type can replace these scalar arguments only if another native consumer needs
it; it is unnecessary for the current HTTP contract.

## Publication boundary

The inspection result needs a bounded structured control member, for example:

```json
{
  "action": "replace",
  "content": "...",
  "upstream": {
    "host": "destination.example",
    "port": 443,
    "scheme": "https"
  }
}
```

This is illustrative, not a wire-format approval. C++ must construct and
validate the member from the staged native operation. User scripts must not be
able to return arbitrary webhook control JSON.

Smithproxy must consume the replacement and the upstream selection before it
releases any request bytes. It either accepts both or rejects both. A rejected
selection must not fall back to the original destination.

### HTTP/1

The operation is valid only while the initial request is retained and no bytes
from that request have reached an upstream peer. In `requestheaders`, the
header can be replaced and routed before the body is released. In `request`,
the complete retained request is routed after the callback.

Reusing an already connected upstream socket is valid only when its endpoint
matches the selected endpoint. Otherwise Smithproxy opens or reuses a
connection for the new endpoint according to its own pool policy. Spider does
not emulate this policy.

### HTTP/2

The selection is per request stream, not per downstream connection. Two
multiplexed client streams may select different upstream endpoints. Smithproxy
must either provide per-stream upstream mapping and stream-ID translation or
reject the operation before publication. Silently applying one stream's target
to its siblings is forbidden.

Source HPACK state still advances from the received client block. The selected
upstream connection's encoder owns the destination HPACK state. Spider may
provide logical headers, but it must not transplant a header block encoded for
another upstream connection.

This is the largest architectural risk in the proposal and must be checked
against Smithproxy's actual H2 connection ownership before implementation.

## Header and endpoint consistency

The public Request model already keeps `host`, `port`, `scheme`, authority, URL,
and Host header behavior consistent. The native commit must use that resulting
model rather than independently synthesizing another authority.

For ordinary HTTP requests:

- HTTP/1 absolute-form targets and Host are rebuilt for the selected endpoint;
- HTTP/1 origin-form requests retain their path and update Host;
- HTTP/2 updates `:scheme` and `:authority` while preserving `:method` and
  `:path`;
- CONNECT and extended CONNECT require separate observations before support and
  must initially fail closed.

## Lifecycle integration

Destination routing and the deferred server lifecycle hooks share one source of
truth. A selected endpoint should become the Server address observed by
`server_connect`; successful socket establishment emits `server_connected`,
failure emits `server_connect_error`, and teardown emits `server_disconnected`.

Implementing routing before those observations is possible, but the routing
result must retain enough structured state to add truthful lifecycle events
later. No synthetic server hook should be inferred from a successful callback.

## Failure behavior

The following cases fail before request publication:

- invalid host, port, or scheme;
- a request Part that is incomplete, already published, or retired;
- a response or non-initial header Part;
- a second conflicting selection in the same transaction;
- missing Smithproxy routing capability;
- an H2 stream whose selected endpoint cannot be isolated from siblings;
- a policy-denied destination.

An upstream connection failure after a valid selection follows the ordinary
proxy failure lifecycle. The acceptance corpus must determine the exact HTTP/1
and HTTP/2 client wire result and `error()` ordering; the current successful
reroute corpus is not evidence for those failure semantics.

## Security and policy

Addon-controlled rerouting is an SSRF-capable operation. Smithproxy remains
responsible for namespace, routing, egress and destination policy. The initial
implementation must preserve the same policy boundary used by ordinary
upstream connections and must not bypass workspace routing through a Spider
host socket.

Deployment capability should be explicit. A script that mutates destinations
without the capability fails closed; it must never degrade into a Host-only
rewrite or original-destination forwarding.

## Required acceptance gates

Before implementation can be called compatible, tests must cover:

1. the checked HTTP/1 `requestheaders` and `request` corpus exactly;
2. zero contacts to the original destination;
3. absolute-form and origin-form HTTP/1 requests;
4. request bodies split at every producer callback boundary;
5. connect success, refusal, timeout, DNS failure and policy rejection;
6. header/authority consistency after rerouting;
7. same-target connection reuse and different-target reconnection;
8. two H2 sibling streams selecting the same endpoint;
9. two H2 sibling streams selecting different endpoints;
10. source and every destination HPACK checkpoint after success and failure;
11. flow-control accounting and request-body cancellation on failed selection;
12. generation retirement, worker failure and callback timeout before commit;
13. quota rollback when endpoint or translated output validation fails;
14. truthful server lifecycle ordering once producer observations exist;
15. a packaged-worker addon that mutates `flow.request.host` and `port` without
    importing or invoking native API objects directly.

## Explicit non-goals

- Spider does not become an HTTP client or a second proxy.
- No new transaction mode is introduced.
- The operation does not implement replay, retries, load balancing, DNS policy,
  CONNECT tunneling, or transparent-network routing.
- Header-only rewrites are not presented as destination changes.
- An unsupported H2 topology is rejected rather than approximated.
