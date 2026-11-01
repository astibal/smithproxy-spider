# HTTP CONNECT producer proposal

Status: five independent mitmproxy 12.3.1 wire corpora define regular,
upstream-proxy, authentication and control behavior. The public hook values and
a dormant Spider lifecycle adapter are implemented with full branch coverage,
but no live producer exists. Registration therefore remains fail-closed. This
document does not authorize changes in Smithproxy or another project.

## Goal

Expose truthful mitmproxy-compatible HTTP CONNECT hooks while keeping CONNECT
parsing, target selection, sockets and tunnel ownership in Smithproxy. Spider
must receive ordered native observations for one stable `HTTPFlow`; it must not
infer lifecycle events from payload bytes, response codes or server callbacks.

## Verified regular-proxy lifecycle

The checked-in reference corpus drives real CONNECT requests through mitmproxy
12.3.1. It establishes the following order and state:

1. `http_connect`
   - the complete CONNECT request has been parsed;
   - `flow.response` is absent;
   - the server address and peer name are absent;
   - this is the decision point before opening the target connection.
2. Successful target connection: `http_connected`
   - the same flow object is retained;
   - `flow.response.status_code` is `200`;
   - the server address is the requested destination;
   - the server peer name is present;
   - the client receives `HTTP/1.1 200 Connection established`.
3. Failed target connection: `http_connect_error`
   - the same flow object is retained;
   - `flow.response.status_code` is `502`;
   - the requested server address is present, but the peer name is absent;
   - `flow.error` remained absent in the observed reference behavior;
   - the client receives `HTTP/1.1 502 Bad Gateway`.

`http_connect_error` must therefore not be approximated as an ordinary
`flow.error`, and `http_connected` must not be synthesized from the generic
server-connected callback.

## Verified upstream-proxy lifecycle

Upstream mode has a separate, deliberately lazy sequence:

1. `http_connect` is emitted for the client CONNECT request with no response and
   no server address.
2. `http_connected` follows with a client-facing `200`. The server address is
   the requested destination, but there is no connected peer yet.
3. Only after the client sends the first tunneled bytes does mitmproxy contact
   the upstream HTTP proxy.
4. `http_connect_upstream` is emitted for the same flow immediately before the
   upstream CONNECT exchange. At that point `flow.response` is absent and the
   server descriptor addresses the connected upstream proxy.

The two meanings of the server descriptor are part of the compatibility
contract. The same `Server` object and public connection ID are preserved while
its native observations change across these hooks. Regular and upstream-proxy
events must not be collapsed into one generic "CONNECT succeeded"
notification.

## Proposed native observations

Smithproxy would publish bounded structured observations tied to its native
connection and CONNECT transaction identities:

```json
{
  "http_connect": {
    "version": 1,
    "event": "request",
    "connection_id": "...",
    "transaction_id": "...",
    "request": {
      "authority": "example.test:443"
    }
  }
}
```

Later observations would use `target-connected`, `target-error`, and
`upstream-connect` events. They carry only native facts required to update the
existing flow and connection descriptors. Response objects are created from
explicit native outcome fields, never guessed from timing or socket state in
Spider.

Each observation is processed synchronously before the corresponding wire
action. The generation that accepted `request` owns the complete CONNECT
lifecycle; late results from a retired generation or closed connection are
discarded.

## Verified addon decisions

A second checked-in wire corpus establishes the ordinary HTTP/1 control
semantics:

- assigning a local response in `http_connect` prevents the target connection,
  sends that response to the client and then invokes `http_connect_error` with
  the same response;
- `flow.kill()` in `http_connect` marks the flow dead, closes the client without
  a response and suppresses later CONNECT hooks;
- changing `flow.request.host` or `flow.request.port` reroutes the actual target
  connection;
- response status mutation in `http_connected` changes the successful wire
  response;
- response status mutation in `http_connect_error` changes the failure wire
  response;
- `flow.kill()` in either outcome hook changes the public flow state but is too
  late to replace the already-prepared 200 or 502 response.

The request-stage native result therefore needs one atomic decision with three
mutually exclusive outcomes: continue with the possibly changed destination,
send a complete local response, or kill. Outcome-stage results carry response
mutation; late kill remains observable on the public flow but has no additional
wire action. This is a generally useful connection-decision boundary rather
than Python-side CONNECT framing.

## Verified proxy-authentication interaction

With built-in proxy authentication enabled, every complete CONNECT request
still enters the CONNECT lifecycle:

- missing credentials enter `http_connect` with a local 407 response and no
  `Proxy-Authorization` header, then enter `http_connect_error`;
- incorrect credentials enter the same two hooks with a local 407 response, but
  the rejected `Proxy-Authorization` header remains observable;
- accepted credentials enter `http_connect` without a response and with the
  authorization header removed, then proceed to `http_connected`.

Only the accepted request contacted the target. Authentication therefore occurs
before target selection but does not suppress the hooks. The native producer
must expose the already-decided local response and the same sanitized request
view that the configured authenticator produced; Spider must not reimplement
credential validation.

## Verified upstream-control behavior

The final corpus fixes behavior after the client-facing CONNECT has already
been acknowledged:

- `http_connect_upstream` receives a non-live flow;
- changing request host or port changes the authority sent in the actual
  upstream CONNECT request;
- `flow.kill()` raises `mitmproxy.exceptions.ControlException` with
  `Flow is not killable.` and does not prevent the upstream request;
- assigning a local response changes the detached flow value but does not
  prevent the upstream request or replace the already-sent client response;
- an upstream 502 closes the established client tunnel and does not emit a new
  `http_connect_error`.

This hook therefore has one transport-effective mutation: changing the upstream
CONNECT authority before Smithproxy serializes that request. It is not a second
general CONNECT decision point. The compatibility adapter must preserve the
non-live state and existing `Flow.kill()` error instead of pretending that
late kill or response replacement succeeded.

## Failure and security rules

- malformed or oversized observations are rejected before addon dispatch;
- callback timeout, worker failure and generation retirement follow the
  explicit deployment failure policy;
- no timeout may accidentally open a target or acknowledge a tunnel;
- authority and authentication material are bounded and never logged as raw
  secrets;
- one connection cannot reuse another connection's transaction identity;
- ordinary HTTP requests, SOCKS negotiation and HTTP/2 extended CONNECT are not
  classified as this HTTP/1 lifecycle.

## Required implementation work

1. **Reference evidence**
   - completed: regular success and target-connect failure wire corpus;
   - completed: lazy upstream-proxy CONNECT wire corpus;
   - completed: local response, kill, reroute and outcome-mutation corpus;
   - completed: built-in proxy-authentication interaction corpus;
   - completed: upstream-control and failure corpus.
2. **Spider adapter**
   - completed: validate a versioned, bounded native envelope;
   - completed: preserve one flow and native connection descriptor identity;
   - completed: dispatch callbacks synchronously and return only proven
     request, response and upstream-authority decisions;
   - completed: reproduce non-live late-hook behavior and late kill failure;
   - pending: connect the adapter only after a native producer exists;
   - keep registration fail-closed until end-to-end support exists.
3. **Smithproxy producer** — separate cross-project approval required
   - publish events at the actual parser, target-selection and connection
     boundaries;
   - await decisions before target connection and client/upstream replies;
   - retain all parser, socket and tunnel ownership.

## Acceptance gates

- exact reproduction of all checked-in mitmproxy 12.3.1 wire corpora;
- the same flow identity and exact hook order on every path;
- complete local-response, kill, reroute and outcome-mutation corpus;
- built-in proxy-authentication interaction corpus;
- upstream-control and failure corpus;
- fragmented HTTP/1 input and pipelined bytes following CONNECT;
- successful, refused, timed-out and aborted target connections;
- lazy upstream connection, upstream rejection and disconnect races;
- worker exception, timeout, crash, redeploy and generation retirement;
- concurrent CONNECT transactions without identity or state crossover;
- packaged-worker, native-boundary and end-to-end wire tests;
- a separately approved design for HTTP/2 CONNECT before enabling that path.

Until every applicable gate passes, all `http_connect*` and `http_connected`
callbacks must continue to fail deployment rather than load as inert hooks.
