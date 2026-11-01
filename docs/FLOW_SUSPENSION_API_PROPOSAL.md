# Flow suspension API proposal

Status: the historical proposal below is superseded by the callback-driven
Spider-only design. H1/H2 callback-driven interception is implemented; idle
wakeup and raw transport suspension remain outside the current contract.

## Current implementation boundary

`api.message.suspend(part, timeout_ms=60000)` stages a hold of complete logical
HEADERS/DATA Parts in the current direction. `api.message.resume(stream_id)`
returns editable retained Parts in a subsequent callback on the same connection,
from either direction. It resumes both directions if both are suspended for that
stream. Both operations require `api.message.translate()` to publish atomically.
Restored Parts keep their original direction. Reverse drafts use the existing
peer output context and `content-reverse`, not the triggering input context.
Use the Parts returned by `resume()` to edit the restored content. Reverse
drafts are not mixed into the incoming message's Parts list. Preparation of both
directions is atomic: neither bytes nor checkpoints are published if either
direction fails. New callback data is processed before reverse drafts, so any
received SETTINGS or stream cancellation applies to their publication.
The queue is owned by the existing native Translate control checkpoint; it does
not depend on keeping a Python worker alive.

Input HPACK continues while a stream is held. Output HPACK encoding happens only
when its logical Parts are released. Already-open sibling streams can continue;
younger client stream openings wait behind an older suspended opening because
HTTP/2 requires increasing stream IDs. No stream remapping is introduced.

Queues and input credit are bounded. Suspended DATA receives no stream-window
refund; bounded connection credit permits siblings to proceed. RST_STREAM and
GOAWAY discard affected held data. Publication failure leaves the host checkpoint
unchanged. Deadlines fail closed on the next callback; there is no idle timer.

The compatibility adapter now maps interception from completed H2 `request`
and `response` hooks to this primitive. A later callback can modify the retained
public flow and call `resume()` or `kill()`. Publication occurs on the next
callback of the owning connection, in either direction, without repeating the
completed message hooks. Body/trailer replacement, local responses and
termination still go through native APIs, including for reverse drafts.

H2 header-hook interception also uses native receive snapshots and prefix holds
while a body is incomplete; see `PROTOCOL_STATE_API_PROPOSAL.md`. No Smithproxy
hold queues or third persistent HPACK context are required. Idle/asynchronous
wakeup and raw TCP/UDP suspension remain outside this implementation. Native
HTTP/1 lane suspension is implemented separately below, including its addon
hook mapping.

### Native HTTP/1 lane suspension

HTTP/1 messages cannot independently overtake one another. Its suspension unit
is an ordered directional lane, named by id `0` and an explicit `side="L"` or
`side="R"`. Suspending a header retains that message and every later Part in
the callback, including younger pipelined messages. A later callback on that
lane keeps the pause unless the script explicitly resumes it.

```python
# In the callback that decides to pause this request:
api.message.suspend(api.message.parts[0])
return api.message.commit()
```

```python
# In a later callback on the SAME connection, in either direction:
parts = api.message.resume(0, side="L")
parts[0].http1.set_header("X-Inspected", "yes")
return api.message.commit()
```

`suspended_parts(0, side="L")` inspects detached copies of previously retained
Parts without consuming the hold. Returned resume drafts remain editable; H1
framing, content length and queued local responses use the existing native
publisher. Resuming an incomplete message removes its logical pause but keeps
the incomplete suffix in the ordinary reassembly hold. It does not publish an
incomplete body or invent a completion event.

A callback can resume a lane, edit its returned drafts, then suspend a younger
header in that lane before committing. Only the older prefix is published.
This also works for opposite-direction drafts, so pipelined interception does
not require an adapter-owned byte queue. Other duplicate or out-of-order
suspension commands in the same lane are rejected.

The host owns the serialized Parts and the pause checkpoint. A fresh worker
can resume them. In the opposite direction, publication returns reverse bytes
and the updated peer hold atomically, without mixing peer Parts into the
callback's input list. The host accepts such a peer-hold update only for an
owned paused lane (or a validated connection close). Failed assembly leaves
the host checkpoint unchanged. Connection termination discards both lanes.

The response-order ledger advances only for the emitted prefix. Held requests
do not allocate origin slots, and held responses do not consume them or release
queued local responses. Existing hold and deployment byte quotas remain in
force. Deadlines are checked on callbacks, not by an idle timer; no Smithproxy
change or background publishing channel is introduced. Existing host fail-open
policy remains a separate deferred concern, not a guarantee of connection close
when a deadline or script failure occurs.

The H1 addon driver pauses from header or complete-message hooks, and from
either hook of a generated response. A resumed header pause still waits for
body completion before delivering the complete-message hook. Delivered hooks
are never replayed. A callback first processes its own lane, then any peer lane
released by those hooks; a release initiated while processing that peer can
wait until the next callback rather than recursively draining both lanes.
Generated replies use the existing native local-response publisher and ledger.

The H1 black-box probe `tests/probes/addon_local_intercept_h1_probe.py` records
the same order-sensitive local-response kill behavior as H2: bare kill and
kill-then-resume remain pending during a two-second observation window, while
resume-then-kill closes the connection. Spider uses native connection close for
all three cases, with the working resume-then-kill error-hook ordering. It does
not reproduce a pending killed connection. The corpus records reference output
unchanged, and tests explicitly distinguish this deviation from resume parity.

### Generated H2 responses

An addon-created response can intercept in `responseheaders()` or `response()`.
The public response keeps its body, unlike the initially empty body of an
upstream response header hook. Spider tracks the two response-hook delivery
steps independently from the request. The native suspension retains the
unforwarded request anchor; resume runs only the remaining hooks, then calls
the existing native `respond()` on the restored anchor. Both callback directions
use the same path, including a second interception in the response hook.

Response replacement, body edits and trailers are read from the current public
response at publication. Intercepted local bodies are limited by the driver's
retained-body limit; native output quotas, windows and HPACK rules still apply.
A reset discards the pending response. Native publication failure invalidates
the addon generation rather than replaying arbitrary hook side effects.

### Deliberate difference: kill must wake an intercepted local response

The isolated mitmproxy 12.3.1 black-box probe
`tests/probes/addon_local_intercept_probe.py` observes this distinction at both
local response hooks:

- `resume()` sends the edited response;
- `kill()` and `kill(); resume()` send neither response nor reset within the
  five-second observation window, although subsequent streams still work;
- `resume(); kill()` sends `RST_STREAM(INTERNAL_ERROR)`. It invokes `error()`
  after a response-header interception, but not after `response()` was delivered.

The order-sensitive result strongly suggests a lost wakeup in the reference;
the probe does not claim to prove an infinite wait. Its results are preserved in
`tests/corpus/addon_local_intercept_h2_v12.json`.

By explicit design decision, Spider does not reproduce the pending-stream
behavior. Killing an intercepted local response emits the native reset without
publishing its body. Hook ordering follows the reference's working
resume-then-kill case. This is a documented compatibility deviation, not a claim
of identical output for the reference's bare-kill case.

## Historical proposal (not the current API contract)

## Objective

Provide a general, bounded Spider transport suspension primitive that can back
long-lived `flow.intercept()` / `flow.resume()` behavior without blocking a
script callback, inventing another HTTP engine, or holding an entire addon
worker hostage.

This is not a mitmproxy-specific operation. Native Spider scripts, policy
engines and future interactive tools may also need to stop one HTTP exchange at
an exact publication boundary and resume or terminate it later.

The operation must reuse native Parts, hold, Rewrite and Translate ownership.
It must not parse HTTP in Python, copy HPACK state into the compatibility layer,
or introduce a second proxy process.

## Why the existing hold is insufficient

`message.parts.hold_from(part)` is callback-local backpressure. It retains an
incomplete suffix until a later payload callback and is released by returning a
new commit for that same native flow. It is intentionally not a control plane.

Long-lived interception differs in four important ways:

1. a complete message may be suspended even when no more input will arrive;
2. the addon callback must return before the ordinary callback deadline;
3. resume may originate from a background addon task or an external operator;
4. other connections and HTTP/2 streams using the same script generation must
   continue to receive serialized callbacks.

Waiting inside the original callback would consume its CPU/wall budget and
block every flow sharing that worker. Re-running the original hook on resume
would duplicate addon side effects. Treating an ordinary hold as a suspension
would leave no reliable wake-up path.

## Proposed native operation

The additive callback-local operation is:

```python
api.message.suspend(
    anchor,
    reason="operator review",
    timeout_ms=60_000,
)
return api.message.commit()
```

`anchor` is the initial typed request or response header Part for the exchange.
The operation is valid only for a live flow deployment at the end of its
enabled chain. It returns a `SuspendedCommit`, analogous to `HeldCommit`, with:

- the safe publishable prefix before the selected exchange;
- a bounded native hold checkpoint for the selected exchange;
- an opaque suspension request identity;
- the exact protocol, connection, direction and stream/exchange anchor;
- the requested reason and bounded deadline.

The backend, not Python, accepts the request and creates the authoritative
suspension token. No uncommitted bytes are published before that acceptance.
Failure to reserve capacity rejects the complete transaction atomically.

This API is backward-compatible and inert for scripts that do not call it.
It does not change ordinary hold, Rewrite or Translate behavior.

## Host-owned token

A token is scoped to all of the following:

- workspace and deployment generation;
- pinned addon worker generation;
- native connection identity;
- HTTP/1 exchange or HTTP/2 stream;
- direction and exact publication checkpoint.

Tokens are random, opaque and single-use. The host stores bounded metadata but
never serializes Python flow objects. A token cannot be replayed after resume,
kill, timeout, connection loss, worker failure or deployment retirement.

The state machine is intentionally small:

```text
ACTIVE -> SUSPENDED -> RESUMING -> RELEASED
                    \-> KILLING -> TERMINATED
                    \-> EXPIRED
                    \-> ABORTED
```

Only one terminal transition wins. Duplicate or late actions return the final
state without publishing bytes again.

## Resume and kill control

The host exposes two internal operations to the owning worker:

```text
resume-suspension(token)
kill-suspension(token, reason)
```

Resume clears the public flow's intercepted state and publishes the retained
native transaction exactly once. It does not run the original request or
response hook again. Kill uses the already approved protocol-owned termination
operation: HTTP/1 closes at the callback boundary and HTTP/2 resets only the
selected stream.

The compatibility adapter maps public operations as follows:

```text
flow.intercept()  -> stage message.suspend(anchor, ...)
flow.resume()     -> request resume-suspension(token)
flow.kill()       -> request kill-suspension(token, "Connection killed.")
```

The flow object remains the same object throughout suspension. Later hooks see
the same mutations, metadata, connection descriptors and addon-owned state.

## Persistent worker control plane

The current worker protocol is synchronous request/response over standard I/O.
Its event loop runs only while a request is being processed, and the parent
does not read unsolicited worker output. That is sufficient for callbacks but
not for an addon background task which calls `flow.resume()` while no traffic
callback is active.

Full compatibility therefore requires a general worker-control channel, not a
sleep or polling loop inside the hook:

1. the addon event loop remains alive for the lifetime of the generation;
2. native callbacks are queued and dispatched serially on that loop;
3. background addon tasks may run between callbacks within the same sandbox;
4. suspension-control events use a framed, versioned side channel with request
   identities and bounded messages;
5. the parent validates generation and token ownership before applying any
   native release;
6. loss of either channel retires the generation and resolves all tokens.

The side channel may be a pre-created `SOCK_SEQPACKET` pair or two framed pipes.
It must be created before sandbox activation and explicitly admitted by the
sandbox. It must not provide arbitrary file, network or process access.

An external operator action uses the same token path but does not require an
addon background task. Supporting only external actions would be a useful first
integration milestone, but it must not be described as complete
`flow.intercept()` compatibility.

## Native protocol behavior

### HTTP/1

- Hold the selected exchange and all younger pipelined exchanges behind it.
- Preserve response ordering and queued local responses.
- Resume publishes the retained request or response once.
- Kill uses the existing callback-local connection termination primitive.
- A connection close aborts all its tokens without attempting publication.

### HTTP/2

- Suspend only the selected stream; sibling streams continue normally.
- Retain the existing stream and connection flow-control accounting exactly
  once, including body reservation and later refund.
- Preserve source and peer HPACK checkpoints through the existing Translate
  transaction ownership.
- Resume publishes the retained stream once.
- Kill emits the existing stream-local `RST_STREAM(INTERNAL_ERROR)` behavior.
- GOAWAY and peer RST_STREAM resolve the token before their normal error hook.

## Bounds and failure policy

The backend enforces per-workspace and per-generation limits for:

- active suspension count;
- retained bytes and serialized checkpoint bytes;
- maximum requested and effective lifetime;
- pending control messages;
- tokens per connection.

No timeout may silently forward traffic. Expiry is fail-closed and produces an
explicit suspension error before protocol-owned termination. Deployment
retirement, worker failure and lost control channels follow the same rule.

The previously explored `socket-ignore-v3` mechanism may later provide an
optional transparent-routing quarantine before a failed connection is closed.
That can prevent a retried application connection from escaping inspection,
but it belongs to Smithproxy/network policy and is not a dependency of this
Spider API. Adding it would require separate cross-project approval.

## Required tests

Implementation is not complete without all of these gates:

- exact reference hook and state ordering for intercept, delayed resume and
  resumed response (fixed by a reproducible 12.3.1 corpus and contract test);
- resume after the ordinary callback deadline without worker timeout;
- addon-scheduled resume while no other traffic callback is active;
- external resume and kill through the same token state machine;
- HTTP/1 sequential and pipelined exchanges;
- HTTP/2 fragmented bodies, two concurrently active streams, exhausted stream
  and connection windows, RST_STREAM and GOAWAY;
- mutations before interception surviving resume exactly once;
- duplicate, stale, wrong-generation and wrong-connection token rejection;
- connection loss, worker crash and deployment retirement;
- quota and deadline exhaustion with no forwarded retained bytes;
- cleanup when addon `done()` raises;
- no impact on ordinary hold, Rewrite, Translate, local responses or
  termination when suspension is unused.

## Approval boundary

This document changes no native API or behavior. Approval is required before:

1. adding `message.suspend()` or a `SuspendedCommit`;
2. adding the worker side channel or persistent event-loop service;
3. adding host token storage and resume/kill operations;
4. connecting the compatibility adapter to live suspension.
