# H2 translate: first live integration (API 0.6)

**Experimental, limited scope.** The API runs through the regular backend and
sandboxed workers. It is not a complete H2 terminator or transparent support for
every HTTP/2 connection. Unsupported state is rejected, not bypassed.

## Getting started

1. The proxy must include the webhook control patch and send content metadata
   `webhook_control: {version: 1, mode: "regular"|"strict", sequence: N, rewrite: true}`.
   `sequence` counts content callbacks for the whole connection, across both directions.
2. The Python worker needs `python-hpack`. Without it, rewrite still works,
   but translate raises CommitException.
3. Enable exactly one deployment with `flow` instancing. Scope and session filter
   determine admission; activation is allowed only in the first callback (`sequence == 1`).
4. Explicitly reserve rewrite during setup (`api.phase == 'setup'`) and return
   `None`. There is no `api.message` here. Easy and Expert need the same reservation;
   create a new connection, since an existing unreserved session cannot be upgraded.
   The same-length raw replacement exception does not activate Translate or a second
   protocol context and does not replace reservation.
5. Every **content** callback must return a translate result. Setup only reserves
   rewrite capability; it does not activate Translate.

Steps 1 and 4 describe the current proxy. For a legacy control-v1 peer without
`rewrite`, the backend retains compatible permission (not implicit `false`),
still requiring first sequence, one flow deployment and subsequent strict confirmation.
Without control-v1 capability, Translate cannot start. See
[metadata compatibility](INSPECTION_COOKBOOK.md#capability-metadata-compatibility);
this does not promise support for every old proxy version.

<!-- translate-example: replace-header -->

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

for part in api.message.parts:
    if part.type == PartType.Http2.Header:
        part.headers.set_header(b"x-lab", b"spider")
return api.message.translate()
```

Even when nothing needs editing:

<!-- translate-example: unchanged -->

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

return api.message.translate()
```

## Examples: indexed headers and explicit translation

Unlike rewrite, this does not write a numeric index. Active translate exposes the
decoded name and value; its own encoder manages output indexing. The same
`set_header()` works even when only an index arrived on the wire.

For a test endpoint, change `x-lab` only in the second client callback. The first
activates translation and populates the input table. In this small scenario each
client callback contains one HEADERS block; a callback is not generally a request.

<!-- translate-example: indexed-once -->

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

if api.side == "L":
    turn = api.state.get("client_callbacks", 0) + 1
    api.state["client_callbacks"] = turn

    if turn == 2:
        for part in api.message.parts:
            if part.type == PartType.Http2.Header:
                part.headers.set_header(b"x-lab", b"changed")

# The third callback must translate too, even without further edits.
return api.message.translate()
```

| Callback | Sender input | Receiver value |
| --- | --- | --- |
| 1 | literal `x-lab: original`, inserted into the table | `x-lab: original` |
| 2 | dynamic index 62 (`be`) | `x-lab: changed` |
| 3 | index 62 (`be`) again | `x-lab: original` |

Index 62 follows from this fixture, not a fixed index for that header. The script
does not handle indexes. Tables are direction-specific, so server responses need
not use the same indexes. The reverse direction must also always translate.

### Incorrect example: no edit means no translation

This script is **deliberately wrong** for already active translate:

<!-- translate-example: missing-translate -->

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

return None
```

The worker rejects the result because explicit `api.message.translate()` is
missing. The backend returns 503 and the strict proxy closes the connection.
`return api.message.commit()` does not satisfy this requirement either: it is a
local rewrite, not continued HPACK translation.

### Incomplete frame or HEADERS/CONTINUATION across callbacks

<!-- translate-example: hold-incomplete -->

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break

    if part.type == PartType.Http2.Header:
        part.headers.set_header(b"x-lab", b"changed")

return api.message.translate()
```

The script selects the hold boundary. The complete prefix is translated and sent;
the suffix remains typed Parts. An empty prefix returns `need-more`, activating
or preserving strict policy. The next callback in that direction completes the
frame/block; the reverse direction has separate hold and HPACK tables and continues
running its callback.

The HPACK checkpoint represents only the **emitted prefix**. Held headers may
provide decoded script views but do not permanently advance tables. Logical edits
to complete held headers survive; collect incomplete parts before editing them.
Running the script again can repeat edits: use your own state for non-idempotent changes.

Until a complete nine-byte frame header is available, its fragment is
`PartType.Opaque` with `complete == False`; even its stream ID is not yet known.
An H2 preface prefix can similarly be held. This framing applies to active H2
translate, not arbitrary protocol guessing from opaque data. First activation
still requires H2 preface (or its prefix) or an H2 annotation from the proxy.

`api.message.bytes` still contains the current callback; the full restored view
is in `api.message.parts`. Hold uses the existing 1 MiB serialized checkpoint
limit and 4 MiB deployment quota; restoration beyond 1 MiB input bytes is rejected.
Exceeding a limit during active translate fails and closes the connection, not bypasses it.

Tests read these marked examples directly and execute them in sandboxed workers.
The indexed scenario checks actual `be` input and independently decodes output
values with libnghttp2, not merely a return status.

**The engine does not decide whether running the script is worthwhile.** Every
content callback in an active connection runs its script, including DATA,
SETTINGS/PING and the reverse direction. Filters, scope, GUI decisions and
heavy-traffic cutoff must not silently skip it. Scripts may branch internally
but must return translate.

## State and failures

- The backend pins a connection to deployment ID/version. Other deployments do
  not enter its flow. Input/output and L/R HPACK tables are separate.
- State travels as bounded JSON checkpoints, not pickle or Python globals. The
  worker may change between callbacks. The limit is 64 KiB per direction; these
  checkpoints count toward the 4 MiB deployment limit with user state and hold.
  The shared SETTINGS checkpoint also has a 16 KiB limit.
- The first successful result carries `control.mode=strict` with replacement.
  The new proxy applies control before replacement. The next callback must confirm
  strict and exactly consecutive sequence. This is capability/state checking,
  not a separate round-trip handshake before the first rewrite.
- After activation, error, timeout, overload, `return None`, missing translate,
  expired state, disable/redeploy or sequence gaps yield HTTP 503. The strict proxy
  closes without releasing current content. The backend retains the failed pin
  until connection-stop instead of attempting to restart tables.
- Strict is not automatically active before the first successfully published
  Translate result. Failure of that first attempt may leave original content
  unchanged under regular policy (fail-open); `set_mode` alone does not enable
  strict on the proxy.
- A strict callback without a known pin (for example after Spider restart) is
  rejected too. Missing capability on an old proxy never allows first translation.
- Tables are not published to the GUI or user `api.state`. Successful preparation
  is not transmission: only returning the script result publishes them.

## SETTINGS and limit acknowledgement

### Same-length DATA

Translate permits `set_bytes()` on a complete DATA part, preserving length.
Frame header, stream ID, all flags including END_STREAM, pad-length byte and
padding remain exactly original. Flow-control accounting therefore remains unchanged;
WINDOW_UPDATE is not translated.

For known uncompressed content, this example masks a six-byte word within one
DATA frame. It does not search across frame boundaries or decompress.

<!-- translate-example: data-redaction -->

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

api.connection.set_mode(Mode.Translate)
for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break
    if part.type == PartType.Http2.Data:
        part.set_bytes(part.get_bytes().replace(b"secret", b"******"))
return api.message.translate()
```

Replacing six-byte content with `part.set_bytes(b"short")` raises
`CommitException` at translate: resizing needs further flow-control support.
Changing DATA stream ID, type or flags is also rejected. A failed transaction
publishes none of the preceding edited parts. Complete edited parts may be held;
hold incomplete parts first and edit only after completion. Same-length replacement
needs no `content-length` repair. This mode does not automatically repair body
integrity metadata such as digests.

### Explicit mode and persistent limit

```python
api.connection.set_mode(Mode.Translate)
api.connection.http2.enforce_header_table_limit(0)

for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break

return api.message.translate()
```

Both calls are idempotent and only stage intent. The first requires flow instancing
and an eligible live H2 connection. The second sets a persistent maximum for both
directions. Omitting `return message.translate()` after `set_mode()` is an error;
nothing is published. Activation through `message.translate()` alone remains
compatible. `Mode.Rewrite` cannot revert an already translated connection.

The policy caps future SETTINGS and never raises a smaller peer-advertised limit.
After handshake it may insert its own SETTINGS; the engine consumes that ACK
rather than forwarding it as acknowledgement of a peer request. Original ACKs
still pass through. Repeating the same setting generates no additional frames.

Each direction receives the policy at its next eligible callback after its first
SETTINGS. Standalone insertion also waits for hold to clear. This is neither an
immediate broadcast to both sockets nor a background task. Zero disables the
dynamic table, not static indexes or Huffman. Setters cannot run after `translate()`.

SETTINGS and ACK still pass through explicit `return api.message.translate()`.
Frames are forwarded unchanged; no extra script call is required to process them.
SETTINGS from R constrain L and vice versa.

- Each direction has a FIFO queue of at most 64 pending SETTINGS, including empty
  ones or unknown identifiers. ACK acknowledges the oldest entry.
- Input validation applies a new limit after ACK. Before ACK, data using old limits
  may still arrive. An ACK without pending SETTINGS is an error.
- Shrinking the HPACK table requires a matching table-size update in the next
  header block. Shrink-then-grow preserves the minimum and final capacity.
- The input decoder respects advertised capacity; checkpoint quotas still apply.
  The output encoder uses at most 4096 bytes even when the peer permits more.
  This is a legal smaller capacity, not a limit on peer input.
- MAX_FRAME_SIZE controls input-frame validation and output HEADERS/CONTINUATION
  splitting. A change may be acknowledged within a single callback.
- Held SETTINGS/ACK do not change published state; it advances with the emitted
  prefix. Failed commit publishes nothing.

Synchronization follows [RFC 9113 §6.5.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.5.3),
and HPACK capacity changes follow [RFC 7541 §4.2](https://www.rfc-editor.org/rfc/rfc7541.html#section-4.2).

## PUSH_PROMISE

Translate also handles HPACK in PUSH_PROMISE. Its type is `PartType.Http2.Header`,
`frame_type == 5`, and `stream_id` identifies the original client stream, not
the promised stream. Promised ID and padding are preserved. The block may span
CONTINUATION and multiple callbacks; the script must explicitly hold incomplete parts.

```python
for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break
    if part.type == PartType.Http2.Header and part.frame_type == 5:
        part.headers.set_header(b"x-lab", b"push-inspected")
return api.message.translate()
```

**Easy and Expert:** the same contract. They translate logical headers, preserve
type, flags and stream ID, and prohibit raw HPACK or promised-ID changes. Input
must come from the server direction, on a nonzero odd client stream, promising
a nonzero even stream. After ACK of push disablement, further PUSH_PROMISE is
rejected. This is not complete stream-lifecycle, promised-ID uniqueness or promised
request HTTP-semantic validation; peers remain responsible for those checks.

PUSH_PROMISE and HEADERS share a direction's HPACK context under
[RFC 9113 §4.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-4.3).
Editing a promised header therefore does not break later indexed headers in that
direction. Hold publishes only emitted-prefix state, not the speculatively decoded
remainder. No translation runs without `message.translate()`.

PUSH_PROMISE verification (2026-10-25): nine new scenarios passed, covering every
fragmentation boundary, padding, held-draft transfer, emitted prefix, subsequent
indexed HEADERS, push-disable ACK and fresh sandboxed workers. Independent
libnghttp2 validates output. Also passed: 11/11 selected CTest regressions (15.26 s)
and the existing real Expert DATA/SETTINGS/fragmentation E2E (24.07 s). That E2E
did not yet send PUSH_PROMISE; new push support was verified at API/worker level,
not through the entire proxy. Build and generated reference passed.

## What this first step does not support

- DATA length, stream-ID or flag changes; user control-frame edits and Parts
  insertion/removal/reordering (except the explicit SETTINGS policy above).
- Raw HPACK and explicit index manipulation (these remain rewrite operations).
- Taking over an existing connection, multiple active translating deployments,
  or reverting a translated live connection to rewrite.
- Guaranteeing HTTP semantics of user-edited headers. HPACK state translation is
  not automatic repair of arbitrary application-protocol modifications.

Known H2 preface and unchanged DATA/control frames pass byte-for-byte. Without
limit policy, permitted SETTINGS are explicitly processed by the script and
forwarded unchanged. Policy may modify SETTINGS and consume its own ACK.
The output encoder owns indexing; `never` remains never-indexed.

## Verification

`inspection_translate_worker_tests` restores checkpoints in a fresh sandboxed
process after each message and checks output with independent libnghttp2.
`inspection_translate_live_tests` uses the real backend handler and worker pool:
DATA and reverse-direction callbacks still run after the filter stops matching;
it tests missing translate, disable, lost state, old proxies and missing callbacks.
The original POC adds a negative control and a long index/eviction sequence.

```sh
cmake -S . -B build -DSPIDER_TEST_TRANSLATE_POC=ON
cmake --build build -j 2
ctest --test-dir build --output-on-failure
```

Proxy control/sequence is independently tested by its JSON and SXBN integrations.
The first implementation was verified in isolation; subsequent lab1 deployment follows.

### Lab1: combined Easy/Expert and PUSH_PROMISE package (2026-10-25)

Deployed: Spider `6fbb860` plus working Easy/Expert/PUSH_PROMISE changes, proxy
`ddb5ce1f` (strict/sequence). Originally clean checkouts were fast-forwarded;
Spider frontend/backend and proxy were built and restarted. Frontend reported
`d7fa71541792`; all 87 live API schema members documented Easy/Expert.

`tests/lab_translate_smoke.py` uses a running lab, its actual webhook registration
and a temporary deployment filtered to a local origin-server port. It refuses to
run alongside active scripts and removes its deployment even on error. Traffic
rules are unchanged. It is not automatic CTest: restart and live-lab use require
deliberate execution.

```sh
python3 tests/lab_translate_smoke.py --lab /home/astib/.local/share/saslik/instances/lab1
python3 tests/lab_translate_smoke.py --lab /home/astib/.local/share/saslik/instances/lab1 \
  --transport connect --proxy-address 127.0.0.1 --proxy-port 33128
```

Both transports passed in Easy and Expert: 4/4 scenarios. Each checked 10 callbacks:
strict/sequence, handshake, fragmented padded PUSH_PROMISE/hold, header edits,
subsequent indexed HEADERS through libnghttp2, same-length DATA replacement and
deliberate failure closing the connection without leaking current data. Live-backend
H1 snapshot preview also rejected a Content-Digest/body edit in Easy and allowed it
in Expert. Lab sources passed 12 Easy, 12 Expert and nine PUSH_PROMISE tests.

The first CONNECT attempt immediately after restart failed: the test deployment
had zero runs and its script had not processed traffic. The exact cause was not
determined; after the lab settled, SOCKS and repeated CONNECT passed. The harness
now checks deployment execution after the first content callback to distinguish
inactive webhooks from hold failure. This does not claim gap-free lab startup.

### Real end-to-end harness

`tests/translate_e2e.py` starts both product processes and controlled H2 peers:

```text
H2 client -- SOCKS --> Smithproxy -- TCP --> H2 origin
                          |
                          +-- content webhook --> Spider --> sandbox worker
```

The content webhook runs directly from proxy to Spider; no mock creates annotations
or replacement. Only the discovery management API is stubbed, obtaining Spider's
random callback URL for temporary proxy configuration. This harness does not test
lease registration/renewal against the real management API.

Basic scenarios verify:

- H2 preface, default SETTINGS and ACK.
- Four request/response streams with actual dynamic index 62 on input.
- Header changes only in the second request and response; original values later.
- Independent output decoding with libnghttp2.
- Byte-preserving PING/ACK and exactly 14 script invocations.
- Capability, strict mode and contiguous sequence in each callback.
- A fifteenth callback with exception or missing translate: origin-socket EOF/reset,
  no released bytes and one recorded deployment error.

Tests use plaintext H2 on loopback, small frames and default SETTINGS.
`--settings --fragmented` changes both directions' tables through
`4096 -> 0 -> 128 -> 8192`, acknowledges via ACK and independently decodes output
with libnghttp2. `inspection_translate_settings_tests` additionally checks ACK
ordering, old data before ACK, invalid limits, queue quotas, duplicate capacity
changes, large HEADERS/CONTINUATION and held SETTINGS/ACK.

`--fragmented` also splits HEADERS/CONTINUATION bytewise, waits for each callback,
checks silence until block completion, and tests a complete PING prefix and
reverse-direction response during hold. `inspection_translate_hold_tests` covers
every message split, partial preface, fresh-worker transfer and complete-draft
preservation. This is not TLS, sustained-load or exhaustive H2 state-transition
testing. Ports, configuration and storage are temporary; actual labs are unchanged.

```sh
python3 tests/translate_e2e.py \
  --smithproxy-source ../smithproxy-need-more-test \
  --smithproxy ../smithproxy-need-more-test/build/smithproxy \
  --spider build/smithproxy-spider --failure exception
```

Use `--failure missing-translate` for the second failure scenario, and
`--fragmented` for fragmentation. Combine `--fragmented --settings` for limit changes.
`--fragmented --policy` activates a zero limit after handshake, checks inserted
SETTINGS and consumption of both synthetic ACKs on real sockets. Later callbacks
repeat the setting without more SETTINGS. Register all CTest variants with
`SPIDER_TEST_TRANSLATE_POC=ON` and absolute CMake paths
`SPIDER_E2E_SMITHPROXY_SOURCE` / `SPIDER_E2E_SMITHPROXY_BINARY`.
Tests require loopback sockets, sandboxed workers and `python-hpack`.

Local verification on 2026-10-25: build passed; all 25 Spider CTest suites passed
(32.34 s), including three translate suites. Proxy passed five control/need-more
suites (28.47 s). Generated examples matched the schema; `git diff --check` was clean.

After real E2E integration: 27/27 Spider suites passed (41.09 s), including both
failure variants. Each E2E variant also passed three consecutive standalone runs
(6/6, 23.43 s). Proxy control/need-more regression again passed 5/5 (28.47 s).
The tested proxy included `ddb5ce1` over `412680e`.

After translate hold/reassembly: 29/29 suites passed (58.99 s). The new nine-test
hold suite includes every fixture split, single bytes and atomic failure.
Fragmented E2E confirmed exactly 225 successful explicit callbacks across both
directions and closure without leakage after a subsequent exception. The live
test of initial `need-more` activating strict also passed separately.

After SETTINGS/ACK: 31/31 suites passed (83.64 s), including four real E2E variants.
The new SETTINGS suite had nine tests; the worker suite checked shared bidirectional
state across fresh sandboxed processes. SETTINGS E2E passed with fragmented
HEADERS/CONTINUATION, eviction/regrowth and independent libnghttp2 decoding
(21.95 s). Build, generated examples and whitespace checks passed. Proxy remained
unchanged at `ddb5ce1`.

After `api.connection` and persistent policy: SETTINGS had 16 tests; worker tests
covered explicit mode, missing translate and incompatible instancing; editor tests
covered completion. Policy E2E passed standalone (24.20 s) and in-suite (24.18 s).
Of 32 suites, 30 passed directly; two needed expected API schema/offline-example
updates. API then passed; one chain retry hit bootstrap assertion
`active_sessions == 0`, and the next standalone run passed (7.62 s). All 32 thus
had a passing run; this was not one clean full run. Build, generated reference
and whitespace checks passed.

After same-length DATA: seven new tests covered directions, lengths, padding,
END_STREAM, all fragmentation boundaries with an active reverse direction,
interleaved streams, edited-part hold, atomic rejection and this document's
executable example. `--fragmented --data` checked padded request/response DATA
masking through the real proxy, preserving content-length and END_STREAM.
E2E passed twice (18.48 s; 17.43 s after the no-op fast path).

The full run passed 33/34 suites (139.10 s). The remaining chain test exposed a
harness bug: its 2 s HTTP timeout was shorter than the backend's 2.5 s language
budget, and OSError restarted the entire stateful scenario. The harness now retries
only discovery and waits 5 s for language; standalone chain then passed (8.02 s).
Production timeouts were unchanged. All 34 suites had a passing run; build and
generated reference were verified. Unchanged DATA returns without materialization.
