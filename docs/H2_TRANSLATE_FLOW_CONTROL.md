# Length-changing H2 Translate: directional flow control

Status: implemented bounded support; validation and limits below.
Date: 2026-10-26.

Translate supports DATA resizing when the proxy advertises
`info.webhook_control["content-reverse"] = true` at Translate activation.
Without that capability, legacy same-length behavior remains. Losing it after
activation fails; it is never silently downgraded. Rewrite remains independent.

## Implemented behavior

Every explicit `message.translate()` builds a private transaction containing
HPACK state, SETTINGS, two directional flow-control ledgers and owned output
queues. The successful worker return publishes these together. Backend state is
shared across directions and survives worker rotation, not backend restart.
The inspection result exposes `flow_control.pending_bytes`, `forward_bytes` and
`reverse_bytes`; raw reverse output and checkpoint bytes are excluded from GUI
and recent-run metadata. These counts describe staged output, not socket ACKs.

The proxy response uses `action: replace`, forward `content` and optional
`content-reverse`. Both payloads are base64. Reverse bytes go back toward the
current callback's source. Empty forward output with reverse bytes is a replace,
not need-more. There is no second callback or background translation.

Input DATA consumption accumulates connection/stream credit. Once a stream's
pending DATA drains, the translator grants that consumed credit back to its
sender. Receiver WINDOW_UPDATEs feed the independent output windows and are not
forwarded as grants to the original sender. This prevents overcredit after
expansion and permits shrink-to-zero to make progress without a receiver reply.
The accounting unit is encoded DATA payload bytes, including padding, not the
frame header or decompressed body size.

Sender-facing input windows are tracked independently from refund obligations
and recipient-facing output windows. Only original callback bytes advance the
input cursor: restoring held Parts does not consume credit again. A complete
nine-byte DATA header reserves its entire declared payload, even before the last
payload byte arrives. The cursor persists through worker rotation and holds at
most nine header bytes; it does not duplicate retained content.

Only actually emitted SETTINGS and WINDOW_UPDATE change the sender-facing
allowance. A reduced initial stream window permits bounded in-flight debt until
the sender's SETTINGS ACK arrives. Connection windows do not change with SETTINGS.
Input stream records have a separate 1024-record bound; each direction permits
128 outstanding SETTINGS and 1024 compact input-reset ranges. Exceeding a window
or quota fails the transaction atomically in both safety modes. An older active
checkpoint without the input ledger requires reconnection rather than guessing
how much credit has already been consumed.

Output is split by available connection credit, stream credit and recipient
frame size. END_STREAM remains on the last actual slice. Pending DATA can be
released by an opposite-direction WINDOW_UPDATE through content-reverse, without
any additional source DATA. SETTINGS_INITIAL_WINDOW_SIZE changes existing stream
windows by a delta, including negative values, and never alters connection credit.
Immediately sendable unchanged DATA preserves padding; reframing can remove it.

Queues preserve frame/header-block order. Connection control frames can bypass
blocked DATA, but SETTINGS ACKs remain behind earlier encoded header blocks.
This is bounded FIFO output, not a fair per-stream scheduler.

Cancelled streams still need compression processing, as described by
[RFC 9113 stream states](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1)
and [GOAWAY](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8).
Preserving queued encoded headers avoids changing the encoder history on which
later blocks already depend. It does not replay application DATA on those streams.

Both Easy and Expert enforce the same transport invariants:

- At most 384 KiB pending output across both directions, 1024 live stream records
  per direction, 1 MiB combined forward/reverse response, 1 MiB control checkpoint
  and the existing 4 MiB deployment-state quota. Closed records are reclaimed after
  queued DATA and credit settle. Their IDs remain in parity-separated, merged
  ranges so late WINDOW_UPDATE does not reopen them. Each direction permits 1024
  retired ranges and 1024 cancellation ranges. Sequential churn is constant-space;
  sparse/out-of-order histories can still reach an explicit quota.
- Invalid/overflowing WINDOW_UPDATE and quota failures raise CommitException.
  Failed assembly leaves checkpoints unpublished and is retryable in the script.
- RST_STREAM discards queued DATA in both directions and refunds connection credit.
  Encoded headers remain ordered for HPACK synchronization. The reset follows
  already queued headers in its own direction; unrelated blocked DATA may delay
  that forwarding under FIFO. In-flight DATA on cancelled streams is consumed
  and refunded only at connection level, never emitted as application content.
- GOAWAY records a non-increasing last-stream ID per sender. DATA for excluded
  peer-initiated streams is discarded in both directions; eligible pending streams
  can drain on later explicit callbacks. Encoded headers still reach the peer for
  minimal compression processing. GOAWAY is forwarded promptly. Peer transport
  closure can still prevent delivery; this does not guarantee graceful shutdown.
- Input END_STREAM is tracked separately from output END_STREAM, rejecting later
  DATA even while an expanded terminal frame remains queued.
- Resizing repairs Content-Length only when the relevant header and complete
  content are still retained. Already emitted Content-Length rejects resizing.
  H2 content digests/signatures are not repaired automatically.
- Explicitly held input is not credited until released. Holding a body larger
  than the sender's window is not supported by this bounded implementation.
  [Bounded hold-credit design](H2_TRANSLATE_HOLD_CREDIT_DESIGN.md) specifies the
  proposed reservation model and its implementation prerequisites; it is not an API.

Once Translate is active, an uncaught failure follows its existing strict
connection teardown policy. Before activation the existing failure policy is
unchanged. The translator does not promise arbitrary HTTP/2 lifecycle repair.

## Small script

Hold the header and the complete body if Content-Length might change:

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break
    if part.type == PartType.Http2.Header and part.content.complete is False:
        api.message.parts.hold_from(part)
        break

for body in api.message.bodies():
    if body.complete and body.get_bytes() == b'secret':
        body.set_bytes(b'redacted content')

return api.message.translate()  # Expert has the same window/retention rules.
```

Physical DATA and logical gzip/deflate Body edits use the same encoded-byte
ledger. Logical Body decoding/recompression remains lazy.

## Why a length delta alone is insufficient

Two independent hyper-h2 peers demonstrate these cases:

| Input DATA | Output DATA | Result without compensation |
| --- | --- | --- |
| 1 byte | 65,536 bytes | Receiver rejects exhausted connection/stream window |
| 65,535 bytes | 0 bytes | Sender stalls; receiver has no DATA to acknowledge |
| 10 bytes | 20 bytes | Forwarding a 20-byte credit overcredits the original sender |

Splitting the expanded body into smaller frames does not enlarge either window.
Waiting for another callback in the original direction is insufficient. The
sender might be blocked or waiting for a response. Even when a WINDOW_UPDATE
arrives in the reverse direction, releasing buffered DATA requires output in
the *other* direction from that callback's ordinary replacement.

The former single replacement `content` could not guarantee progress: a queued
WINDOW_UPDATE waiting for a future callback might never be sent. Directional
output removes that transport limitation.

## Design rationale

Keep the existing user-controlled execution contract:

```text
incoming callback -> script -> message.translate()
                                  |
                         staged directional outputs
                                  |
                       proxy publishes in each direction
```

There is no hidden translator run. One explicit translate invocation may need to
authorize both a normal replacement and reverse control output, or release a
previously buffered output prefix after receiving credit from the other side.
The transport extension is capability-negotiated before enabling resizing.

The translator must track, for each DATA direction:

- input and output connection credit;
- input and output per-stream credit and initial-window settings;
- bounded pending output and its ownership;
- credit already granted for consumed input, preventing duplicate grants;
- stream termination/reset and cleanup without losing connection accounting.

The two directions cannot use one signed counter as a complete model. Connection
credit and stream credit are independent. Padding consumes flow-control credit;
the nine-byte frame header does not. A SETTINGS_INITIAL_WINDOW_SIZE reduction
can make existing stream windows negative without changing connection credit.
Compressed bodies are charged by their encoded DATA payload size, not plaintext.
These rules follow [RFC 9113 sections 6.1 and 6.9](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.9).

## Assembly and publication boundaries

1. Complete logical edits and lazy compression in a private draft.
2. Repair Content-Length from encoded body bytes while the relevant headers are
   still retained. Already emitted headers cannot be repaired retroactively.
3. Frame DATA within the recipient's maximum frame size and available credit.
   Preserve order and END_STREAM on the actual final frame, not an earlier slice.
4. Retain unsent bytes with bounded ownership. A later reverse WINDOW_UPDATE must
   be able to release them without waiting for fresh original-direction DATA.
5. Translate or generate credit only according to an explicit buffering policy.
   Credit grants promise capacity; do not grant unlimited credit for held input.
6. Publish HPACK, window state, output queues and transport instructions together
   on successful script return. Failed assembly must remain retryable.

A numeric old/new length delta remains useful for diagnostics, but it is not a
substitute for this ledger. Zero WINDOW_UPDATE increments must be suppressed;
overflow, reset, terminal states and partial consumption need explicit treatment.

Holding an entire body larger than the advertised window also needs bounded
credit advancement. Do not claim arbitrary-sized body edits merely because the
existing logical hold mechanism accepts fragmented Parts.

## Executable evidence

`inspection_translate_windows_test.py` exercises the production translator
against independent hyper-h2 peers and fresh sandboxed workers. It covers both
directions, multi-window expansion, shrink-to-zero, padding, END_STREAM, fragmented
credit, negative windows, streams, resets, quotas, retry, retained Content-Length,
gzip and SETTINGS/ACK ordering. The windows Easy/Expert variants of
`translate_e2e.py` use real Smithproxy and Spider processes plus real hyper-h2
peers. The peer library enforces windows and Content-Length independently.

`tests/inspection_translate_flow_control_test.py` uses real hyper-h2 sender and
receiver state machines. Its deliberately minimal bridge substitutes DATA on
the wire and manually demonstrates the missing compensation operations. It is
not wired into production and does not test a completed Spider translator.

The twelve probes cover unchanged-size behavior in both directions, expansion
overflow, shrink-to-zero stalls in both directions, reverse credit injection,
overcredit, compensated credit, reverse-callback output release, invalid zero
increments, independent streams, padding, negative stream windows and gzip sizes.

Run directly:

```sh
python3 tests/inspection_translate_flow_control_test.py -v
```

Or enable the optional CTest suite with
`-DSPIDER_TEST_FLOW_CONTROL_POC=ON` (requires python-h2 for tests only).

The original probes remain useful counterexamples; passing those probes alone
is not end-to-end acceptance. The production tests above exercise the implemented
path, not just the model.

### Validation run: 2026-10-26

- Full configured Spider CTest run: 48/48 suites passed in 184.92 seconds.
- Production window tests: 34 tests passed, with 17 scenarios each in Easy and
  Expert, including additional direction and payload-size combinations.
- Nine integration suites passed. The two window suites used real Smithproxy
  and Spider processes with independent hyper-h2 peers: six bytes expanded to
  160,000 bytes, shrink-to-zero, unchanged data and subsequent traffic in both
  directions. Reverse credit alone released queued output without fresh source
  DATA. The tests also checked Content-Length and bounded GUI summaries.
- API example generation consistency and whitespace checks passed.

This is the Spider regression run, not a new native full-P3 run. The preceding
native content-reverse full P3 passed separately against Smithproxy `63a2c67`.

### Lifecycle review and validation: 2026-10-26

The follow-up review addressed four concrete limitations:

- Closed records exhausted a lifetime stream quota. Closed IDs now compact into
  bounded ranges, preserving open holes and ignoring late credit without reopening.
- Reset with pending headers tore down translation. Queued encoded headers now
  survive cancellation, including subsequent indexed-header dependencies; resets
  cannot overtake earlier headers in their own output direction.
- GOAWAY rejected every pending queue. It now cancels only excluded streams,
  preserves HPACK history and allows eligible output to finish. A later GOAWAY
  cannot increase the last accepted stream ID. Tests cover both initiator parities.
- Input END_STREAM was only enforced after output drained. Input termination is
  now checked while expanded output is pending. Refunds settle per stream, so
  unrelated blocked DATA does not retain a cancelled stream's connection credit.

Verification after the implementation changes:

- Build passed; full configured CTest: **48/48 suites**, zero failures, **177.34 s**.
- Production window/lifecycle suite: **48 tests** (24 each in Easy and Expert).
  Includes 3000 sequential closures, out-of-order holes, live/range quotas and
  atomic failure, cancelled input refunds, HPACK after reset/GOAWAY, terminal DATA
  rejection, and cancellation state restored through fresh sandboxed workers.
- Nine integration suites passed. Both window variants used real proxy/Spider
  processes and independent hyper-h2 endpoints. In addition to resizing and reverse
  credit, each tested a reset during pending expanded output and **1100 further
  completed streams** in both directions. GOAWAY's compression-state cases are
  API-level tests, not a claim of socket-level graceful-GOAWAY coverage.
- Generated API reference consistency and `git diff --check` passed.

The full run used an isolated user/network namespace, not a live SASlik instance.
No native production code changed; the earlier native P3 remains separate evidence.
Fair scheduling and complete peer stream-lifecycle validation remain out of scope.
Large retained bodies are addressed by the linked design proposal only; no early
hold credit is enabled by this change.

### Input-window accounting and socket GOAWAY

The input ledger is the first prerequisite for bounded hold-credit advancement,
not an early-credit API. Ordinary hold still cannot collect a body larger than
its available sender window. Backend reservation admission, already-refunded
provenance and early grants remain future work.

Production regression cases exercise partial DATA headers and payloads, padded
holds, release without duplicate debit/refund, connection oversend, stream-window
reductions before/after ACK, retained SETTINGS, held END_STREAM and fresh workers.
The real-socket `--goaway` fixture covers both safety modes: stream 1 drains its
160,000-byte expanded body after GOAWAY, excluded streams 3/5 lose DATA but preserve
ordered HPACK history, and a subsequent PING is still forwarded. An independent
libnghttp2 decoder checks headers on the recipient side.

Validation on 2026-10-26:

- Full configured regression: **50/50 CTest suites**, zero failures, **191.73 s**.
- A final refinement stops input-ledger stream recreation after a reset received
  during hold. After rebuilding the embedded worker, all **7/7 targeted suites**
  passed in **42.33 s**: production windows, holds, real fragmented headers,
  windows Easy/Expert and GOAWAY Easy/Expert.
- The final production window suite contains **64 tests** (32 per safety mode),
  including the retained-reset regression and JSON state across fresh workers.
- Generated API reference consistency and whitespace checks passed. Native code
  and live SASlik configuration were unchanged; no new native full P3 was run.
