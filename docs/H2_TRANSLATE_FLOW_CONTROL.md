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

Input DATA consumption accumulates connection/stream credit. Once a direction's
pending output drains, the translator grants that consumed credit back to its
sender. Receiver WINDOW_UPDATEs feed the independent output windows and are not
forwarded as grants to the original sender. This prevents overcredit after
expansion and permits shrink-to-zero to make progress without a receiver reply.
The accounting unit is encoded DATA payload bytes, including padding, not the
frame header or decompressed body size.

Output is split by available connection credit, stream credit and recipient
frame size. END_STREAM remains on the last actual slice. Pending DATA can be
released by an opposite-direction WINDOW_UPDATE through content-reverse, without
any additional source DATA. SETTINGS_INITIAL_WINDOW_SIZE changes existing stream
windows by a delta, including negative values, and never alters connection credit.
Immediately sendable unchanged DATA preserves padding; reframing can remove it.

Queues preserve frame/header-block order. Connection control frames can bypass
blocked DATA, but SETTINGS ACKs remain behind earlier encoded header blocks.
This is bounded FIFO output, not a fair per-stream scheduler.

Both Easy and Expert enforce the same transport invariants:

- At most 384 KiB pending output across both directions, 1024 tracked streams
  per direction, 1 MiB combined forward/reverse response, 1 MiB control checkpoint
  and the existing 4 MiB deployment-state quota. Closed stream records are retained
  within that quota; this first implementation does not provide unlimited churn.
- Invalid/overflowing WINDOW_UPDATE and quota failures raise CommitException.
  Failed assembly leaves checkpoints unpublished and is retryable in the script.
- RST_STREAM discards queued DATA for that stream and refunds connection credit.
  A reset conflicting with a queued header block fails rather than silently
  corrupting HPACK. GOAWAY while output is pending also fails explicitly.
- Resizing repairs Content-Length only when the relevant header and complete
  content are still retained. Already emitted Content-Length rejects resizing.
  H2 content digests/signatures are not repaired automatically.
- Explicitly held input is not credited until released. Holding a body larger
  than the sender's window is not supported by this bounded implementation.

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
