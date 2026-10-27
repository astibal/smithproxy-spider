# Bounded credit advancement for retained H2 Parts

Status: implemented bounded first version. Date: 2026-10-27.

Ordinary `hold_from()` grants no early DATA credit and may stall on a whole body
larger than the sender's window. Explicit reservation enables larger bodies within
the limits below. Every callback must still explicitly return Translate.

## API

`api.connection.http2.reserve_body(header, max_bytes)` stages intent for a complete
initial HEADERS Part in the held suffix. Its original header must never have been
emitted. The immutable integer limit, in 1..262144, counts original encoded DATA
including padding, not decompressed bytes. Original Content-Length is checked even
if the script edited its draft. Each direction supports up to 32 collecting or
output-pending reservations, with a combined limit of 256 KiB. Both directions
can reserve together. Releasing the
reserved header requires complete content.

```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return

retaining = False
first = None
for part in api.message.parts:
    if first is None and (part.frame_type == 1 or not part.complete):
        first = part
    if not part.complete:
        retaining = True
    elif part.type == PartType.Http2.Header and part.content.complete is False:
        retaining = True
        api.connection.http2.reserve_body(part, 128 * 1024)

if retaining:
    api.message.parts.hold_from(first)

for body in api.message.bodies():
    if body.complete and body.get_bytes() == b'secret':
        body.set_bytes(b'redacted content')

return api.message.translate()
```

A reservation alone does not change application content. Gzip/deflate remain lazy;
accounting never requires decompression. Complete retained content can be resized,
repairing Content-Length from encoded output.

The example collects at most two 128 KiB bodies in one direction. Choose smaller
per-stream limits to admit more streams. Repeating the same reservation is
idempotent; changing its limit fails. The hold boundary still retains a suffix,
not independently selected streams. Keeping that suffix until all its bodies
complete avoids emitting a header whose DATA remains behind another held header.
Cancelled streams release their own debt without disturbing other reservations.

## Backend ownership and admission

The backend admits intent under the existing deployment serial transaction,
before returning directional output. Ownership belongs to the deployment
generation and connection across workers. User `api.state` is not an admission
authority. Preview requests cannot claim backend reservation support.

Admission charges serialized checkpoint capacity only where liability remains:

| Slot | Reserved capacity |
| --- | ---: |
| Each direction with a reserved body, owned DATA or early-credit debt | 256 KiB to 1 MiB, in 64 KiB steps |
| Shared translation control / output queues while reserved | 1 MiB |

Actual script state, HPACK checkpoints and structural overhead are added.
The directional class rounds `3 * (sum(limits) + 65535) + 65536` up to 64 KiB,
capped at 1 MiB. It includes baseline input credit, serialized representations and
metadata headroom. The actual serialized hold must fit that class before publication;
unusually fragmented or metadata-heavy input can still fail explicitly. A class
never shrinks while directional ownership or credit remains outstanding.
`state_bytes` includes these slots: a single 128 KiB limit charges approximately
1.625 MiB, and the full 256 KiB aggregate approximately 2 MiB, plus actual metadata.
Two 128 KiB single-direction reservations on separate connections fit the 4 MiB
deployment quota; a third does not. Both directions share the control slot.
Directional slots are reclaimed as their liabilities settle. The final shared
reservation is released only when both directions have no reserved body, no owned
input and no early connection-credit debt. A later body must pass admission again.
Actual retained HPACK metadata remains charged. This is not exact RSS accounting.

Serialization and worker-envelope limits remain independent. Very fragmented or
metadata-heavy traffic can reach a checkpoint limit before the encoded-body cap.
Admission failure publishes neither state nor credit. Connection stop releases
the instance. Generation retirement, idle state loss or backend restart trigger
the existing strict failure policy on subsequent callbacks.

## Encoded input and credit invariants

For each DATA direction:

```text
H = owned original DATA (held + declared partial payload + pending output source)
W = sender-facing connection window
B = sum(reservation limits) + 65535 bytes of admitted encoded-input capacity

H + W <= B
new connection grant <= B - H - W
```

Baseline credit is an existing liability, including other streams. DATA is charged
once from original callback bytes when its nine-byte header arrives. Reserving the
entire declared payload covers fragmentation; restored Parts are never debited again.
Only actually emitted SETTINGS/WINDOW_UPDATE change input allowances; ACK boundaries
cover initial-window changes and in-flight data.

Input capacity, like its serialized class, retains its highest admitted value until
directional liabilities settle, and never exceeds 262144 + 65535. This prevents
unreserved competing streams from consuming credit backed only by a smaller body.

Early connection grants are also bounded by retained source input not already
credited. Connection debt is backed by the retained input pool across streams;
normal release is ordered, but cancellation can settle any cancelled ownership first.
Stream debt is separate and grants respect the body's remaining limit. Accepting
original DATA settles these debts before ordinary refunds are recorded. This
physical-input provenance, including padding, survives JSON checkpoints and worker
rotation independently of mutable output bodies.

Input transferred into blocked output stays owned until that output drains or is
discarded. Releasing Parts alone does not free capacity backing queued output or
promised credit. Settled ownership, rather than connection lifetime, releases slots.
Receiver WINDOW_UPDATEs still feed output windows rather than passing through.

## Transaction and failures

1. Restore backend ownership, windows, held Parts and early-credit debts.
2. Debit new DATA, including declared incomplete payload.
3. Validate intent, original Content-Length and retained headers.
4. Stage edits/output and settle input credit once.
5. Stage capacity-backed grants; validate all checkpoints and output budgets.
6. Backend admission atomically publishes state and both directional outputs.

Empty forward output plus reverse WINDOW_UPDATE uses `replace` with
`content-reverse`. The worker owns held Parts; native need-more does not retain
a second copy. Real proxy fixtures cover JSON and negotiated SXBN.

Input must complete before exhausting its cap, with END_STREAM on the DATA
reaching it. A body terminated by trailers therefore needs a reservation larger
than its DATA byte count (including padding). Exceeding the limit, exhausting capacity, or having no
effective input window that consumed-byte advancement can reopen fails explicitly.
There is no silent wait at the cap or automatic streaming fallback. Lost ownership
or an older input ownership checkpoint requires reconnection.

RST_STREAM and GOAWAY are processed during explicit Translate even inside a body
hold. Cancelled DATA is discarded from both the output queue and both directional
hold checkpoints, atomically with credit settlement and backend publication.
Initial headers still retained at the source do not establish a recipient stream;
a reset from their initiator is suppressed rather than sent on an idle stream.

Retained source HPACK blocks survive cancellation until that direction resumes.
They update the input decoder only; their drafts are discarded, and they appear
complete to the script so the cancelled body does not request another hold.
Already encoded output headers remain ordered for the recipient decoder. Other
streams' retained drafts and data remain intact. Partial DATA retains only a byte
count to skip; its physical input cursor still consumes the remainder exactly once.

END_STREAM trailers complete reserved bodies and record release like END_STREAM
DATA. Repeated cancellation cannot refund input twice. A subsequent body can reserve
the same direction, subject to fresh admission if the previous liability settled.
Reset and replacement reservation may share a callback. Every stream has its own
credit debt; connection credit remains pooled. Legacy single-body checkpoints are
upgraded without losing debt and retain their original full directional capacity.
Easy and Expert share these limits; arbitrary-size bodies and full lifecycle
repair are not promised.

## Validation and future work

Production tests cover both directions, 100000-byte and 256 KiB boundary bodies,
zero/unchanged/expanded output, gzip, padding, partial DATA, competing streams,
simultaneous directional holds, exhaustion, source Content-Length despite edits,
immutable limits, failed commit/retry, cancellation, fresh workers and lost ownership.
Independent hyper-h2 endpoints validate windows and Content-Length. Backend tests
race connections for admission and recover capacity after settled output, cancellation
and stop. Worker tests rotate processes across partial DATA and cross-direction
cancellation. Churn tests cancel 1200 reserved streams per safety mode while checking
bounded state and quota release. Real JSON/SXBN socket fixtures exercise both Easy
and Expert, trailers, collecting/pending cancellation and subsequent traffic.

Incremental DATA processing already supports bodies beyond the whole-body limit
without reservation. See the cookbook for its distinct content/encoding contract.
Automatic fallback from a retained whole body to streaming remains unsupported.
