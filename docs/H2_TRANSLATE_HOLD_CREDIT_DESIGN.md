# Bounded credit advancement for retained H2 Parts

Status: design proposal, not implemented and not a public API.
Date: 2026-10-26.

The current `hold_from()` retains semantic Parts and grants no early DATA credit.
That remains the default. A whole body larger than the sender's window can stall
before END_STREAM, even if its eventual serialized checkpoint would fit in memory.
This proposal enables an explicit, bounded reservation to make such bodies possible.
It does not promise arbitrary-size bodies or change Rewrite behavior.

## Ownership and admission

Reserve capacity for one deployment/generation, connection, direction and stream.
The backend owns reservations across worker rotation, alongside held Parts and
translation state. User `api.state` is not an accounting authority. Admission must
include reservations in the existing deployment quota before returning any credit.
Both directions compete for the same deployment budget; two workers cannot each
promise the same free capacity. Activation still requires content-reverse and every
later callback must explicitly return `message.translate()`.

An eventual explicit API should specify a maximum encoded body size and request
reservation before the first early refund. A complete retained initial header must
identify the content. The operation must reject an already emitted header when
Content-Length repair would be required. No API spelling is committed here.

Known Content-Length permits an up-front size check; unknown-length input needs a
script-selected maximum and an explicit overflow failure. Gzip's decoded size is a
separate limit: reserve and account encoded DATA, including padding, and keep the
existing decoded-body bound. Decompression must not be needed for admission.

## Credit invariants

First track the sender-facing receive window at connection and stream levels.
This is additional state: today's consumed-byte refund ledger alone is insufficient.
Start from the handshake, apply actual forwarded SETTINGS and every generated
WINDOW_UPDATE, and debit newly received physical DATA once. Restored held Parts
are not new input. A partial DATA frame must also reserve its advertised payload
before any credit can be advanced; otherwise fragmentation hides in-flight memory.

For each direction define:

```text
H = encoded bytes retained (including incomplete DATA already received)
W = connection credit already granted but not yet consumed by the sender
B = admitted encoded-input capacity for this direction

H + W <= B
new connection grant <= B - H - W
```

Already advertised baseline credit is an existing liability, not free capacity.
It cannot be revoked by withholding later grants. At admission, account for all
remaining connection credit, even when other streams could consume it. Stream
grants are limited by their own admitted remainder; connection grants are limited
by the aggregate reservation. Neither grant may exceed the H2 maximum window.

Example with a 128 KiB admitted input budget and a 65,535-byte initial window:

| Step | H | W | Maximum new connection grant |
| --- | ---: | ---: | ---: |
| Reservation accepted | 0 | 65,535 | 65,537 |
| First window retained, no earlier grant | 65,535 | 0 | 65,537 |
| Second grant consumed in full | 131,072 | 0 | 0 |

An actual encoded body must leave room for framing and metadata reservations.
The example is the credit ledger only, not a claim that a 128 KiB body fits every
current checkpoint. Serializing `_wire`, `_data`, header drafts and relationships
can duplicate data; measure/reserve their worst-case representation separately.
The 1 MiB hold checkpoint, 1 MiB control checkpoint, 4 MiB deployment state and
worker response envelope remain independent hard limits.

Per retained DATA part, checkpoint how many input bytes were already refunded.
When released, normal flow accounting refunds only uncredited bytes. Otherwise
early hold credit followed by ordinary release would grant the same bytes twice.
Credit tokens follow physical input provenance, not mutable output-body size.
Padding is credited once even if the eventual output omits it.

## Transaction boundaries

1. Restore reservations, Parts, input windows and already-refunded provenance.
2. Debit only newly received DATA, including incomplete payload bytes.
3. Stage draft edits, reservation changes and prospective grants privately.
4. Serialize both checkpoints and directional output; validate all quotas.
5. Atomically publish reservation ownership, checkpoints and grants on successful
   worker return. Failed commit/retry publishes nothing and grants nothing twice.

Reverse credit with an empty forward prefix uses `replace` plus content-reverse,
while the worker retains the held Parts. It must not rely on native `need-more`
also retaining a second copy of those bytes. Verify this through JSON and SXBN.

Reservation capacity is transferred, not freed, when retained content becomes
pending translated output. Expansion must fit the output budget before transfer.
An output queue can remain blocked after the script releases its hold. Credit
already promised to the sender is still a liability until consumed or the
connection terminates; freeing Parts alone cannot release that reservation.

On RST_STREAM or GOAWAY exclusion, discard application drafts but retain enough
source compression/framing state to consume in-flight frames. Unused stream credit
cannot be revoked. Keep the connection's input liability and suppress further
stream grants. The current terminal-output handling is not a held-input reservation
implementation. A backend restart or lost reservation follows strict teardown.

## Exhaustion policy

Do not silently stop granting credit at an incomplete body cap: that can deadlock
both peers indefinitely. Reject a known oversized body before early grants. If an
unknown body exhausts its reservation without completion, fail explicitly under
Translate's strict policy. A later implementation may support an explicit streaming
fallback selected by the script, but cannot retroactively emit retained drafts or
repair headers that were already sent.

## Implementation order and acceptance

1. Add sender input-window and partial-frame accounting, with persisted provenance.
2. Add backend admission/ownership for reservations within deployment quotas.
3. Expose explicit opt-in reservation intent; keep ordinary hold unchanged.
4. Connect early refunds, release, cancellation and pending-output ownership.
5. Validate real JSON/SXBN proxy paths and independent H2 endpoints.

Required cases: 100 KiB and boundary-size bodies across several windows in both
directions; retained Content-Length; gzip; bytewise DATA fragmentation; padding;
multiple competing streams; both directions reserving together; unknown-length
overflow; zero-sized edits; expansion on release; reset/GOAWAY during hold; fresh
workers; failure/retry before publication; no duplicate grants after release;
deployment admission races; strict teardown after state loss. Peer window checks
and actual serialized-memory limits are separate assertions.

This design deliberately stops before implementation: reservation ownership and
partial-input accounting must land together. Adding early WINDOW_UPDATE to the
existing hold loop alone would not satisfy these invariants.
