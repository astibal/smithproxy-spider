# First Class API Design

**Status: BINDING DESIGN CONTRACT**
Version: 1.1

Date: 2026-10-25
Scope: Spider scripting API, Parts, editing, commit, hold and their presentation.

This document defines the target First Class API architecture. Implementation,
generated documentation, editor and tests must agree with it. Deviations require
an explicitly approved contract change, not a silent implementation shortcut.
A binding design does not imply that every part is already implemented.

**Must**, **must not** and **shall** denote binding requirements. Open decisions
are listed separately and must not be presented as settled contracts.

## Core philosophy

We work with **Parts**: content units carrying meaning, representation and links
to original wire data. The same abstraction supports reading, editing, assembly
and waiting for another callback. Hold extends a part's lifetime, not just that
of anonymous bytes.

The API should be approachable. Users work with what Spider actually understands,
without manually calculating offsets, lengths or routine representation conversions.
Unknown content is first-class: a missing annotation is not an error.

Scripts run on the backend even without an open GUI. The editor knows the API and
provides typed hints and examples. Reference documentation is generated from API
definitions rather than maintained independently.

## Message and Parts list

`api.message` is the working message for the current script invocation. Its `parts`
cover all available content, including unannotated gaps. With hold, the message
can contain retained parts from previous callbacks before newly received parts.

A part is not necessarily one annotation or one contiguous wire slice. Annotations
can overlap; one interpreted part can refer to multiple wire ranges. Overlapping
annotations must not cause duplicate byte emission. Exact rules for splitting
overlapping annotations into parts remain open.

Scripts may reorder parts. The framework must not generally prohibit an order
merely because it is unusual or the peer might reject it. It assembles known
representations and unambiguous dependencies; it does not guarantee application success.

Header recalculation uses subsequent **relevant** parts. Relevance must account
for the particular message, direction and protocol stream, not simply every byte
after the header. Commit rejects ambiguous dependencies instead of guessing.

## Part types

A type describes the part, not the protocol of the entire connection. HTTP content
can contain MIME parts, for example. A separate `Protocol` selector is not part
of this model.

```python
for part in api.message.parts:
    if part.is_a(PartType.Http1.Part):
        # HTTP/1 family, for example Header or Body.
        ...
    elif part.is_a(PartType.Mime.Part):
        ...
    elif part.type == PartType.Opaque:
        data = part.get_bytes()

return api.message.commit()
```

- `part.type == ...` compares the exact type.
- `part.is_a(...)` tests membership in a type family.
- `PartType.Opaque` means content without a protocol interpretation. It has the
  same basic read, write, commit and hold operations as other parts.
- Protocol APIs must be backed by annotations or explicitly constructed typed
  parts. HTTP-looking text inside an Opaque part must not automatically become HTTP API.

Examples describe the target API, not a list of already implemented types.

## Lazy representations and original bytes

Parts represent meaningful content. An HTTP body may be exposed as cleartext
even when its original wire representation was gzipped.

`part.get_bytes()` creates a slice, copy or decoded representation as needed.
Creating, iterating or holding a part must not require materializing its content.
An already available suitable representation may be reused.

Reading must not mark a part dirty. Explicit `part.set_bytes(data)` creates a
change. An unchanged part must preserve its original wire bytes, without needless
recompression or serialization. Identical cleartext need not produce identical gzip.

For Opaque, representation-to-wire conversion is the identity. Typed parts provide
the corresponding serialization or encoding where supported.

Representation size, original wire size and resulting wire size are distinct.
The API must not hide them behind one ambiguous `size()`. Encoding must be directly
discoverable rather than inferred from size differences. Exact attribute names remain open.

## Two commit levels

`part.commit()` validates the edited representation and prepares its wire form,
for example by serializing headers or recompressing a modified body. It sends
nothing to the peer. For an unchanged part it is a cheap no-op.

`api.message.commit()` commits all output parts and assembles the result. It
recalculates known dependencies such as Content-Length, framing and output offsets.
Explicit `part.commit()` is optional: use it for early validation or to inspect
the resulting wire size. Held parts are not output; hold alone does not force commit.

```python
for part in api.message.parts:
    if part.type == PartType.Http1.Header:
        part.http1.set_header("X-Test", "another way")
    elif part.type == PartType.Http1.Body:
        api.print(part.get_bytes().hex())
        part.set_bytes(b"\r\n\r\n\r\n")

return api.message.commit()
```

Commit must not publish partial changes during assembly. Failed assembly raises
a catchable `CommitException`, preserves the original input and leaves drafts
repairable. A successful local commit does not guarantee a successful message
commit. Bytes emitted by an earlier callback cannot be repaired retroactively.

The result uses the existing script return mechanism. A payload transaction does
not promise rollback of external operations, shared storage or other script effects.

## Part and content completeness

```python
part.complete
part.content.complete
```

`part.complete` describes one part, such as an H2 DATA frame. `part.content.complete`
describes its entire associated content, such as an HTTP body. A complete DATA
frame does not necessarily mean complete content.

Both distinguish `True`, `False` and `None`: complete, known incomplete, and
undeterminable from available information. Checking completeness must not require
unnecessary decoded-content materialization.

Complete content requires a known end and every required part. END_STREAM or a
successful inflate alone is insufficient. `content` is a context linking related
parts, not automatically another byte copy or a separate stream view.

The framework does not magically wait for future callbacks. A script needing the
whole content must hold the relevant parts. To change body length, it must retain
the ability to modify the corresponding header; holding a body cannot retrieve
an already emitted header.

## Streams without automatic views

`part.stream_id` is always an integer. Parts with protocol stream IDs expose the
actual ID; otherwise the value is **1**, including Opaque parts. Actual zero stays
zero, for example for connection-level H2 frames.

```python
for part in api.message.parts:
    if part.stream_id == 1:
        # Deliberately includes actual stream 1 and parts with the default ID.
        ...
```

Scripts select and group parts. The API does not currently create automatic
per-stream views or stream-based ordering. Internal relationships must not rely
solely on public `stream_id`: default 1 does not associate an Opaque part with H2 stream 1.

## Hold preserves whole Parts

Free-form byte `hold(N)` is not the target model. We retain whole parts and their
meaning, not bytes to be rediscovered later.

```python
api.message.parts.hold_from(part)
```

This retains the selected part and every subsequent part in the current order.
The preceding prefix may be assembled and emitted. Scripts may reorder the list
first; there is no general prohibition on a formerly later part overtaking a held part.

The hold buffer preserves type, stream ID, completeness, annotations, internal
relationships, original wire content, lazy representation, draft edits and any
local commit result. Hold itself forces neither decode nor commit. Held parts
are consumed from the current output and must not reach the peer.

The next invocation receives held parts before new parts, preserving order. The
backend must retain semantic state across Python worker lifetimes rather than
relying on surviving Python objects. Transport hold lifetime is not user
`api.state` lifetime.

Hold must be isolated at least by deployment, connection and direction. Endpoint
instancing must not mix connections. Exact transactions across scripts and
deployment changes remain an open implementation contract.

## Custom typed Parts

A script may insert a newly constructed part; the target API includes:

```python
ping = api.http2.Ping(opaque_data=b"12345678")
api.message.parts.append(ping)
```

New parts have no original wire ranges but share the commit contract. Typed
serialization validates type-specific requirements. This constructor example is
not a promise of already implemented support. Interactions with peers, such as
ACK handling for inserted control frames, require explicitly defined behavior.

## Stateful decoding and annotations

The live stateful engine processes each new incoming byte exactly once. A script's
assembled input containing held parts must not be replayed into live HPACK or
decompression state.

```text
new input -> stateful enrichment -> new parts
                                   + held parts
                                   |
                                   v
                              working message
                                   |
                                   v
                            edit / hold / commit
```

Moves and assembly recalculate annotation coordinates and relationships. The
framework need not repair their original semantic correctness or overlaps, but
must preserve derived representation provenance. Enrichment spanning callbacks
is not an ordinary slice.

Incoming decoder state and peer state after output edits are different. In
particular, HPACK writes are not safe merely because one header can be serialized.

## GUI visibility

GUI publication must clearly report at least that content changed or was held.
Original payloads and annotations must not masquerade as modified transmitted output.

Processing metadata should distinguish incoming, modified, held, released and
sent content, identifying original callbacks and the intervening script. Exact
field names and retained-output scope remain open. A change flag alone does not
justify displaying reconstructed output as actually captured data.

## Open decisions and deliberately deferred hold protection

- Atomic continuity of hold buffers and output across a script chain.
- Error, timeout or unavailable worker after a successful hold. Passing only the
  current original fragment is insufficient: earlier held parts would be lost.
- Connection termination, disable, redeploy, filter changes and backend restart.
- Memory/wait limits and policies on exceeding them.
- Serialization and versioning of retained parts, including incomplete representations.
- Completing parts/content across callbacks without replay through the live decoder.
- Exact annotation-overlap, part-splitting and relationship rules.
- `return None`, errors and ad-hoc preview with a hold buffer.

The first live implementation explicitly retains **fail-open**, deferring outage
protection to `docs/TODO.md`. Failure after need-more may break completeness or
ordering; current hold does not solve this. The normal success path must still
prevent early or duplicate emission. This is not TRANSLATE mode.

Live hold is available in the last enabled `flow` deployment. Checkpoints are
separated by deployment/generation, connection and L/R direction, independently
of user `api.state` and Python process state. They are versioned typed JSON, not
pickle. The serialized checkpoint limit is 1 MiB; the deployment limit including
instance state is 4 MiB. Ownership transfers only on successfully returning
`message.commit()`: an empty prefix returns `need-more`, a nonempty prefix returns
`replace`. The next callback restores original Parts and their drafts.

`return None` after restoring hold is an error: explicitly return a result or
hold again. Preview and message/endpoint instancing reject hold. An executed
script failure abandons prior hold in that direction with `hold.state=abandoned`;
current policy passes the current fragment unchanged. Stop/expiry/redeploy also
remove the instance checkpoint. It does not persist across backend restart.
Documentation must expose these limitations.

## Relationship to the current implementation

The write API includes `api.message.snapshot()` and monolithic `draft.http1`,
with private commit and Content-Length recalculation for a limited set of complete
HTTP/1 messages. Live H1 Parts/hold supports an annotated complete header with one
Content-Length and an uncompressed body completed by subsequent callbacks. H1
Header exposes `part.http1`, Body exposes `get_bytes/set_bytes`; commit recalculates
Content-Length.

Initial live H2 REWRITE uses `api.message.parts`: annotated frames, complete local
HEADERS/PUSH_PROMISE + CONTINUATION blocks and Opaque gaps. Incomplete parts can
be preserved, not rebuilt. HPACK fields, explicit indexes, table-size updates,
DATA and custom frames are writable. Complete locally known content permits
Content-Length recalculation; `commit(False)` explicitly disables that repair
for assembler/research edits.

`part.complete` means a complete frame/header block. `part.content.complete` means
complete locally known content (`True`), in progress (`False`) or unknown (`None`).
For DATA without a local initial header, END_STREAM alone does not prove complete
content. Compressed-content writes and general annotation overlaps are not yet
implemented. Bounded live H2 TRANSLATE is implemented as described below.

H2 hold preserves incomplete frames with an available nine-byte header and
incomplete HEADERS/CONTINUATION blocks, completing them without replay into the
live HPACK decoder. Structural H2 parts are assembled when the callback API is
created. DATA and Opaque retain views into original bytes; `get_bytes()` materializes
them on read. An unchanged commit does not copy them into individual representations.

Current HTTP/1 snapshot recognition directly from bytes must be replaced by
annotation-backed interpretation when moving to Parts. The monolithic snapshot
is not a model for further public API growth; its validation and serialization
can become building blocks for parts and their joint commit.

## REWRITE and TRANSLATE

Default **REWRITE** assembles only explicitly modified current content. It never
activates hidden rewriting of later callbacks. The engine serializes frame lengths,
splits DATA/header blocks and resolves supported local dependencies. It does not
guarantee meaningful values, flow-control compensation or future agreement between
peer HPACK tables. An explicit index may reference a missing entry: a valid HPACK
instruction need not be accepted in peer state. This is deliberately the script
author's responsibility. Unchanged HPACK instructions and frames retain original bytes.

Live **TRANSLATE** requires explicit activation. Current H2 support covers
HEADERS/PUSH_PROMISE, HPACK, supported SETTINGS and same-length DATA edits, not
general DATA resizing with flow-control compensation. It requires one enabled
flow deployment and activation in the first content callback. Every subsequent
callback must run the script and return `api.message.translate()`; there are no
hidden repairs outside user execution. The backend pins deployment/version and
maintains separate input/output HPACK states in both directions.

The current proxy requires `request_rewrite()` during setup, before first-payload
analysis. Setup has no `api.message` and does not activate Translate. Without
reservation, only same-length replacement is permitted, at the script's risk.
A missing legacy `rewrite` field remains a compatibility path, not an explicit
denial; see [capability metadata compatibility](INSPECTION_COOKBOOK.md#capability-metadata-compatibility).

The first successfully returned Translate result activates strict alongside content
or need-more. Subsequent callbacks confirm strict and contiguous sequence. An
already active translation failure returns HTTP 503 and closes the strict proxy
connection instead of continuing with inconsistent state. Failure before first
successful activation may still fail open under regular policy. Ordinary REWRITE,
including hold, remains fail-open; state-loss protection is deliberately deferred.
Implemented contract details: [Live H2 Translate](H2_TRANSLATE_LIVE.md).

## Verification criteria

Implementation tests must cover original wire preservation after read-only access,
lazy materialization, Opaque gaps, type hierarchy and default stream ID 1. They
must distinguish frame from content completeness, check atomic commit and retry
after CommitException, and prove semantic preservation across hold.

Transport tests must prove that held content is neither emitted early nor twice,
mixed between connections, or replayed into the live decoder. GUI tests must
distinguish original input from modified or held output.

### First H2 REWRITE verification — 2026-10-25

- `ctest --test-dir build --output-on-failure -j 2`: **17/17 passed**.
- `tests/inspection_h2_test.py`: **17 tests**, including 200 deterministic random
  no-op/partial inputs and 100 binary HPACK literal sets. Independent libnghttp2
  validates output, not our own encoder/parser.
- Coverage includes Huffman/indexed input, explicit table/index edits,
  padding/priority, PUSH_PROMISE, CONTINUATION, size boundaries, END_STREAM,
  Content-Length, DATA insertion/removal, Opaque gaps, lazy materialization,
  atomic failure/retry and explicit worker result publication.
- `spider_chain_test`: real local webhook with backend HPACK enrichment,
  sandboxed rewrite and independent replacement decoding. Disabling the script
  restores unchanged callbacks; translation does not secretly continue.
- Language tests check part, header, HPACK entry and constructor types.
- `tests/browser_smoke.py --repeat 1`: **passed**, isolated editor and
  library/deploy/draft separation regression. It does not test live H2 browser
  traffic; the backend integration above covers that traffic.

### Live hold verification — 2026-10-25

- Expanded to **19 suites**, all also passed under UBSan.
- `inspection_hold_test.py`: **11 tests** covering every H1 body/H2 DATA split,
  repeated checkpoints across fresh workers, retained header drafts and length
  dependencies after DATA removal, prefix emission, limits, invalid annotations
  and unsupported-mode rejection.
- `inspection_hold_live_tests`: real backend handler/pool; interleaved connections
  and directions, concurrent callbacks, bytewise progress, one final replacement,
  stop/redeploy generation isolation and current failure fail-open behavior.
  H2 HEADERS/CONTINUATION uses real HPACK enrichments.
- `spider_chain_test`: two pure `need-more` HTTP responses followed by one `replace`
  with edited body and new Content-Length; no running lab1 required.
- Results do not guarantee backend/proxy outage recovery. That remains an explicit
  TODO, not an implicitly solved property.

### Extended deterministic corpora — 2026-10-25

- Standard build and **21/21 CTest suites passed** in 26.17 s. This was not a new
  UBSan run; the UBSan result above belongs to the preceding suite.
- `inspection_h1_corpus_tests`: requests/responses, empty bodies, every byte value,
  UTF-8, JSON, null bytes, HTTP-looking body content, random data and 64 KiB+1
  bodies. A 54-rewrite fragmentation/length matrix and 69 additional splits check
  exact body/following-Opaque preservation; also 24 interleaved checkpoints and
  draft repair after failed commit.
- `inspection_h2_corpus_tests`: 40 DATA-length/stream-ID combinations including
  16383/16384/16385 boundaries, frame splitting and END_STREAM; 27 HPACK-length/
  indexing combinations with libnghttp2-validated HEADERS/CONTINUATION; 16
  interleaved streams with independent Content-Length; 128 DATA splits with
  repeated checkpoints; 100 random unknown frames preserved byte-for-byte.
- Fixed seeds make failures reproducible. Both suites run in CTest with a 30 s
  timeout. These are transaction/serialization tests, not replacements for live
  webhook/worker-pool integrations or proof of full coverage of all inputs.
