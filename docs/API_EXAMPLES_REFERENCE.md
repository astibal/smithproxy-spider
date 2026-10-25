# API examples: úplný inventář

Generováno pomocí `python3 tools/generate-api-examples.py`; neupravuj ručně.

[Praktické scénáře a očekávané chyby](INSPECTION_COOKBOOK.md).

Tyto mikro-příklady pokrývají každý veřejný člen typovaného schematu.
`api` poskytuje callback. Příklady s `part` předpokládají vybraný H2
HEADERS part s dekódovanými hlavičkami; `entry` je jeho HPACK položka.
Nejde o jeden souvislý skript: každý blok je samostatná ukázka.

## InspectionViews

Typed API v0.6. Read-only input views, editable Parts, H1 snapshots and explicit live H2 translation.

### InspectionViews.message

Current content fragment.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `Message`.

```python
api.print(api.message.size)
```

### InspectionViews.metadata

Metadata of the current content callback.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `ContentMetadata`.

```python
api.print(api.metadata.side)
```

### InspectionViews.http1

HTTP/1 head supplied by backend enrichment.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `Http1`.

```python
if api.http1.available:
    api.print(api.http1.target)
```

### InspectionViews.http2

Read-only HTTP/2 frame slices and decoded HPACK blocks.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `Http2`.

```python
for block in api.http2.header_blocks:
    for header in block.headers:
        api.print(block.stream_id, header.name, header.value)
```

### InspectionViews.state

JSON object local to this logical instance. Committed after success, discarded on error; 64 KiB maximum. No persistent Python globals.

Dostupnost: Always available for a content callback.

Přístup: mutable instance state; typ/výsledek: `dict[str, Any]`.

```python
api.state["seen"] = api.state.get("seen", 0) + 1
api.print(api.state["seen"])
```

### InspectionViews.storage

Persistent shared JSON namespaces across scripts and versions. Writes commit per operation, even if the script later fails.

Dostupnost: Always available for a content callback.

Přístup: shared persistent storage; typ/výsledek: `SharedStorage`.

```python
shared = api.storage.namespace("stats")
api.print(shared.increment("callbacks"))
```

### InspectionViews.instance

Identity and lifecycle mode of this invocation.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `InstanceContext`.

```python
api.print(api.instance.mode, api.instance.key, api.instance.version)
```

### InspectionViews.connection

Explicit live connection mode and HTTP/2 policy.

Dostupnost: Always available for a content callback.

Přístup: staged connection policy; typ/výsledek: `Connection`.

```python
api.connection.set_mode(Mode.Translate)
return api.message.translate()
```

## Message

Current webhook content fragment, not necessarily a complete application message.

### Message.bytes

Original callback bytes. No decoding or reassembly.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bytes`.

```python
# Inspect a bounded prefix without assuming text or a complete message.
api.print(api.message.bytes[:32].hex())
```

### Message.size

Length of this fragment in bytes.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
api.print(api.message.size)
```

### Message.parts

Ordered drafts, including resumed held parts. hold_from(part) retains a suffix when the committed result is returned.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `PartList`.

```python
for part in api.message.parts:
    if part.headers is not None:
        part.headers.set_header(b"x-test", b"yes")
return api.message.commit()
```

### Message.commit

Assemble the emitted Parts atomically and checkpoint any held suffix. Recalculate known Content-Length; incomplete emitted content raises CommitException. Return the result to publish it. No future-message translation.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: assemble private draft; typ/výsledek: `bytes | HeldCommit`.

```python
return api.message.commit()
```

### Message.translate

Explicitly translate every callback of a pinned H2 flow. Header edits only; requires a capable strict-control proxy and python-hpack. Hold incomplete Parts with parts.hold_from(part); only the emitted prefix advances HPACK state. No silent background runs.

Dostupnost: First observed content of a new flow, sole enabled deployment; every callback thereafter.

Přístup: assemble translated output; typ/výsledek: `bytes | HeldCommit`.

```python
if api.instance.mode == "flow":
    return api.message.translate()
```

### Message.snapshot

Create an independent editable draft of this callback. No live bytes change until the script returns draft.commit().

Dostupnost: Always available; HTTP/1 editing requires one complete supported message.

Přístup: create private draft; typ/výsledek: `MessageSnapshot`.

```python
draft = api.message.snapshot()
api.print(draft.http1.available)
```

## ContentMetadata

Metadata reported by the current webhook; not connection history.

### ContentMetadata.session_id

Connection identifier from event.id; empty if absent.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
api.print(api.metadata.session_id)
```

### ContentMetadata.side

Observed side: L (client), R (server), or empty when absent.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
if api.metadata.side == "R":
    api.print("Server fragment", api.message.size)
```

### ContentMetadata.payload_layer

Reported payload layer, without inferring a protocol.

Dostupnost: None when webhook omits payload_layer.

Přístup: read-only snapshot; typ/výsledek: `str | None`.

```python
if api.metadata.payload_layer is None:
    api.print("Payload layer was not reported")
else:
    api.print(api.metadata.payload_layer)
```

## Http1

First complete HTTP/1 head decoded by Spider for this callback. Does not imply a complete body or enumerate pipelined messages.

### Http1.available

True only when http1.parse-head enrichment provides a complete head.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool`.

```python
if api.http1.available:
    api.print("Decoded head; body may still be incomplete")
else:
    api.print("No complete HTTP/1 head for this callback")
```

### Http1.method

Request method, e.g. GET. No inference from body bytes.

Dostupnost: None for responses or unavailable heads.

Přístup: read-only snapshot; typ/výsledek: `str | None`.

```python
api.print(api.http1.method)
```

### Http1.target

Request target as decoded by Spider; may contain escaped non-printable bytes.

Dostupnost: None for responses or unavailable heads.

Přístup: read-only snapshot; typ/výsledek: `str | None`.

```python
if api.http1.target is not None:
    api.print(api.http1.method, api.http1.target)  # e.g. GET /search?q=spider
```

### Http1.status

HTTP response status code.

Dostupnost: None for requests or unavailable heads.

Přístup: read-only snapshot; typ/výsledek: `int | None`.

```python
if api.http1.status is not None and api.http1.status >= 400:
    api.print("HTTP error", api.http1.status)
```

### Http1.headers

Ordered headers including duplicates. Empty means no fields or unavailable; check available.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `tuple[Header, ...]`.

```python
for header in api.http1.headers:
    api.print(header.name, header.value)
```

## Header

One decoded HTTP header; order and duplicate names are preserved.

### Header.name

Header name with observed casing.

Dostupnost: Only on an existing Header; shared by HTTP/1 and HTTP/2.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
for header in api.http1.headers:
    if header.name.lower() == "content-type":
        api.print(header.value)
```

### Header.value

Decoded display value from Spider; non-printable bytes may appear as \xNN.

Dostupnost: Only on an existing Header; shared by HTTP/1 and HTTP/2.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
# Iterate instead of converting to a dict: duplicate fields are preserved.
for header in api.http1.headers:
    api.print(header.name, header.value)
```

## Http2

Observed HTTP/2 callback view, not a whole request, stream or connection. Empty header_blocks does not imply no headers on the wire.

### Http2.available

HTTP/2 annotation or complete HPACK enrichment was observed. Does not guarantee decoded headers or complete frames.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool`.

```python
if api.http2.available and not api.http2.header_blocks:
    api.print("H2 observed, but no complete decoded header block in this callback")
```

### Http2.frames

Frames with a complete annotated header in this callback, in wire order. Continuation fragments without a header are not guessed.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `tuple[H2Frame, ...]`.

```python
for frame in api.http2.frames:
    api.print(frame.stream_id, frame.type, frame.complete)
```

### Http2.header_blocks

All complete HPACK enrichments emitted for this callback, in backend order.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `tuple[H2HeaderBlock, ...]`.

```python
for block in api.http2.header_blocks:
    for header in block.headers:
        if header.name in (":method", ":path", ":status"):
            api.print(block.stream_id, header.name, header.value)
```

### Http2.Header

Create a literal HPACK field. Indexing may affect future peer state, which REWRITE does not repair.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: create private draft; typ/výsledek: `HpackField`.

```python
part.headers.entries.append(api.http2.Header(b"x-test", b"yes"))
```

### Http2.HeaderIndex

Create an explicit HPACK field reference. Existence in the peer table is the script author's responsibility.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: create private draft; typ/výsledek: `HpackField`.

```python
part.headers.entries.append(api.http2.HeaderIndex(62))
```

### Http2.TableSize

Create an HPACK table-size update; insert before header fields.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: create private draft; typ/výsledek: `HpackField`.

```python
part.headers.entries.insert(0, api.http2.TableSize(4096))
```

### Http2.Frame

Construct a frame from its raw payload, including any padding/priority fields. Known DATA/header blocks are interpreted for subsequent editing.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: create private draft; typ/výsledek: `RewritePart`.

```python
api.message.parts.append(api.http2.Frame(0, 1, 3, b"body"))
```

### Http2.Ping

Construct a connection-level PING with exactly eight opaque bytes.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: create private draft; typ/výsledek: `RewritePart`.

```python
api.message.parts.append(api.http2.Ping())
```

## H2Frame

Frame starting at an observed complete nine-byte frame-header annotation. No guessed boundaries or cross-callback reassembly.

### H2Frame.offset

Frame header offset in api.message.bytes.

Dostupnost: When frames is non-empty.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
for frame in api.http2.frames:
    header = api.message.bytes[frame.offset:frame.offset + 9]
    api.print(header.hex())
```

### H2Frame.length

Declared frame payload length, excluding its nine-byte header.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
for frame in api.http2.frames:
    api.print("Declared", frame.length, "available", len(frame.payload))
```

### H2Frame.type

Numeric HTTP/2 frame type; unknown types are preserved.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
for frame in api.http2.frames:
    if frame.type == 0:  # DATA; 1 = HEADERS, 9 = CONTINUATION
        api.print("DATA on stream", frame.stream_id)
```

### H2Frame.flags

Raw frame flags; their meaning depends on frame type.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
for frame in api.http2.frames:
    if frame.type in (0, 1) and frame.flags & 0x01:  # END_STREAM, not SETTINGS ACK
        api.print("Stream end declared", frame.stream_id, "frame complete:", frame.complete)
```

### H2Frame.stream_id

HTTP/2 stream ID; zero denotes connection-level frames.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
for frame in api.http2.frames:
    api.print(frame.stream_id)
```

### H2Frame.complete

Entire declared frame payload is present in this callback. Does not imply a complete HTTP body or stream.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool`.

```python
for frame in api.http2.frames:
    if not frame.complete:
        api.print("Partial frame", frame.stream_id, len(frame.payload), "/", frame.length)
```

### H2Frame.payload

Read-only slice of the available frame payload, including padding and priority fields.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `memoryview`.

```python
for frame in api.http2.frames:
    prefix = bytes(frame.payload[:16])  # Explicitly copy only this prefix.
    api.print(prefix.hex())
```

### H2Frame.data

Unpadded DATA bytes only for a complete, valid DATA frame; otherwise None. Still wire content: gzip is not inflated here.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `memoryview | None`.

```python
for frame in api.http2.frames:
    if frame.data is not None:  # An empty DATA slice is valid too.
        api.print(frame.stream_id, len(frame.data), bytes(frame.data[:16]).hex())
```

## H2HeaderBlock

One complete backend-decoded HPACK block; may be headers, trailers or a PUSH_PROMISE.

### H2HeaderBlock.stream_id

Stream ID supplied by the backend decoder.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
for block in api.http2.header_blocks:
    api.print(block.stream_id)
```

### H2HeaderBlock.kind

Original backend header-block kind; does not by itself distinguish initial headers from trailers.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
for block in api.http2.header_blocks:
    api.print(block.stream_id, block.kind)
```

### H2HeaderBlock.parent_stream_id

Parent stream for PUSH_PROMISE, otherwise None.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int | None`.

```python
for block in api.http2.header_blocks:
    if block.parent_stream_id is not None:
        api.print("Push from", block.parent_stream_id, "promises", block.stream_id)
```

### H2HeaderBlock.spans_previous_envelopes

Block includes bytes from earlier callbacks; not all bytes are in api.message.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool`.

```python
for block in api.http2.header_blocks:
    if block.spans_previous_envelopes:
        api.print("Decoded using earlier callbacks", block.stream_id)
```

### H2HeaderBlock.headers

Ordered decoded fields, including pseudo-headers and duplicates.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `tuple[Header, ...]`.

```python
for block in api.http2.header_blocks:
    for header in block.headers:
        api.print(block.stream_id, header.name, header.value)
```

## InstanceContext

Identity of the current logical instance, not a persistent Python process.

### InstanceContext.mode

message, flow or endpoint; ad-hoc preview uses message.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
api.print(api.instance.mode)
```

### InstanceContext.key

Selected flow/endpoint key; empty for message mode.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
api.print(api.instance.key)
```

### InstanceContext.deployment_id

Backend deployment id; empty for ad-hoc runs.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
api.print(api.instance.deployment_id)
```

### InstanceContext.version

Deployed version; zero for ad-hoc runs. New versions have new state.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `int`.

```python
api.print(api.instance.version)
```

## SharedStorage

Backend-wide persistent JSON storage shared across scripts. Not a security boundary between trusted scripts.

### SharedStorage.namespace

Select an explicitly named shared namespace. Names are database keys, never file paths.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: shared storage operation; typ/výsledek: `StorageNamespace`.

```python
shared = api.storage.namespace("inspection-stats")
api.print(shared.increment("callbacks"))
```

## StorageNamespace

Explicit shared namespace. Each operation is atomic; a sequence of operations is not a transaction.

### StorageNamespace.get

Read a JSON value; absent keys return default.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: shared storage operation; typ/výsledek: `Any`.

```python
shared = api.storage.namespace("stats")
api.print(shared.get("responses", 0))
```

### StorageNamespace.set

Atomically replace one JSON value. Independent of script success.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: shared storage operation; typ/výsledek: `None`.

```python
shared = api.storage.namespace("example")
shared.set("last_status", {"code": 200})
```

### StorageNamespace.delete

Atomically remove a key. Returns whether it existed.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: shared storage operation; typ/výsledek: `bool`.

```python
shared = api.storage.namespace("example")
api.print(shared.delete("last_status"))
```

### StorageNamespace.increment

Atomic read-modify-write counter; missing key starts at zero. Use instead of get()+set() when concurrent scripts update counters.

Dostupnost: Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.

Přístup: shared storage operation; typ/výsledek: `int | float`.

```python
shared = api.storage.namespace("stats")
api.print(shared.increment("responses", 1))
```

## MessageSnapshot

Independent draft. commit() assembles and returns bytes, never sends them. Return those bytes from the script to publish; returning None discards changes. A failed commit leaves the original and draft untouched.

### MessageSnapshot.http1

Editable HTTP/1 view. Unsupported or incomplete fragments remain available as unchanged no-op snapshots only.

Dostupnost: Always available for a content callback.

Přístup: mutable private draft; typ/výsledek: `Http1Draft`.

```python
draft = api.message.snapshot()
if draft.http1.available:
    draft.http1.set_header("X-Spider", "inspected")
    try:
        result = draft.commit()
        api.print(len(result))  # Use return result to apply the edit.
    except CommitException as error:
        api.print("Cannot commit:", error)
```

### MessageSnapshot.commit

Validate and rebuild a single HTTP/1 message, recalculating Content-Length. Returns at most 1 MiB. No-op preserves exact original bytes. Raises CommitException for unsupported framing or invalid edits; catch it in the script. No partial publication.

Dostupnost: On a message snapshot. H2, chunked, partial and pipelined edits are rejected.

Přístup: assemble private draft; typ/výsledek: `bytes`.

```python
draft = api.message.snapshot()
if draft.http1.available:
    draft.http1.set_header("X-Spider", "inspected")
    try:
        result = draft.commit()
        api.print(len(result))  # Use return result to apply the edit.
    except CommitException as error:
        api.print("Cannot commit:", error)
```

## Http1Draft

Mutable HTTP/1 wire snapshot, not the escaped display headers in api.http1. Header strings round-trip via Latin-1; body is bytes. No reassembly or automatic decompression.

### Http1Draft.available

One complete supported HTTP/1 message was found. Informational, not a bypass for commit validation.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool`.

```python
draft = api.message.snapshot()
api.print(draft.http1.available)
```

### Http1Draft.headers

Ordered draft headers. Duplicates are preserved except Content-Length, which commit manages. Use set_header/remove_header for convenient edits.

Dostupnost: Always available for a content callback.

Přístup: mutable private draft; typ/výsledek: `list[Header]`.

```python
draft = api.message.snapshot()
if draft.http1.available:
    draft.http1.set_header("X-Spider", "inspected")
    try:
        result = draft.commit()
        api.print(len(result))  # Use return result to apply the edit.
    except CommitException as error:
        api.print("Cannot commit:", error)
```

### Http1Draft.body

Complete wire body. Assign bytes; commit recalculates Content-Length. Encoded bodies and bodies with known integrity metadata cannot be changed in this version.

Dostupnost: Always available for a content callback.

Přístup: mutable private draft; typ/výsledek: `bytes`.

```python
draft = api.message.snapshot()
if draft.http1.available:
    api.print(len(draft.http1.body))
```

### Http1Draft.target

Request target, or None for a response. May change length. Whitespace and control bytes are forbidden.

Dostupnost: Always available for a content callback.

Přístup: mutable private draft; typ/výsledek: `str | None`.

```python
draft = api.message.snapshot()
if draft.http1.available and draft.http1.target is not None:
    draft.http1.target = "/inspection"
```

### Http1Draft.set_header

Replace all case-insensitive occurrences at the first occurrence, or append a new header. Validation happens at commit.

Dostupnost: On a private HTTP/1 draft.

Přístup: edit private draft; typ/výsledek: `None`.

```python
draft = api.message.snapshot()
if draft.http1.available:
    draft.http1.set_header("X-Spider", "inspected")
    try:
        result = draft.commit()
        api.print(len(result))  # Use return result to apply the edit.
    except CommitException as error:
        api.print("Cannot commit:", error)
```

### Http1Draft.remove_header

Remove every case-insensitive occurrence. Removing Content-Length does not disable framing: commit recreates it when needed.

Dostupnost: On a private HTTP/1 draft.

Přístup: edit private draft; typ/výsledek: `None`.

```python
draft = api.message.snapshot()
if draft.http1.available:
    draft.http1.remove_header("X-Debug")
```

## CommitException

Draft cannot be assembled safely. Original bytes are unchanged; fix the draft and retry, or return None. Available directly in script scope.

Typ bez veřejných členů ve schematu; praktické použití je v cookbooku.

## RewritePart

Assembler-level H2 or Opaque part. No implicit future-message translation.

### RewritePart.type

opaque, http2.header, http2.data, or http2.frame.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `str`.

```python
if part.type == PartType.Http2.Data:
    part.set_bytes(b"new body")
```

### RewritePart.stream_id

H2 stream identifier, or 1 for Opaque. Zero remains zero.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `int`.

```python
part.stream_id = 3
```

### RewritePart.frame_type

Numeric frame type; None for Opaque.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `int | None`.

```python
api.print(part.frame_type) 
```

### RewritePart.flags

Frame flags; END_HEADERS is rebuilt when a header block is edited.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `int`.

```python
part.flags |= 1  # END_STREAM on DATA/HEADERS
```

### RewritePart.complete

Complete frame or HEADERS/CONTINUATION block available. Hold incomplete parts to continue them in a later callback before assembly.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool`.

```python
if part.complete:
    api.print(part.get_bytes()[:16].hex())
```

### RewritePart.content

Separate whole-content completeness, based on original callback parts.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `PartContent`.

```python
api.print(part.complete, part.content.complete)
```

### RewritePart.headers

HPACK instructions for a complete parseable block; None otherwise.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `H2Headers | None`.

```python
if part.headers is not None:
    part.headers.set_header(b"x-test", b"yes")
```

### RewritePart.max_frame_size

Output splitting limit, default 16384. Caller may set a known peer limit up to 16777215.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `int`.

```python
part.max_frame_size = 16384
```

### RewritePart.http1

H1 header draft for an annotated Content-Length message; None on other parts. Edit the body through its Body part.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `Http1Draft | None`.

```python
for part in api.message.parts:
    if part.http1 is not None:
        part.http1.set_header("X-Test", "held")
```

### RewritePart.is_a

Test exact type or family.

Dostupnost: All rewrite parts.

Přístup: read-only; typ/výsledek: `bool`.

```python
if part.is_a(PartType.Http2.Part):
    api.print(part.stream_id)
```

### RewritePart.get_bytes

Materialize representation: unpadded DATA, HPACK block, raw control-frame payload, or Opaque bytes. No gzip inflation.

Dostupnost: All rewrite parts.

Přístup: read-only; typ/výsledek: `bytes`.

```python
api.print(part.get_bytes()[:32].hex())
```

### RewritePart.set_bytes

Replace the representation, not the nine-byte frame header. Rewrite supports unknown frame types; translate permits same-length DATA edits while preserving stream ID, flags and padding.

Dostupnost: Complete parts only for a changed commit.

Přístup: mutable rewrite draft; typ/výsledek: `None`.

```python
part.set_bytes(b"changed")
```

### RewritePart.commit

Prepare this part without publishing or changing the original. Message commit handles cross-part dependencies.

Dostupnost: Unchanged or complete parts.

Přístup: assemble private draft; typ/výsledek: `bytes`.

```python
wire = part.commit()
api.print(len(wire))
```

## PartContent

Completeness of this callback's known content, not just one frame.

### PartContent.complete

True only for a complete locally bounded content; False for a known unfinished content; otherwise None.

Dostupnost: Always available for a content callback.

Přístup: read-only snapshot; typ/výsledek: `bool | None`.

```python
if part.content.complete is not True:
    api.print("Whole content is not available")
```

## H2Headers

Ordered mutable HPACK instructions. Unchanged instructions keep their wire bytes.

### H2Headers.entries

Preserves duplicates, representation choices and table-size instructions. Reorder, append or remove explicitly.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `list[HpackField]`.

```python
part.headers.entries.append(api.http2.Header(b"x-test", b"yes", "incremental"))
```

### H2Headers.set_header

Replace matching fields with one literal; fails if any field name is unresolved. Does not protect future peer state.

Dostupnost: Complete decoded H2 header block.

Přístup: mutable rewrite draft; typ/výsledek: `None`.

```python
part.headers.set_header(b"x-test", b"yes")
```

## HpackField

One HPACK instruction, including indexed references and table-size updates.

Logical names/values are bytes, not escaped GUI strings. None means the
backend did not supply the decode context. Explicit indices are not resolved
or checked against the peer's table; REWRITE deliberately leaves that to you.


### HpackField.name

Logical name, None when unresolved.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `bytes | None`.

```python
entry.name = b"x-test"
```

### HpackField.value

Logical value, None when unresolved.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `bytes | None`.

```python
entry.value = b"changed"
```

### HpackField.indexing

without, incremental, never, indexed, or table-size. Changing it may diverge peer HPACK state.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `str`.

```python
entry.indexing = "incremental"
```

### HpackField.index

Full-field reference for indexed; capacity for table-size.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `int`.

```python
entry.index = 62
```

### HpackField.name_index

Name-only reference for literal fields; zero encodes the name bytes.

Dostupnost: Always available for a content callback.

Přístup: mutable rewrite draft; typ/výsledek: `int`.

```python
entry.name_index = 0
```

## PartList

Ordered mutable parts with an explicit suffix hold boundary.

### PartList.hold_from

Hold this part and everything after it. Return message.commit() in rewrite or message.translate() in translate to publish the prefix and retain the suffix for the next callback.

Dostupnost: Live flow deployment at the end of the enabled chain.

Přístup: mutable hold boundary; typ/výsledek: `None`.

```python
if api.message.parts:
    api.message.parts.hold_from(api.message.parts[0])
    return api.message.commit()
```

## HeldCommit

Opaque committed prefix plus retained Parts. Return it from the script; do not serialize it yourself.

Typ bez veřejných členů ve schematu; praktické použití je v cookbooku.

## Connection

Connection intent is staged; setters never send or translate payloads by themselves.

### Connection.http2

HTTP/2 connection policy.

Dostupnost: Always available for a content callback.

Přístup: staged connection policy; typ/výsledek: `ConnectionHttp2`.

```python
api.connection.set_mode(Mode.Translate)
api.connection.http2.enforce_header_table_limit(0)
return api.message.translate()
```

### Connection.set_mode

Request Mode.Translate explicitly. Requires flow instantiation and a live eligible connection. Mode.Rewrite is a no-op before activation; an active translated connection cannot revert.

Dostupnost: Live flow deployment. The returned translate result activates the mode atomically.

Přístup: staged connection mode; typ/výsledek: `None`.

```python
api.connection.set_mode(Mode.Translate)
return api.message.translate()
```

## ConnectionHttp2

Persistent HTTP/2 policy, applied only by an explicitly returned translate result.

### ConnectionHttp2.enforce_header_table_limit

Enforce a maximum HPACK table capacity in both directions. Idempotent; never increases a peer-advertised limit. SETTINGS and synthetic ACK handling occur only through message.translate().

Dostupnost: Live H2 flow deployment; requires Translate mode. Each direction is updated on its next eligible callback, after its first SETTINGS.

Přístup: staged connection policy; typ/výsledek: `None`.

```python
api.connection.set_mode(Mode.Translate)
api.connection.http2.enforce_header_table_limit(0)
return api.message.translate()
```
