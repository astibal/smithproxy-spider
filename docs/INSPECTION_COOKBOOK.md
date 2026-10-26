# Inspection cookbook

## Setup before live rewrites

Live scripts also receive `connection-start`: `api.phase == 'setup'`,
`api.message is None`, and metadata is in `api.info`. During this phase,
explicitly call `api.connection.request_rewrite()` and return `None` if later
callbacks will change length or use hold/Translate. Without opt-in, a script may
return `None` or a replacement **exactly as long in bytes as this callback's input**,
in both Easy and Expert. Late opt-in raises `CommitException`; Expert alone does
not grant a reservation.

Same-length raw replacement passes silently, even when it changes headers or
state fields. The proxy retains one input context: no second-view recalculation,
Translate activation or late fork. Protocol consistency, content, digests and
possible breakage of later messages are the script's responsibility. Typed
`commit()` checks in Easy/Expert are unchanged; raw output promises no such validation.
Length means the entire resulting replacement, not character count, base64 length
or just the modified body. Unreserved resizing raises `CommitException` in the
worker; the proxy closes the connection on a directly supplied unauthorized
webhook response.

<!-- example: same-size-without-reservation fixture=h1-unreserved expect=replace -->
```python
if api.phase == 'setup':
    return  # No second-context reservation.
# Simple same-length raw rewrite; parser consistency is not checked.
return api.bytes.replace(b'abc', b'xyz')
```

For live deployment, prepend this guard to the payload examples below. Saved-sample
previews have `api.phase == 'content'` and need no reservation. Setup does not
activate Translate: each content callback still requires an explicit
`return api.message.translate()`.

<!-- example: reserve-rewrite fixture=setup expect=setup -->
```python
if api.phase == 'setup':
    api.connection.request_rewrite()
    return
# The payload example continues here.
return None
```

Reservation belongs to the connection; changing deployments mid-session cannot
grant it retroactively to an unreserved session. Filters and scope are evaluated
during setup, so they can use only metadata available then, not future L7 annotations.
Failed setup publishes no reservation. In flow instancing, successfully saved
`api.state` carries from setup to the first content callback.

### Capability metadata compatibility

`webhook_control.rewrite` has three distinct states:

| Value | Current behavior |
|---|---|
| `false` | Unreserved: same-length replacement only, no hold/Translate. |
| `true` | The proxy confirms reserved rewrite capability. |
| Absent | Legacy path or offline input; the worker does not enforce reservation. |

An absent field does not confirm the new setup contract. For compatibility, it is
not converted to `false`. Legacy Translate still requires all other conditions:
control `version == 1`, first content `sequence == 1`, one flow deployment and
subsequent strict/sequence confirmation. Absence alone or offline preview does
not activate Translate. This does not promise compatibility with every old proxy;
use current proxy and Spider versions with explicit setup.

## Easy and Expert

The default is `Safety.Easy`. `commit(safety=Safety.Expert)` applies only to that
call; neither separate `part.commit()` nor hold carries it to the next commit.
Snapshot, message and translate accept the same parameter. It is independent of
`Mode.Rewrite` / `Mode.Translate`, instancing and deployment scope.

| Area | Easy | Expert |
|---|---|---|
| Supported H1 Content-Digest | Recalculates | Recalculates |
| H1 body edit with unsupported encoding/digest/range/signature metadata | Rejects | Leaves metadata to the script |
| H1 Host and bodyless status | Checks semantics on change | Permits inconsistency |
| Known Content-Length | Recalculates | Also recalculates; Expert does not implicitly disable repairs |
| H2 control above configured max_frame_size | Rejects at commit; the limit can be set first | Permits within physical representation and quota |
| H2 fragmentation below 16384 | Rejects | Permits with positive frame data capacity |
| Edited incomplete part, conflicting raw/typed writes, quota, duplicate object | Rejects | Rejects |
| Translate HPACK/strict/flow-control conditions | Preserves | Preserves; no implicit switch to rewrite |

`message.commit(False, safety=Safety.Expert)` disables only known H2 Content-Length
repair. H1 typed assembly always recalculates length. Compressed H1 Parts, chunked,
trailers, upgrade and ambiguous input framing remain unsupported in both modes;
Expert neither implements them nor automatically compresses content.

Easy provides existing semantic safeguards, **not complete protocol validation**.
For example, H2 rewrite does not maintain peer HPACK state even in Easy; unchanged
bytes, including unknown frames, are preserved. Typed values still require
unambiguous encoding (for example, a header name without CR/LF or a positive HPACK
index); explicit raw output is not a safety filter. Storage, reads and setters
also do not depend on commit safety. Every field/method's exact rules are in the
[generated reference](API_EXAMPLES_REFERENCE.md), browser API Reference and editor
hints. There is no automatic Easy-to-Expert fallback.

For the same edit with an invalid digest, Easy rejects it while Expert assembles
a deliberately inconsistent message. Other examples without `safety` use Easy.

<!-- example: easy-digest fixture=h1 expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.set_header("Digest", "old-digest")
draft.http1.body = b"changed"
return draft.commit(safety=Safety.Easy)
```



<!-- example: expert-digest fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
draft.http1.set_header("Digest", "old-digest")
draft.http1.body = b"changed"
return draft.commit(safety=Safety.Expert)
```

Live connections also expose `api.connection`: explicit mode selection through
`set_mode(Mode.Translate)` and persistent H2 policy through
`http2.enforce_header_table_limit(0)`. See [H2 translate](H2_TRANSLATE_LIVE.md)
for the contract and example; they require a live flow instance, not an offline
fixture. Setters do not replace `return api.message.translate()`.

These short scenarios are for your own lab and authorized testing. Use each block
as a separate script, not successive steps of one script.
`inspection_cookbook_tests` executes every Python block here in a real worker
against its marked fixture, including expected errors.

## H1 content changes with Content-Digest

Complete uncompressed H1 bodies can be edited through a snapshot or Body part.
Commit recalculates Content-Length and existing or newly set Content-Digest.
Supported algorithms are `sha-256` and `sha-512`, including both together and
multiple header lines (output is normalized to one line). This is a byte-sequence
dictionary under [RFC 9530 §2](https://www.rfc-editor.org/rfc/rfc9530.html#section-2).

<!-- example: content-digest-repair fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
draft.http1.body = b"changed"
# An empty byte sequence is an assembly input; commit fills in the actual hash.
draft.http1.set_header("Content-Digest", "sha-256=::, sha-512=::")
return draft.commit()
```

Both Easy and Expert repair supported digests. Expert does not disable repair.
Unknown algorithms, member parameters, duplicate algorithms and invalid syntax
are currently unsupported: Easy raises CommitException, Expert preserves the
whole dictionary unchanged (no partial repair). A complete no-op preserves
original bytes; unchanged digests are not verified. Reading a snapshot is not an
integrity check. Removing Content-Digest explicitly removes that integrity claim.

Repr-Digest, ETag, signatures, Content-Range, chunked/trailers and compression are
outside this step. Easy still rejects body edits with such unresolved dependencies.
A digest header cannot be sent before the digest is calculated: for incomplete
Parts, hold the entire H1 message from its Header part until the body is complete.
Recalculation does not mutate the draft, and failed commit publishes nothing.

## What 100% coverage means

The [complete inventory](API_EXAMPLES_REFERENCE.md) contains an example of **every
member of the current typed API schema**. Generator and test reject stale docs;
`inspection_api_tests` also executes every schema example against empty, populated
and incomplete callbacks. Practical scenarios and failures follow below.
Older flat helpers are demonstrated together in the first example.

Verification on 2026-10-25: schema v0.5 had 20 types and 82 members; the cookbook
contained 21 independent executable blocks. **22/22 CTest tests passed** (29.17 s).
New documentation tests used the real sandboxed worker; this was not a new UBSan
or production load test.

This does not mean 100% branch coverage, all protocol combinations or a guarantee
of correctness. `PartType` supports `Opaque`, `Http1.Part/Header/Body` and
`Http2.Part/Header/Data/Frame`; `part.is_a(...)` tests the type family.
`HeldCommit` is opaque: return it, do not construct or serialize it.

## Basic rules

- Read-only views describe input; `message.parts` contains editable drafts.
- `get_bytes()` materializes bytes on read. Compression is not yet a write API here.
- `part.commit()` returns local bytes; only `return api.message.commit()` publishes
  the assembled message. Calling commit alone sends nothing.
- `complete` means a complete part; `content.complete` means the entire known
  content (`True`, `False`, or `None` when undeterminable).
- Hold requires the last enabled live flow deployment and direction L/R.
  Run on selected and message/endpoint instancing do not support transport hold.
- REWRITE does not translate subsequent messages. HPACK table edits can desynchronize peers.
- Ordinary REWRITE script failure under regular policy is fail-open. After failure
  with held data, an intact flow cannot be guaranteed; HOLD/REWRITE protection is
  TODO. Already active Translate instead returns HTTP 503 and the strict proxy
  closes the connection. Failure before first successful activation may still
  fail open; a setter call alone does not activate proxy mode.
- Limits: replacement 1 MiB, checkpoint 1 MiB, combined prefix/checkpoint 1.5 MiB,
  state 64 KiB, state+hold 4 MiB per deployment. Large inputs may fail.

## 1. Diagnostics without changing traffic

Metadata can contain secrets; only limited previews are printed here. Flat helpers
are the compatible older interface. L7 ranges are offsets into original
`api.bytes`, not the assembled draft.

<!-- example: observe fixture=h1 expect=unchanged -->
```python
api.print(api.session_id, api.session_label, api.side)
api.print("decoded views", api.http1.available, api.http2.available)
api.print(len(api.bytes), api.text[:40])
api.print(api.event.get("id"), api.info.get("payload_layer"))
api.print(api.annotations, len(api.enrichments))
api.print(api.l7_state, api.l7_ranges, api.l7_encodings)
api.print(api.l7_bytes[:16].hex())
api.print(api.hexdump(limit=32, width=8))
return None
```

## 2. H1: change the path and add a test identifier

A snapshot is an independent draft of a complete H1 message. `set_header`
replaces duplicates; to retain repeated headers, append `Header(name, value)`
directly to the list.

<!-- example: h1-route fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
if not draft.http1.available:
    return None
draft.http1.target = "/lab/echo"
draft.http1.remove_header("X-Old")
draft.http1.set_header("X-Test-ID", "spider-lab")
draft.http1.headers.append(Header("X-Tag", "first"))
draft.http1.headers.append(Header("X-Tag", "second"))
return draft.commit()
```

## 3. H1 Parts: rewrite the body and repair length

Uncompressed, with one Content-Length and an annotated complete header.
HTTP-looking body text is not another header. Length is measured in bytes.

<!-- example: h1-body fixture=h1 expect=replace -->
```python
for part in api.message.parts:
    if part.is_a(PartType.Http1.Part):
        api.print(part.type, part.content.complete)
    if part.type == PartType.Http1.Body:
        part.set_bytes(b'{"lab":true}')
return api.message.commit()
```

## 4. H1: wait for the rest of the body

The first callback contains the header and only `a` of body `abc`; the second
supplies `bc`. The first result is `need-more`, the second a single `replace`
with repaired length. Hold from the header because its Content-Length still needs editing.

<!-- example: h1-hold fixture=h1-partial expect=hold-resume -->
```python
for part in api.message.parts:
    if part.type == PartType.Http1.Header and not part.content.complete:
        api.message.parts.hold_from(part)
        return api.message.commit()
    if part.type == PartType.Http1.Body:
        part.set_bytes(part.get_bytes() + b"-checked")
return api.message.commit()
```

## 5. H2: tag a test request

This example handles only stream 3. Rewrite header values are `bytes`, whereas
read-only decoded views use text. Local commit can be used for a preview.

<!-- example: h2-header fixture=h2 expect=replace -->
```python
for part in api.message.parts:
    if part.stream_id == 3 and part.type == PartType.Http2.Header:
        part.headers.set_header(b"x-test-id", b"spider-lab")
        api.print("encoded bytes", len(part.commit()))
return api.message.commit()
```

## 6. H2: larger DATA and automatic frame splitting

Change a test response/request body to 20 KiB. The engine splits DATA, retains
END_STREAM on the last frame and repairs known Content-Length.

<!-- example: h2-body fixture=h2 expect=replace -->
```python
for part in api.message.parts:
    if part.type == PartType.Http2.Data:
        part.max_frame_size = 16384
        part.set_bytes(b"A" * 20000)
return api.message.commit()
```

## 7. H2: explicit HPACK and custom frames

Isolated labs only. Index 2 is static `:method: GET`; index 62 may already depend
on the dynamic table. Table-size updates must precede header fields. Incremental
indexing changes peer state; rewrite does not repair subsequent messages for you.

<!-- example: h2-construct fixture=h2 expect=replace -->
```python
for part in api.message.parts:
    if part.type == PartType.Http2.Header:
        part.headers.entries = [
            api.http2.TableSize(4096),
            api.http2.HeaderIndex(2),
            api.http2.Header(b"x-lab", b"value", "incremental"),
            api.http2.Header(b"authorization", b"lab-only", "never"),
        ]
api.message.parts.append(api.http2.Ping(b"lab-ping"))
api.message.parts.append(api.http2.Frame(0, 1, 5, b"lab"))
return api.message.commit(False)
```

`commit(False)` disables automatic Content-Length repair, not serialization
validation. Resulting stream consistency is deliberately the test author's responsibility.

## 8. Opaque: a known custom binary format

Without annotations, the engine does not guess HTTP. Explicitly editing Opaque
content in a custom protocol makes its framing your responsibility.

<!-- example: opaque fixture=opaque expect=replace -->
```python
for part in api.message.parts:
    if part.type == PartType.Opaque:
        part.set_bytes(part.get_bytes() + b"\x00")
return api.message.commit()
```

## 9. Instance and shared counter

`state` lives according to instancing (message/flow/endpoint), not as a Python
global. Shared storage operations are individually atomic, but a sequence of
operations is not a transaction. A later script failure does not roll back storage writes.

<!-- example: counters fixture=h1 expect=unchanged -->
```python
api.print(api.instance.mode, api.instance.key,
          api.instance.deployment_id, api.instance.version)
api.state["callbacks"] = api.state.get("callbacks", 0) + 1
shared = api.storage.namespace("lab-cookbook")
shared.set("last", {"side": api.metadata.side})
api.print(shared.get("last", {}))
api.print(shared.increment("callbacks"))
shared.delete("last")
return None
```

## 10. Commit without return publishes nothing

<!-- example: discard-draft fixture=h1 expect=unchanged -->
```python
draft = api.message.snapshot()
draft.http1.body = b"not published"
draft.commit()
return None
```

## 11. Error: CRLF in an H1 header

The engine rejects inserting another line through a header value. An uncaught
CommitException means script failure and no replacement, not a partial rewrite.

<!-- example: bad-header fixture=h1 expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.set_header("X-Test", "value\r\nInjected: yes")
return draft.commit()
```

## 12. Catch an error and repair the draft

<!-- example: retry fixture=h1 expect=replace -->
```python
draft = api.message.snapshot()
draft.http1.target = "/bad target"
try:
    return draft.commit()
except CommitException:
    draft.http1.target = "/safe"
    return draft.commit()
```

## 13. Error: editing a gzip body without an encoder

A snapshot permits the original message unchanged, but editing its encoded body
is unsupported. The same applies to integrity/range metadata that cannot be recalculated.

<!-- example: encoded-body fixture=gzip expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.body = b"plain text is not gzip"
return draft.commit()
```

## 14. Error: incomplete H1 message without hold

<!-- example: incomplete fixture=h1-partial expect=CommitException -->
```python
return api.message.commit()
```

## 15. Error: invalid PING / HPACK ordering

PING must contain exactly eight bytes; a table-size update must not follow a header field.

<!-- example: ping-size fixture=h2 expect=CommitException -->
```python
api.message.parts.append(api.http2.Ping(b"short"))
return api.message.commit()
```



<!-- example: table-order fixture=h2 expect=CommitException -->
```python
for part in api.message.parts:
    if part.headers is not None:
        part.headers.entries.append(api.http2.TableSize(0))
return api.message.commit()
```

## 16. Error: the same part twice in the output

Construct a copy explicitly; do not append the same object twice.

<!-- example: duplicate fixture=h2 expect=CommitException -->
```python
api.message.parts.append(api.message.parts[0])
return api.message.commit()
```

## 17. Error: invalid shared counter

Storage contains JSON values; increment does not convert text to a number.

<!-- example: bad-counter fixture=h1 expect=TypeError -->
```python
shared = api.storage.namespace("lab-cookbook")
shared.set("bad-counter", "three")
shared.increment("bad-counter")
```

## 18. Error: hold in preview or without returning the result

The first example runs as Run on selected (no flow deployment): commit creates
a local result, but the worker rejects transport hold. The second never returns commit.

<!-- example: hold-preview fixture=h1-partial expect=CommitException -->
```python
api.message.parts.hold_from(api.message.parts[0])
return api.message.commit()
```



<!-- example: hold-no-return fixture=h1-partial expect=CommitException -->
```python
api.message.parts.hold_from(api.message.parts[0])
return None
```

## 19. Error: replacement too large

The entire replacement, including headers, must fit within 1 MiB, not just the body.

<!-- example: too-large fixture=h1 expect=CommitException -->
```python
draft = api.message.snapshot()
draft.http1.body = b"A" * (1024 * 1024)
return draft.commit()
```

## Other important boundaries

- H1 Parts do not yet parse chunked/compressed/pipelined messages. Without suitable
  annotations, the result is Opaque, not automatically recognized HTTP.
- An incomplete H2 frame can be preserved unchanged but not arbitrarily rewritten;
  rewrite hold currently needs the complete nine-byte frame header.
- An unresolved HPACK index may have no `name`/`value`; `set_header` may then fail.
  An explicit index may be serializable yet meaningless to the peer.
- Read-only dataclasses and memoryviews cannot be edited. Use drafts/Parts.
- Removed/duplicated hold boundaries, oversized checkpoints, `return None` after
  restored hold, or hold without `return message.commit()` are errors.
- Storage may report contention/infrastructure failure as `StorageBusy`;
  the sandbox blocks networking and unauthorized files. These are not payload validation errors.
