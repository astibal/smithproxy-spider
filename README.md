# Smithproxy Spider

**Binding API design:** [First Class API Design](docs/FIRST_CLASS_API_DESIGN.md)
defines the required Parts model, lazy representations, transactional commit and
semantic hold buffers. It distinguishes the target architecture from implemented
features; API changes must follow this contract.

**API examples:** [Practical cookbook](docs/INSPECTION_COOKBOOK.md) includes small
H1/H2 rewrite, hold, storage and expected-failure scripts, executed by the real
worker in `inspection_cookbook_tests`. The [complete example inventory](docs/API_EXAMPLES_REFERENCE.md)
covers every typed schema member; regenerate with `python3 tools/generate-api-examples.py`.
The test rejects stale generated documentation. This is public API example coverage,
not a claim of exhaustive input or branch coverage.

### Python editor type inference

The editor uses an authenticated backend language service (`POST /api/inspection/language`)
powered by optional **Jedi** in the Python interpreter selected by CMake. Install Jedi
in that interpreter's environment (for a system Python, the distribution's `python3-jedi`
package). Without it or with an older backend, direct `api.…` schema completion still works;
the editor shows the fallback status and an explanatory tooltip.

- Ctrl+Space completes aliases, loop elements and ordinary Python values.
- Hover shows inferred definitions/documentation; Ctrl+Shift+Space shows call parameters.
- Syntax diagnostics are underlined. This is not a full type checker: invalid attribute
  diagnostics and complete control-flow narrowing are not guaranteed.

Typed properties and examples are generated from the same API schema as the reference.
Analysis includes the hidden `def __spider_script(api: SpiderApi)` wrapper, and maps
positions back to the visible script. Python source is analyzed, not executed, and no
traffic samples are sent with editor requests. The transport is a small HTTP API, not
a general-purpose LSP endpoint. One isolated analysis worker (separate from execution
slots), a 64 KiB script limit and a 2.5 s wall-clock limit bound each query. Requests
are serialized, debounced for typing, and discarded when the document/backend changes.
No Node.js or Python runtime is added to the browser.

### Read-only HTTP/2 inspection API

`api.http2.frames` exposes annotated frame headers (offset, declared length, numeric
type, flags, stream ID and completeness). `payload` is a read-only memoryview into
the current callback; `data` is an unpadded DATA slice only when the frame is complete
and its padding is valid. No boundaries are guessed and no reassembly is performed
in Python. A continuation fragment without an annotated frame header is not listed.

`api.http2.header_blocks` exposes every complete backend HPACK enrichment, preserving
field order, duplicates, pseudo-headers, stream ID, block kind and cross-callback
provenance. Missing HPACK context means no decoded block, not an empty HTTP head.
These immutable views do not modify traffic. The backend-generated API reference
and editor completions use the same typed definitions and examples.

```python
for block in api.http2.header_blocks:
    for header in block.headers:
        api.print(block.stream_id, header.name, header.value)
for frame in api.http2.frames:
    if frame.data is not None:
        api.print(frame.stream_id, len(frame.data), "DATA bytes")
return None
```

### Transactional HTTP/1 writes (API v0.4)

Original views remain immutable. `api.message.snapshot()` creates an independent
draft from the **wire bytes**, not the escaped display enrichment. Edit its
`http1.headers`, `http1.target` or `http1.body`, then call `commit()` to validate
and assemble replacement bytes. Header values use Latin-1; encode a text body
explicitly (for example with UTF-8) and set its Content-Type appropriately.

```python
draft = api.message.snapshot()
if not draft.http1.available:
    return None
try:
    draft.http1.set_header("X-Inspected-By", "Spider")
    if draft.http1.target is not None:
        draft.http1.target = "/new/path"
    # draft.http1.body = "New content".encode("utf-8")
    return draft.commit()
except CommitException as error:
    api.print("Cannot commit:", error)
    return None  # Keep the input of this script unchanged.
```

`commit()` itself does not publish or change `api.bytes`, `api.message`, protocol
views or the draft. Only returning its bytes publishes the replacement through
the existing backend `replace` response. Returning None discards a successful
commit too. Failed commits leave the draft editable for correction and retry.
An uncaught CommitException is a normal script error; the existing chain rolls
back payload changes to the original callback. This is not a transaction for
`api.storage` operations or already successful instance-state updates.

Supported: one complete HTTP/1.0 or HTTP/1.1 message in one callback, ordered
headers (including duplicates), request-target edits and unencoded body changes.
`set_header` replaces all occurrences case-insensitively; `remove_header` removes
them all. `Header(name, value)` is also available in script scope for explicitly
appending duplicate fields. Content-Length is managed by commit and counts bytes,
not characters. A 304 Content-Length retains its representation-length meaning.
Unchanged drafts preserve exact original bytes. Output is limited to 1 MiB.

Unsupported edits raise CommitException: HTTP/2, chunked/Transfer-Encoding,
trailers, partial or pipelined messages, close-delimited responses, CONNECT and
protocol upgrades. No cross-callback buffering is done. `available` describes
supported input framing, not a guarantee that every subsequent edit can commit.
Body changes with Content-Encoding, known digest/ETag/range metadata, and changes
to signed messages are rejected rather than silently leaving stale metadata.
Compression, HPACK, application-specific checksums/authentication and semantic
request-response correlation are not recomputed. In particular, a HEAD response
whose declared length exceeds the supplied bytes is not treated as a complete
editable body. HTTP methods, response statuses and protocol versions are not
editable in this first write API.

The schema, API Reference and Jedi alias completion include MessageSnapshot,
Http1Draft and CommitException. Rebuild the backend to update both worker and
generated documentation; no browser Python runtime is required.

### Saved Follow sessions

**Save to library…** stores a named snapshot of all currently retained payloads in the Follow
scope, their enrichments, retained event messages, context-completeness flags and view
preferences. It opens a separate saved tab; the live Follow remains separate.
**Capture Library** in the Payloads heading opens the backend catalog, including sessions
whose tabs were closed. Open saved tabs reload their actual data from the backend on UI
restart, not from the volatile payload cache.

The collection picker also offers **Open in Follow** for a selected sample. This opens
an offline tab with its original bytes, annotations, enrichments and stored session
context, without copying the sample or appending live traffic. Reload restores it from
the collection. A single sample is explicitly incomplete connection context; **Save to library…**
can create a named snapshot of it.

Snapshots are private files under `$SPIDER_COLLECTION_DIR/saved-sessions`, written via
an exclusive temporary file and atomic rename. Names are labels, never filesystem paths;
Save as always creates a new ID, even for the same name. Saved sessions share the collection
disk budget and are limited to 64 MiB / 10,000 payload records per snapshot. Missing or
evicted data is not recovered by saving. Saved tabs do not accept live traffic, and cannot
send live decisions; recomputation affects the open copy until saved again.

Authenticated API: `GET/POST /api/inspection/saved-flows` (list/save) and
`GET /api/inspection/saved-flow?id=...` (load). A backend update is required.

### Follow enrichment replay

Opening Follow recomputes enrichment from the currently retained browser payloads,
in arrival order, using an isolated backend decoder. **Recompute** repeats the snapshot
after more payloads arrive. No scripts, traffic decisions, collection writes or live
decoder state are involved. Results merge into the existing cards; original bytes
are unchanged. Replay does not run continuously on each incoming payload.

Known cache eviction, omitted passed payloads or a missing connection-start make
HPACK context incomplete; replay does not reconstruct HPACK for those sessions.
Other supported enrichments can still be recovered where the retained bytes suffice.
Previously available enrichments are preserved when replay cannot produce replacements.
The status shows processed payloads, output count and incomplete connections.

The authenticated `POST /api/enrichment/replay` accepts an SXBN chain, each envelope
containing `{event, context_complete}` plus raw payload bytes, and returns enrichment
envelopes with `replay_index` and a final `replay-summary`. Limits: one replay at a time,
10,000 records, 64 MiB input, 32 MiB output and a five-second budget checked between
records. The backend update is required.

### Capture Library

**Capture Library** in Payloads and **Choose input…** in Inspection open the same
library of collected samples and saved flows. Click a row to select it and edit
its name, notes or virtual folder; opening is a separate **Open in Follow** action.
**Use in Inspection** loads a sample as offline input. For a flow, explicitly select
a message first: the first message is never silently chosen. No script is executed
by choosing an input. The library also links back to live traffic.

Folders are a flat, virtual organizational layer: **All captures**, **Unfiled**,
and up to 256 user-created folders. Create/rename them in the left pane, and move
captures with the Folder field. Names and notes are searchable together with endpoint,
HTTP method/path/status, MIME and enrichment summaries. Cookie/authorization values
and payload bodies are not indexed. Renaming, moving and notes do not rewrite captured
data. Save to library offers name, folder and notes when creating a flow snapshot.
Folder, query, page, selected row and list scroll are remembered per backend in the
browser. Unsaved detail edits require confirmation before leaving.

Backend metadata is stored atomically in private `.capture-library` (maximum 4 MiB)
inside the collection root and survives backend/browser restarts. `.capture-index`
is a rebuildable lightweight summary cache (maximum 32 MiB). The first listing of old
samples may be slower: each missing summary is derived once from the sample; subsequent
queries and restarts use the index, checking file size/mtime instead of rereading
payloads. Existing flow summaries are read without their payloads. The browser only
loads payload data on Open or Use; listings contain 100 summaries per page. Indexing
is capped at 50,000 captures. Catalog limits are bounded overhead separate from the
capture payload quota; no automatic deletion of user data is performed.

Authenticated API: `GET /api/inspection/library?offset=0&q=...&folder=*` returns
items, folders and `revision`; `folder=` means Unfiled. `POST /api/inspection/library`
uses the current revision and either `operation: folder` (name, optional existing id)
or `operation: item` (key, name, notes, folder). Keys distinguish `sample:<id>` from
`flow:<id>`. Stale edits are rejected instead of overwriting another editor's work.
The legacy collections and saved-flow read endpoints remain supported. One Spider
process should own a collection directory; concurrent processes editing it are not supported.

Follow views have **Collect** above Keep all. Collection is backend state, independent
of the browser cache, and captures future callbacks (not already retained payloads).
Connection views match the exact session ID; client/service views use their source
and destination scope. This requires the updated backend, including authenticated
`GET /api/inspection/collections?offset=0` and
`GET /api/inspection/sample?id=...`.

### Synthetic PCAPNG export

Follow views offer **Synthetic** (retained application bytes over reconstructed TCP)
and **Synthetic+Decoded**. The latter currently requires complete retained HTTP/2
frames and decoded HPACK metadata for every header block. It writes literal HPACK
names/values without Huffman or dynamic-table references, and replaces available
complete gzip/deflate bodies using exact enrichment ranges. For transformed bodies,
Content-Encoding and Content-Length are removed; DATA and header blocks are reframed.
TCP sequence numbers, packet lengths and checksums are regenerated.

Missing header context, incomplete inflate coverage, unsupported PUSH_PROMISE or
non-H2 traffic produces an explicit error, not a partially rewritten download.
Use Synthetic in those cases. Original retained bytes are never modified.
Both filenames and PCAPNG section comments identify the synthetic nature of the export.

Small, fast C++ webhook observer/controller for Smithproxy. The C++ backend uses
`lmhpp` and `libmicrohttpd`; the frontend is a separate static application and
can run on another machine.

## Build

```sh
git clone --recurse-submodules https://github.com/astibal/smithproxy-spider.git
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Dependencies: C++20 compiler, CMake, `libmicrohttpd`, `libcurl`, `libnghttp2`,
`zlib`, `pkg-config`, and `nlohmann-json`.

## Run

```sh
SPIDER_SMITHPROXY_KEY='configured-api-key' ./build/smithproxy-spider \
  --bind 0.0.0.0 --port 8080 \
  --smithproxy-url https://127.0.0.1:55555 \
  --smithproxy-insecure
```

Smithproxy must have `settings.webhook.enabled=true` and
`settings.webhook.api_override=true`. Spider exchanges the configured API key
for session tokens, acquires an owned v2 webhook lease (with automatic fallback
to the legacy API), renews it every 20 seconds, and adds a process-local random
token to its callback URL.

Serve `frontend/` on the workstation, for example:

```sh
python3 -m http.server 5173 --directory frontend
```

Open <http://127.0.0.1:5173/> and enter the Helmut backend URL, for example
`http://192.0.2.10:8080`. Smithproxy API URL, API key and TLS verification can
then be configured directly in the page. The key is sent to Spider once and is
not stored by the frontend.

The initial Helmut deployment may bind to `0.0.0.0` on the isolated test link.
Do not use that setup on an untrusted network. `SPIDER_TOKEN` can protect the
browser API; the Smithproxy callback is protected separately by a random URL
suffix because the current webhook sender cannot attach an authorization
header.

For a persistent test deployment, install `deploy/smithproxy-spider.service`,
put the API key in `/etc/smithproxy-spider.env` as
`SPIDER_SMITHPROXY_KEY=...`, and adjust `ExecStart` if Smithproxy does not use
its default local API address. The supplied unit exposes Spider on all Helmut
interfaces, but keeps the Smithproxy API and callback hop on loopback.

The first milestone intentionally returns immediately: content is unchanged and
access requests are accepted. No request waits for a UI action.

**Payloads** contains flows, counters and the payload viewer. **Inspection** contains
a named local script library, editor/output and a separate ordered backend chain.
The original four Python slots are imported into the library on first use.
Drafts are retained in this browser; **Save to library** updates the saved version,
not the backend. **Export script** downloads the editor source as `.py`.
**Run on selected** sends the draft and selected payload to backend CPython and
previews its result without deploying. **Deploy saved version** validates syntax
and the optional session filter and creates a **disabled** chain item. Enable it
explicitly after testing. Updating an existing enabled item replaces its deployed
snapshot only after validation succeeds. Validation does not prove runtime correctness.
Items execute top-down, in displayed order; reorder with arrows and **Apply order**.
Closing the browser does not stop enabled backend items. JavaScript and Pyodide
browser execution have been removed. API fields include bytes, text, side,
session metadata, L7 ranges/bytes/encodings, annotations and enrichments.
Returning `None` preserves content; returning text or bytes proposes replacement.

Backend scripting requires `SPIDER_TOKEN` and Python 3 (located at build time).
Scripts require Linux x86_64/aarch64, Landlock ABI >= 3 (Linux 6.2+) and
`libseccomp.so.2`. A mandatory kernel sandbox is installed before validation or
execution; unavailable protection returns `sandbox_unavailable`, never an
unsandboxed fallback. Enabled deployments use two prewarmed sandboxed Python
workers, exclusively owned by that deployment version. Validation, ad-hoc
"Run on selected" and editor help still use fresh processes. Workers have a
sanitized environment, 256 MiB address-space limit, 2 lifetime CPU seconds, and per-call
wall-clock budgets of at most 3 seconds,
50,000 captured output characters and a 1 MiB replacement limit. At most four
workers execute concurrently; overload and execution errors leave live content
unchanged. The server retains counters and the latest 20 outputs. Script globals,
API objects and captured output are fresh per invocation; imported module/native
caches may survive inside a worker. Never use module mutation as flow state;
use the explicit state/storage APIs below instead.

Both workers initialize the sandbox and compile the deployment once, before
enable/redeploy is published. Errors, timeouts, crashes and malformed output
discard a worker immediately. Healthy workers request retirement after 256 calls,
0.5 seconds of cumulative CPU or five minutes of age. Maintenance rotates them
**one at a time**, keeping the other process serving even if it also requested
retirement. The retired process is reaped before spawning its replacement: this
does not add a third worker. The grace period is bounded by 4,096 calls (also
counted by the parent), 1.5 observed CPU seconds or ten minutes of age; the kernel
2-second CPU and 256 MiB limits remain unchanged. Hard limits and failures can
still empty the pool, because containment takes precedence over availability.
A maintenance thread replenishes missing workers;
requests wait in FIFO order at most 250 ms (and within their execution budget)
for a ready worker. A timed-out request is removed from the queue, so it cannot
block successors; newly arriving requests cannot overtake existing waiters.
Requests are **never automatically replayed**, since storage writes may already
have committed. Disable, removal, suspension and redeploy retire the old pool;
in-flight calls finish within their original deadline but cannot restore retired
instance state. Startup failure leaves the previous deployment unchanged.

The pool is not a security boundary between callbacks in the same deployment.
Different deployments/versions never share interpreters, but `api.storage` remains
explicitly shared. Up to 16 deployed scripts means up to 32 resident workers
(briefly more during a generation handover); the global four-active-call limit
remains in force. Pool ready/busy/starting/restart counters are exposed in status
and the Inspection sidebar. Prewarming trades idle memory for lower callback latency.
Status additionally exposes `cold_waits` (requests finding neither process),
`queue_wait_us` and `max_queue_wait_us` (cumulative/maximum wait for successful
worker acquisition, including the pool mutex). These distinguish empty-pool
startup stalls from ordinary execution latency; maximum wait includes warmup.
`rotations` counts planned retirement starts, `forced_recycles` counts failures
or hard limits, and `queued` reports current pool waiters.

The sandbox permits read-only Python standard-library files and read/write access
only to the dedicated shared storage directory. Network sockets (including Unix
sockets), subprocesses/threads, exec, signals to other processes, ptrace, mounts,
device ioctls and unlisted syscalls are denied. Native calls through `ctypes` are
subject to the same policy. No home/configuration files or `/proc` contents are
readable; file metadata is not hidden. Imports requiring external shared libraries
or host configuration may fail. Existing file descriptors are restricted to the
worker's request/response and stderr by the launcher.

This is defense in depth for authenticated administrator scripts, **not a
multi-tenant isolation guarantee**. Scripts can still modify shared storage and
return arbitrary traffic replacements. Use a dedicated unprivileged service user
and a dedicated storage directory (never home, a repository or system directory).
The static Jedi language service does not execute submitted scripts; it retains
its separate bounded process and is not covered by the script syscall policy.

### Script instances, storage and runtime protection

Deployment settings select a **logical instance**, not a persistent Python process:

| `instancing` | State shared by |
| --- | --- |
| `message` (default) | Nothing; each content callback starts with `{}` |
| `flow` | One connection ID, both directions; not an HTTP/2 stream |
| `endpoint`, `endpoint: destination` | Destination protocol + IP + port across connections |
| `endpoint`, `endpoint: source` | Source IP across ports and destinations |

Endpoint keys use the observed connection endpoints, not hostname groups. Session
filters and scope still determine which callbacks reach a deployment. A callback
can contain a fragment, several frames, or less than one application message.

```python
# Deploy per flow to count both directions of this connection.
api.state['callbacks'] = api.state.get('callbacks', 0) + 1
api.print(api.instance.key, api.state['callbacks'])

# Explicitly shared across deployments and backend restarts.
stats = api.storage.namespace('inspection-stats')
api.print('Total callbacks:', stats.increment('callbacks'))
return None
```

`api.state` must remain a JSON object (64 KiB per instance, 4 MiB per deployment).
It commits only after that invocation succeeds; exceptions, invalid values and
timeouts leave the previous state unchanged. This is **not** a transaction across
the whole chain. Disable, resume, redeploy, removal and backend restart discard
instance state. Flow stop removes its state; idle instances also expire. Defaults:
`max_instances: 128` (1–1024), `idle_seconds: 1800` (1–86400).

`api.storage.namespace(name)` provides `get`, `set`, `delete`, and atomic
`increment`. Values must be JSON; use `increment` rather than `get` + `set` for
concurrent counters. Each operation commits separately: storage writes survive
a later script/chain failure. **Run on selected uses the same persistent storage**,
but starts with fresh `api.state` and never changes live traffic. Use a separate
namespace for test data. Standalone `make_views` documentation examples use memory.

Storage is a private SQLite database in `SPIDER_STORAGE_DIR`, or by default a
sibling of the collection directory named `<collection-directory>-inspection-storage`.
Limits: 64 KiB/value, 4096 keys and 16 MiB logical data across all namespaces;
database pages are additionally capped. Namespaces are names, not paths. Storage
is for small shared data, not payload archives. Namespaces are not security
boundaries between scripts. Raw files inside the shared storage directory remain
accessible without API quota/transaction guarantees; other files are denied by
the sandbox. Use filesystem quotas if protection against storage exhaustion by
hostile administrator scripts is required.

Flow/endpoint deployments serialize invocations, including different instances,
to avoid lost state updates. Message-mode deployments may execute two callbacks
concurrently; completion order is not guaranteed. Separate deployments can run concurrently. At most
8 calls wait per deployment, for at most 250 ms; excess work fails open with the
original payload. The global four-worker cap still applies. Queue rejection and
storage contention do not count as script faults. Ordering is worker lock acquisition
order, not a promise of network arrival order under concurrent webhook delivery.

`timeout_ms` defaults to 1000 (50–3000); the complete chain retains its 3-second
budget. `error_limit` defaults to 3 consecutive errors/timeouts (1–100). A deployment
also suspends after 5 consecutive runs consume at least 80% of its full configured
wall-clock budget. This measures latency, not CPU utilization. A budget shortened by
earlier chain steps does not count as that script's slowness. A suspended deployment
stays disabled until explicitly resumed; resume starts with fresh state.

Inspection shows retained instances, state bytes, waiting/executing calls, rejected
work, duration and the suspension reason. The backend retains the last 20 suspension
notifications, surfaced in Activity while the GUI is open; no email delivery.
The historical single-script API keeps its legacy behavior until converted to a
chain deployment. Use chain deployments for instancing and automatic suspension.

Headless clients use authenticated JSON endpoints (`X-Spider-Token`):

- `GET /api/inspection`: deployed source, state, counters, recent output and traffic rules.
- `GET /api/inspection/schema`: generated typed Python API reference for this backend build.
- `POST /api/inspection/run`: `{ "script": "return api.bytes.upper()", "event": { "details": { "info": { "content": "YWJj" } } } }`.
- `POST /api/inspection`: `{ "script": "return api.bytes.upper()", "enabled": true, "scope": "all" }`.
- `POST /api/inspection/rules`: same `rules` and `bypass_all` schema as the traffic-rules WebSocket message.

Chain mutations use `POST /api/inspection` with the current `revision` from GET
and an `operation`. Stale revisions are rejected, rather than overwriting another
editor's changes. Operations:

- `deploy`: `name`, `script`, `scope` (`rules` or `all`), optional `filter`
  (SessionFilter expression, e.g. `dst port 443`), optional existing deployment `id`;
  `instancing`, `endpoint`, `timeout_ms`, `error_limit`, `max_instances`, `idle_seconds`
  as described above. Omitted runtime settings use defaults, including on redeploy.
- `enable`: `id`, boolean `enabled`. Enabling validates syntax again without
  executing user code. New deployments are always disabled.
- `reorder`: `ids`, every deployment ID exactly once in the desired order.
- `remove`: `id`, removes only the deployed snapshot, not a local library script.

At most 16 items can be deployed. Each message uses a consistent chain snapshot;
changes affect subsequent messages. Each item gets the previous item's replacement.
`None` means continue unchanged, not stop the chain. After a replacement, original
L7 offsets/annotations and parsed enrichments are cleared for subsequent items
(re-enrichment of rewritten content is not implemented yet). The entire chain
has a 3-second worker wall-time budget. An error stops the chain and passes the
original payload, not partially rewritten content. Per-item counters, last-run
timestamps and version numbers are returned in `chain`; test runs count only in
the global counters. Legacy single-script configuration is retained until the
first chain operation, which preserves the legacy deployment as a chain item.

Scope `rules` executes only INSPECT matches; `all` executes all content except
PASS, FORGET, bypassed and auto-accepted callbacks. Deployment and rules currently
live in server memory: after a backend restart, redeploy through these endpoints.
They survive browser disconnects. Test runs never apply replacements to traffic.

### Heavy traffic guard

The visible **Ignore heavy traffic** switch in the left sidebar is opt-in and
runs on the backend, independently of the browser. Defaults: five seconds from
the first content callback are always admitted; afterwards more than **200
callbacks/s OR 1 MiB/s**, sustained for three seconds, stops capture for that
connection (both directions combined). Grace cannot be configured below five
seconds. Counters use ten 100 ms buckets (approximately a one-second window),
and are evaluated on arrival, not by CPU polling. Brief bursts do not suffice.

The cutoff sends Smithproxy `action: not-interested` before payload decoding,
enrichment, script execution or collection. It does **not** drop network data.
It still costs HTTP reception and envelope parsing to receive the triggering
callback; this is not a global CPU limit. Smithproxy must support not-interested.
An ordinary weight icon marks the incomplete flow and its saved snapshot, with
observed rates, configured limits and cutoff time in the tooltip. Existing data
is retained. Disabling protection does not resume an already declined capture.

Collection/INSPECT traffic is exempt by default. Conservatively, any enabled
backend script exempts all connections; **Also cut Collection / script traffic**
explicitly opts into interrupting these workflows. Limits are configurable in
the switch's expandable panel. Authenticated headless clients can POST partial
settings to `/api/inspection/heavy-traffic`; GET `/api/inspection` includes
`heavy_traffic`. Fields: `enabled`, `grace_seconds` (5–300),
`messages_per_second`, `bytes_per_second` (1–1073741824), `sustain_seconds`
(1–60), `include_managed`. Settings are in memory until backend restart.
Changing settings restarts observation for sessions not yet cut off. Tracking
is bounded to 65536 connections, with ten-minute idle expiry and stop cleanup;
at capacity new connections are not tracked. This is per-session protection,
not an aggregate limit on many small concurrent connections.

### Collection capture

Right-click an endpoint and use **Toggle Collection**. The neutral `▣` badge is
independent of the endpoint's Focus/Inspect color. Collection is a backend rule
(`mode: "collect"`) and continues without a browser. Address rules and Sift
labels/globs are supported. Hostname groups/globs are matched against the backend's
observed hostname-to-address mappings, including later observations; no historical
traffic is recovered. CIDR collection is not exposed yet.

Matching content gets the same available enrichment as focused/inspected content.
The backend writes one self-contained `spider-sample-v1` JSON per matching rule
**before any script modifications**, with base64 original content, the full current
event metadata, enrichment metadata/binary content, capture time, collection identity
and available bounded session history. It is a snapshot, not a guaranteed complete
connection capture: missing earlier protocol state is not fabricated.

Collection does not enable scripts or manual interception. It also runs for
passed/bypassed traffic; a matching FORGET rule does not suppress future callbacks
while Collection needs them. Already-forgotten connections cannot be retroactively
re-enabled. Rules are in memory until restart; sample files persist.

`SPIDER_COLLECTION_DIR` sets the destination (default `collections` relative to the
backend working directory). The supplied systemd service uses
`/var/lib/smithproxy-spider/collections`. Directories have a readable sanitized
endpoint prefix and stable hash; wildcard/path characters never become paths.
Files are private (`0600`), directories owner-only, and completed samples appear
by rename after flushing. `SPIDER_COLLECTION_MAX_BYTES` sets a **total store budget**
(default 1 GiB, existing files counted at startup). Reaching it stops saving new
samples, not traffic. No automatic deletion occurs. Inspection shows saved count,
bytes, configured path and write errors; counters are per backend lifetime.
One backend process should own a collection directory.

Snapshots can contain credentials and personal data: restrict access and choose
retention deliberately. This first version writes synchronously; background queues,
collection browsing/indexing and replay into the editor are deferred.

The **API Reference** tab loads the connected backend's generated schema. Search
types and fields, expand entries for availability, descriptions and examples,
and insert examples at the editor cursor. Typing `api.` or pressing Ctrl+Space
opens basic member suggestions; arrows select, Tab inserts, Escape dismisses.
Hover a suggestion for its description. This is an initial integration, not a
Python language server or full IDE.

The typed preview exposes `api.message.bytes/size`,
`api.metadata.session_id/side/payload_layer` and
`api.http1.available/method/target/status/headers`. The HTTP/1 view consumes
`http1.parse-head` enrichment: no complete head means `available == False`,
nullable fields are `None`, and headers are empty. A complete head does not imply
a complete body; only the first decoded head is exposed in this initial slice.
Header order and duplicate names are preserved. Views are read-only snapshots.

Definitions, types, descriptions, availability and examples live together in
`src/inspection_api.py` and `src/inspection_h2.py`. CMake embeds those definitions into the Python worker and
generates its schema with `tools/generate-inspection-schema.py`. Editing this file
triggers regeneration on the next build. No separate browser field list is needed.

### HTTP/2 REWRITE (API 0.5)

`api.message.parts` contains annotated H2 frames, complete header blocks (including
local CONTINUATION frames), and Opaque gaps, in source order. Original read-only
`api.http2.frames/header_blocks` remain available. Edits are drafts: only returning
the committed bytes publishes a replacement.

```python
for part in api.message.parts:
    if part.is_a(PartType.Http2.Header) and part.headers is not None:
        part.headers.set_header(b"x-spider", b"rewrite")
    elif part.type == PartType.Http2.Data:
        if part.content.complete is True:
            part.set_bytes(b"new body")
return api.message.commit()
```

Names and values are **bytes**, not escaped display strings. `headers.entries`
preserves duplicates and exposes `indexing` (`without`, `incremental`, `never`,
`indexed`, `table-size`), `index`, and `name_index`. Constructors include
`api.http2.Header(...)`, `HeaderIndex(62)`, `TableSize(4096)`, `Frame(...)` and
`Ping()`; append new frames to `api.message.parts`. Indexed/Huffman values need
backend decode metadata to expose logical bytes; unresolved values are `None`,
but their original instructions remain preserved and explicit index edits work.

`get_bytes()` reads the representation: unpadded DATA, HPACK bytes for a header
block, or control/Opaque bytes. DATA is **not inflated**. Do not mix raw HPACK
replacement with logical header edits. `part.commit()` previews a frame/block;
`message.commit()` also recalculates existing Content-Length for changed, fully
known local content. `complete` means frame/block completeness;
`content.complete` is True/False/None for whole locally bounded content. Incomplete
parts cannot be rebuilt until continued through a hold. Gzip rewriting remains
deferred. `commit(False)` explicitly disables Content-Length repair.

Default output frame limit is 16384; `part.max_frame_size` can use a known peer
limit. This mode does not discover or maintain output peer settings/HPACK state.
It also does not compensate connection/stream flow-control windows after DATA
size changes. It permits explicit index/table changes and nonsensical semantic values: a valid
HPACK encoding can still fail against the receiver's dynamic table. **No later
messages are silently translated.** TRANSLATE and strict control policy are future
work. Failed assembly raises `CommitException`, leaves original bytes untouched,
and allows fixing the draft and retrying. The script must return the result.

### Live Parts hold / need-more

Deploy with **flow** instancing, as the **last enabled script** in the chain.
Hold is not supported in preview or message/endpoint instances yet.

```python
for part in api.message.parts:
    if part.type == PartType.Http1.Body:
        if not part.content.complete:
            api.message.parts.hold_from(api.message.parts[0])
            return api.message.commit()
        part.set_bytes(b"a different body")
return api.message.commit()
```

This first H1 slice requires a complete annotated header with one Content-Length,
without compression/chunked framing. Subsequent body bytes need no new header
annotations. Header edits use `part.http1.set_header(...)`; retain the header too
if a later body edit will change Content-Length. Trailing unrecognized data stays
Opaque, not silently interpreted as another request.

`hold_from(part)` retains that part and the entire following suffix, including
meaning, lazy data and pending edits. Returning `message.commit()` emits only the
prefix: empty prefix becomes webhook `need-more`, otherwise `replace`. The next
callback receives held Parts before new Parts. H2 frames with a complete nine-byte
header and partial payload/header blocks can be continued; the live enrichment
engine sees each incoming byte only once. `api.bytes` and `message.bytes/size`
still describe the current callback, while `message.parts` includes resumed data.

Hold checkpoints live in the backend, isolated by deployment/version, connection
and direction; they survive Python worker replacement, not backend restart. They
are separate from `api.state`, with a 1 MiB serialized checkpoint limit and a
4 MiB deployment state+hold quota. Return an explicit result after resuming:
`None` is an error. Event inspection metadata reports `holding`, `released` or
`abandoned`; checkpoint contents are not copied into status/event output.

**Known limitation, deliberately deferred:** failure handling remains fail-open.
A failed webhook, script error, stop/expiry, disable/redeploy or backend restart
can lose held data while later bytes continue. Strict ordering/failure protection
is tracked in `docs/TODO.md`, for HOLD/REWRITE as well as future TRANSLATE.

Live edit is opt-in. When enabled, each new content callback waits up to ten
seconds for `accept`, `accept-session`, `replace`, or `discard`. Accept-session
passes the current callback and bypasses later callbacks belonging to that
session. Disabling live edit, losing the last WebSocket client, or reaching the
deadline resolves pending callbacks unchanged (fail-open).

The sidebar groups active sessions into observed source and destination
endpoints. Traffic Endpoints retains observations for a configurable TTL from
10 seconds to one hour (ten minutes by default); addresses fade near expiry.
Each endpoint column can show its top 10, top 20, or all observed values.
Right-clicking any observed IP adds an ordered traffic rule. `PASS` still sends
callbacks to Spider and keeps them in Events, but excludes their content from
Payloads and Flows. `FORGET` accepts the current payload and permanently
declines future content callbacks for every matching connection. `FOCUS` makes
unmatched traffic implicit PASS while
at least one focus rule exists. `INSPECT` is non-exclusive and always runs the
deployed backend script when enabled, even when Live edit is disabled; its result
is returned as unchanged or replace. First match wins. Rules are owned by the
backend; the browser loads them on reconnect and shows live match counters.

Focused and inspected HTTP traffic can carry chained SXBN enrichment envelopes.
Spider parses complete HTTP/1 message heads and maintains independent HPACK
decoder state for both directions of HTTP/2 connections. H2 frame headers and
header blocks may span callbacks; incomplete pre-focus HPACK context fails
closed instead of presenting uncertain headers as decoded data. Annotated gzip
and deflate bodies are inflated as independent HTTP/1 directions or HTTP/2
streams and delivered as binary enrichment envelopes. Decompressed output is
bounded per event to protect the backend from compression bombs.

The active-session tree shows only session keys at its leaves. Its draggable
`src`, `dst`, and `dport` controls enable grouping dimensions and define their
nested sorting priority. All groups start folded; manually opened groups remain open
across the live session refreshes.

## API

```text
GET  /                     service identity
GET  /api/health           unprotected liveness endpoint
GET  /api/ready            Smithproxy readiness (200/503)
GET  /api/status           connection and callback counters
GET  /api/diagnostics      callback, store, replay and WebSocket data-path counters
POST /api/config/smithproxy runtime Smithproxy URL and credentials
GET  /api/sessions         active sessions
GET  /api/session-history  active and recently completed sessions
GET  /api/session?id=ID    complete retained session detail
DELETE /api/session-history remove completed sessions (active sessions remain)
GET  /api/events?after=N   bounded event history
GET  /api/events/ws        authenticated WebSocket event stream and decisions
POST /webhook/<token>      Smithproxy webhook receiver
```

The actual callback path includes a random suffix and is registered
automatically. The frontend never receives the Smithproxy API key.

Session history retains up to 1000 completed sessions plus all active sessions.
Each retained session keeps its latest summary and up to 200 session events.

## Local chain test

Terminal 1:

```sh
python3 tests/fake_smithproxy.py
```

Terminal 2:

```sh
SPIDER_SMITHPROXY_KEY=integration-key ./build/smithproxy-spider \
  --port 18080 --smithproxy-url http://127.0.0.1:15555 \
  --callback-url http://127.0.0.1:18080/webhook
```

Then `curl http://127.0.0.1:18080/api/events` shows authorization, webhook
lease renewal, and a callback `ping` from `fake-smithproxy`.

## Helmut test runners

Initialize a fresh, self-contained workspace as root. The optional second
argument selects the Smithproxy branch or ref and defaults to `api-ng`:

```sh
tools/init-test-workspace.sh ~/smithproxy-spider-test api-ng
```

The initializer refuses to modify a non-empty target directory. It clones the
Spider repository and its submodules, fetches the selected Smithproxy ref, and
creates the build and state directories. It does not build or start services.

As root on Helmut, start an isolated Smithproxy built from the selected ref,
then start Spider and its static test UI:

```sh
tools/run-test-smithproxy.sh start
tools/run-test-spider.sh start
```

The first runner keeps all generated test artifacts under one explicit root:

```text
~/smithproxy-spider-test/
├── src/
│   ├── smithproxy-spider/   Spider checkout
│   └── smithproxy/          managed Smithproxy checkout
├── build/
│   ├── spider/              Spider build
│   └── smithproxy/          Smithproxy build
└── state/                   configuration, certificates, tokens, PIDs and logs
```

It creates network namespace `sxp-test` and adds outbound NAT only for
`10.254.77.2`. It generates fresh API and frontend keys under the `state/`
directory on each start. The
test veth keeps the normal Ethernet MTU. Any upstream PMTU or MSS handling
belongs on the network gateway, outside the test runner.

Default test endpoints:

```text
Smithproxy API  https://10.254.77.2:55580
HTTP CONNECT    http://10.254.77.2:33128
Smithproxy CLI  10.254.77.2:55000
Spider backend  http://<helmut>:18080
Spider UI       http://<helmut>:15173
Test CA          http://<helmut>:15173/test-ca.pem
```

The Smithproxy runner can update its managed checkout without building or
restarting it. The selected ref is remembered for later `start` commands:

```sh
tools/run-test-smithproxy.sh fetch api-ng
tools/run-test-smithproxy.sh start
```

Run `fetch` without a ref to update the previously selected ref; a fresh state
defaults to `master`. It refuses to overwrite tracked local changes. Both
scripts also accept `status` and `stop`. Stop Spider before removing its
Smithproxy namespace:

```sh
tools/run-test-spider.sh stop
tools/run-test-smithproxy.sh stop
```

`start` preserves the generated CA, API/frontend tokens and `smithproxy.cfg`,
including configuration persisted with `save config`. Use the explicit reset
command only when a fresh test identity and configuration are wanted:

```sh
tools/run-test-smithproxy.sh reset
```

### Inspection editor

The Inspection workspace uses a locally bundled CodeMirror 6 editor: Python
highlighting, line numbers, folding, undo/redo, search and four-space indentation.
`Ctrl+Space` opens API completion; Enter or Tab accepts a suggestion.
Completion uses the backend's `/api/inspection/schema`, including indexed header
access (`api.http1.headers[0].`). It is not a Python language server: inferred
local variables and legacy helpers absent from that schema are not completed.
Python execution and deployment validation remain on the backend.

The checked-in `frontend/vendor/inspection-editor.js` needs no CDN or npm at
runtime. To rebuild after editing `tools/editor/editor.js`:

```sh
cd tools/editor
npm ci
npm run build
```

Commit the bundle and generated license notices together with source changes.

### Frontend freshness in the lab

`tools/run-test-spider.sh` serves the UI with `tools/serve-frontend.py`.
The server fingerprints the actual HTML/JS/CSS (including dirty changes), adds
that version to asset URLs and disables HTTP caching. The header shows the loaded
UI fingerprint, separate from the backend's event revision.
Open pages check for updates every 30 seconds and on returning to the tab.
Updates require an explicit reload confirmation because payloads are memory-only.

For a standalone frontend:

```sh
python3 tools/serve-frontend.py 18763 --directory frontend
```

An existing `python3 -m http.server` process must be replaced once; copying new
files alone does not change its cache policy or enable the version endpoint.
Other static hosts must supply equivalent asset stamping/version metadata and
cache headers; the UI reports `UI development` when served without stamping.

### Pre-merge verification

The normal CTest suite includes the kernel-sandbox negative tests and frontend
cache/versioning tests. Sandbox checks deliberately fail (not skip) on a host
without the required protection. Browser tests use a separate temporary profile,
an ephemeral local frontend port and mocked backend responses; they never attach
to your open browser or deploy scripts to a real backend.

```sh
cmake --build build -j4
ctest --test-dir build --output-on-failure -j2 --repeat until-fail:3 \
  --output-junit premerge-results.xml

# Node >= 20 + Playwright; NODE_PATH and CHROMIUM_PATH may select local installs.
python3 tests/browser_smoke.py --repeat 3

cmake -S . -B cmake-build-ubsan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=undefined -fno-sanitize-recover=all -g1' \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined
cmake --build cmake-build-ubsan -j3
ctest --test-dir cmake-build-ubsan --output-on-failure -j2 \
  --output-junit premerge-ubsan-results.xml
```

The sandbox follows the Linux [Landlock ABI](https://docs.kernel.org/userspace-api/landlock.html)
and libseccomp's default-deny syscall policy. It is not an independent security
audit or a guarantee against kernel/interpreter vulnerabilities. The current
local verification platform is Linux x86_64; aarch64 requires separate CI coverage.

Pre-merge verification on 2026-10-24 (`fc-api`, based on `d9b4d02` with sandbox changes):

- normal build: all 14 CTest suites passed three consecutive times (42 executions);
- UBSan Debug build: 14/14 suites passed, no undefined-behavior diagnostics;
- isolated Chromium GUI smoke: 3/3 consecutive runs passed, including sandbox
  indication, library/deployment workflow, payload modes, toolbar stability and
  idle-render suppression;
- ten sandbox test methods cover allowed payload/storage operations, denied
  files/network/processes/signals, native `ctypes` calls, symlink escapes,
  unsupported protection, limits and recovery. The real HTTP API also rejects
  attempted sandbox opt-out and successfully executes the next normal request;
- local JUnit reports: `build/premerge-results.xml` and
  `cmake-build-ubsan/premerge-ubsan-results.xml` (generated, not committed);
- indicative worker startup/run measurement, ten warmed trivial invocations:
  median 94.4 ms before versus 115.9 ms with containment. This is not a throughput
  benchmark or latency guarantee; invocation deadlines include startup overhead.

The GUI test settles Playwright's automatic scroll before measuring button
positions; exact x/y equality checks remain enabled. No browser-test assertion
was relaxed to hide a layout change. Python coverage percentages were not
remeasured in this run (the optional coverage package was unavailable).

Persistent deployment pool verification (same date, after the sandbox baseline):

- all 15 CTest suites passed three consecutive times (45 executions), and
  all 15 passed in the UBSan Debug build;
- Chromium GUI smoke passed three consecutive times;
- pool tests exercise two simultaneous workers, fresh invocation globals,
  deployment isolation, queue saturation, timeout/crash/protocol-error recovery,
  sandbox rejection, bounded worker recycling and no replay after storage writes;
- a warmed pool processed 100 trivial callbacks in 16.6 ms total (about
  0.17 ms each). This measures local pool IPC and execution, not end-to-end
  webhook latency. Startup/containment cost now belongs to deployment warmup;
- generated reports: `build/pool-results.xml` and
  `cmake-build-ubsan/pool-ubsan-results.xml`.

### Webhook latency / load harness

Run against a local binary, **not** an existing deployment:

```sh
python3 tests/webhook_benchmark.py build/smithproxy-spider \
  --requests 1000 --warmup 40 --sizes 64 4096 65536 \
  --concurrency 1 2 4 --output build/webhook-benchmark.json
```

Each matrix entry starts a fresh loopback-only Spider with temporary collection
and script storage and a fake Smithproxy used only for callback registration.
The timed path is the actual HTTP webhook handler, including JSON/base64,
enrichment, inspection, response transport and client response validation.
The baseline has no script; the script scenario deploys and enables a message-mode
`return api.bytes.upper()` script with the two-worker pool. Startup, deployment
and warmup are excluded. Each producer has its own HTTP keep-alive connection
(the first measured request includes connection establishment).

The table reports p50/p95/p99 milliseconds, requests/s and response errors. JSON
also includes successful-only percentiles/throughput, backend run/error/rejection
deltas, worker restarts and suspension state. Every replacement is checked against
the expected bytes: fail-open/unchanged is **not** counted as script success.
Errors or backend rejections cause a nonzero exit; overload results are still
written. The report includes platform, timestamp and binary SHA-256. The output
path is overwritten as each case finishes, preserving completed cases if a later
case fails.

For an intentional saturation check (expect nonzero exit):

```sh
python3 tests/webhook_benchmark.py build/smithproxy-spider \
  --requests 24 --warmup 8 --sizes 64 --concurrency 8 \
  --script-delay-ms 300 --output build/webhook-benchmark-overload.json
```

This is a **closed-loop** harness: each producer waits for its response before
sending another request. It does not model a fixed arrival rate or account for
coordinated omission, and Python client CPU can limit measured throughput.
There is no TLS, real Smithproxy forwarding or browser subscriber in this test.
Run it alone on an otherwise idle host; the default 200 requests per case are
a quick comparison, not a statistically stable tail-latency or capacity claim.
Benchmark-accounting unit tests are registered as `webhook_benchmark_tests`;
the load benchmark itself is intentionally outside ordinary CTest runs.

Local verification on 2026-10-24: 18 cases × 1,000 measured requests, plus
40 warmup requests per case, completed without response errors, backend errors
or capacity rejections. For one producer, median baseline / scripted latencies
were 0.301 / 0.561 ms (64 B), 0.454 / 0.911 ms (4 KiB) and
2.180 / 6.037 ms (64 KiB). The scripted cases recorded 3–4 completed worker
restarts each, and maximum latencies reached 93–128 ms; 64 B with four producers
had p99 30.612 ms. Recycling is a candidate explanation for the tail spikes,
not established causal attribution from this aggregate report. Do not interpret
the sub-millisecond medians as a worst-case latency guarantee.

The intentional overload check returned exit status 1: 12 of 24 scripted requests
returned unchanged, and backend rejection delta was 12. The accounting unit tests
also passed through CTest. Full local reports are in
`build/webhook-benchmark.json` and `build/webhook-benchmark-overload.json`.

#### Tail-latency follow-up: rolling retirement and FIFO

Instrumentation confirmed the original empty-pool stall: with 64 B and four
producers, a pre-fix run recorded 10 requests entering an empty pool and a maximum
pool wait of 95.7 ms, matching the 96.9 ms HTTP maximum. Both processes had reached
their retirement threshold together. Rolling retirement removes that synchronized
outage without adding workers. A subsequent 64 KiB/four-producer repeat still
showed an 87 ms queue wait without entering an empty pool; FIFO admission removes
the opportunity for new callers to repeatedly overtake waiting callers while
only one worker is available.

The final 18-case × 1,000-request matrix passed with zero response/backend errors,
capacity rejections, cold waits or forced recycles. Planned worker rotations
remained active. Selected local results (milliseconds, not latency guarantees):

| Script case | Before p99 / max | Final p99 / max |
| --- | --- | --- |
| 64 B, 1 producer | 1.094 / 96.932 | 0.787 / 2.909 |
| 64 B, 4 producers | 31.910 / 96.886 | 2.025 / 3.404 |
| 64 KiB, 4 producers, rolling-only vs FIFO | 25.597 / 93.349 | 14.737 / 15.772 |

These are separate local runs, so scheduling and client load still contribute
to variation. The large-payload row isolates the later FIFO follow-up rather than
using the original pre-rolling baseline. Reports:
`build/webhook-before-rotation.json`, `build/webhook-rolling-large-repeat.json`,
and `build/webhook-final-rotation.json`. Regression tests cover healthy sustained
4-producer rotation (4,000 callbacks), FIFO entry order, queue timeout removal,
failure recovery and retirement after sustained rotation.

Final regression verification: all 16 CTest suites passed three consecutive runs
(48 executions); UBSan passed 16/16. Generated reports:
`build/rolling-pool-results.xml` and
`cmake-build-ubsan/rolling-pool-ubsan-results.xml`.
