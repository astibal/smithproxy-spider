# Smithproxy Spider

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
Scripts are trusted administrator code with the service user's OS permissions,
not sandboxed untrusted code. Each invocation runs in a fresh process with a
sanitized environment, 256 MiB address-space limit, 2 CPU seconds, 3 wall seconds,
50,000 captured output characters and a 1 MiB replacement limit. At most four
workers execute concurrently; overload and execution errors leave live content
unchanged. The server retains counters and the latest 20 outputs. This first
runtime does not retain Python globals between invocations; use the explicit
state/storage APIs below instead.

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
is for small shared data, not payload archives. Scripts remain trusted code:
namespaces and process resource limits are not security isolation. Ordinary files
are still accessible with the service user's permissions, without these API guarantees.

Each deployment serializes invocations, including different endpoint/flow instances,
to avoid lost state updates. Separate deployments can run concurrently. At most
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
`src/inspection_api.py`. CMake embeds those definitions into the Python worker and
generates its schema with `tools/generate-inspection-schema.py`. Editing this file
triggers regeneration on the next build. No separate browser field list is needed.

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
