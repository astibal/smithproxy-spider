# Smithproxy Spider

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

The Inspection editor keeps four local Python drafts. **Run on selected** sends
the draft and selected payload to backend CPython and previews its result.
**Deploy to backend** publishes a separate active snapshot; editing a draft does
not change the deployed script. **Stop backend** disables automatic execution.
Closing the browser does not stop a deployed script. JavaScript and Pyodide
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
runtime version does not retain Python globals between invocations.

Headless clients use authenticated JSON endpoints (`X-Spider-Token`):

- `GET /api/inspection`: deployed source, state, counters, recent output and traffic rules.
- `GET /api/inspection/schema`: generated typed Python API reference for this backend build.
- `POST /api/inspection/run`: `{ "script": "return api.bytes.upper()", "event": { "details": { "info": { "content": "YWJj" } } } }`.
- `POST /api/inspection`: `{ "script": "return api.bytes.upper()", "enabled": true, "scope": "all" }`.
- `POST /api/inspection/rules`: same `rules` and `bypass_all` schema as the traffic-rules WebSocket message.

Scope `rules` executes only INSPECT matches; `all` executes all content except
PASS, FORGET, bypassed and auto-accepted callbacks. Deployment and rules currently
live in server memory: after a backend restart, redeploy through these endpoints.
They survive browser disconnects. Test runs never apply replacements to traffic.

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
