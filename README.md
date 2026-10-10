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

Dependencies: C++20 compiler, CMake, `libmicrohttpd`, `libcurl`, `pkg-config`,
and `nlohmann-json`.

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

The browser UI includes a Payload workbench. It retains the latest 100
`connection-content` callbacks in browser memory, preserves their base64 data as
bytes, and offers four JavaScript slots stored in local storage. Scripts receive
an `api` object with `bytes`, decoded `text`, direction, and session metadata.
Returning a string or `Uint8Array` creates a replacement preview; returning
`undefined` keeps the payload unchanged. Each run uses a fresh Web Worker and is
terminated after two seconds. This first workbench is deliberately offline: its
preview is not sent back to an already completed callback.

## API

```text
GET  /                     service identity
GET  /api/health           unprotected liveness endpoint
GET  /api/ready            Smithproxy readiness (200/503)
GET  /api/status           connection and callback counters
POST /api/config/smithproxy runtime Smithproxy URL and credentials
GET  /api/sessions         active sessions
GET  /api/session-history  active and recently completed sessions
GET  /api/session?id=ID    complete retained session detail
DELETE /api/session-history remove completed sessions (active sessions remain)
GET  /api/events?after=N   bounded event history
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
