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

## API

```text
GET  /                     service identity
GET  /api/health           unprotected liveness endpoint
GET  /api/ready            Smithproxy readiness (200/503)
GET  /api/status           connection and callback counters
POST /api/config/smithproxy runtime Smithproxy URL and credentials
GET  /api/sessions         current sessions
GET  /api/events?after=N   bounded event history
POST /webhook/<token>      Smithproxy webhook receiver
```

The actual callback path includes a random suffix and is registered
automatically. The frontend never receives the Smithproxy API key.

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
