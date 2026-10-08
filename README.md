# Smithproxy Spider

Small, fast C++ webhook observer/controller for Smithproxy. It uses `lmhpp` and
`libmicrohttpd`, keeps bounded in-memory state, and serves its browser UI from
the same binary.

## Build

```sh
git clone --recurse-submodules https://github.com/astibal/smithproxy-spider.git
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Dependencies: C++20 compiler, CMake, `libmicrohttpd`, `pkg-config`, and
`nlohmann-json`.

## Run

```sh
./build/smithproxy-spider --bind 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080/> and configure Smithproxy to POST webhooks to
`http://127.0.0.1:8080/webhook`.

Keep this initial version bound to loopback. `SPIDER_TOKEN` enables an
`X-Spider-Token` check, but current Smithproxy webhook requests cannot attach
that header. Remote deployment therefore needs either a trusted tunnel/reverse
proxy or the planned authenticated registration protocol; secrets are
deliberately not accepted in URL paths.

The first milestone intentionally returns immediately: content is unchanged and
access requests are accepted. No request waits for a UI action.

## API

```text
GET  /                     embedded UI
GET  /api/health           unprotected liveness endpoint
GET  /api/sessions         current sessions
GET  /api/events?after=N   bounded event history
POST /webhook              Smithproxy webhook receiver
```
