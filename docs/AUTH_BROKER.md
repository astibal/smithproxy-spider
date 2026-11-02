# Host authentication broker client

Spider can use the external authentication daemon introduced by Smithproxy
`new-AAA`, commit `f1e93750`. Both clients speak the same small `/v1/pap` contract;
Spider does not link PAM, copy the user database or ask Smithproxy to verify a
password on its behalf.

```text
Smithproxy --comm-auth PATH ----+
                               +-- Unix HTTP /v1/pap --> broker --> PAM + group
Spider host --auth-socket PATH -+
```

## Current scope

`AuthBrokerClient` is a reusable C++ host service, configured once at startup and
owned by `ServerConfig`. It can be called by a future producer/decision handler.
A diagnostic invocation in the real Spider executable exercises this same
client without starting the HTTP server, webhook manager or script workers:

```sh
smithproxy-spider --auth-socket /run/smithproxy-auth/auth.sock --auth-check USERNAME
```

Supply one password line on standard input through a protected pipe. The command
does not implement a hidden terminal prompt. Passwords are never command-line
arguments and results print only `accepted`, `rejected` or `unavailable`.
Exit status is 0 for accepted, 1 for rejected/unavailable, and 2 for invalid
configuration or oversized diagnostic input.

Normal server startup accepts `--auth-socket PATH` without `--auth-check`. An
omitted option leaves the service unconfigured; an explicitly empty or relative
path is an error. The daemon need not be running when Spider starts. No default
socket search, PAM configuration, socket ownership change or service launch is
performed. Spider needs permission to connect to the configured socket; the
current daemon's owner-only socket requires the same effective UID.

This is **not yet live addon proxy authorization**. The existing dormant
`socks5_auth` and HTTP CONNECT adapters have not been connected to a Smithproxy
producer. There is no new generic Spider-to-Smithproxy command channel. A later
change must specify the producer event, connection/exchange ownership, callback
result and failure handling before applying a decision to a waiting connection.
The current worker sandbox still prohibits creating/connecting sockets; neither
the broker descriptor nor its network capability is handed to addon code.

## Transport and failure behavior

Each verification creates its own connection to the configured Unix socket.
This permits recovery after a daemon restart on the next request, without a
background reconnect loop or retries of an already submitted password. No
acceptance or rejection is cached. The immutable client can be shared by host
callers; each call owns its curl handle and response buffer.

The request remains:

```json
{"version":1,"username":"alice","password":"supplied-by-client"}
```

The client distinguishes accepted, rejected and unavailable. Only a valid HTTP
200/version 1 accepted response returns an identity and group list. An invalid
or oversized reply, unsupported decision/version, HTTP error, redirect, missing
socket or timeout returns unavailable with no identity/groups. Environment HTTP
proxies are disabled; configuring the Unix transport must succeed. There is no
TCP or internal authentication fallback.

Limits follow the daemon: username 255 bytes, password 1024 bytes, request body
4096 bytes and response body 16384 bytes. Credentials must be nonempty, NUL-free
UTF-8. Accepted identity is bounded to 512 bytes and groups to 64 entries of at
most 255 bytes each. Invalid credentials are rejected locally. Unknown extra
response fields are tolerated for additive extensions.

Verification is synchronous, with a 1500 ms total deadline by default. A timeout
does not cancel a PAM operation already running in the daemon. Any future live
callback integration must account for this blocking behavior and fail closed;
a transport test alone does not prove enforcement on proxy traffic.

## Tests

`auth_broker_tests` uses real Unix HTTP responders and one persistent client to
check connect-on-demand, restart recovery, absence of cached acceptance, request
framing, malformed/oversized replies, deadlines and environment proxy isolation.
`auth_broker_cli_tests` checks the real Spider executable and diagnostics.

To enable the cross-project `auth_broker_pam_tests` gate, configure Spider with
both paths from a build of Smithproxy `new-AAA`:

```sh
cmake -S . -B build \
  -DSPIDER_AUTH_BROKER_EXECUTABLE=/path/to/keyway/build/smithproxy-keyway \
  -DSPIDER_AUTH_PAM_TEST_MODULE=/path/to/keyway/build/keyway_test_pam.so
cmake --build build -j2
ctest --test-dir build -R '^auth_broker' --output-on-failure
```

The PAM gate uses a temporary PAM service and the native test-only module. It
checks password verification, canonical identity, allowed group, account denial,
daemon loss and restart without changing system accounts or `/etc/pam.d`.
The fixed fixture password is not a production backend. A normal build does not
require a Smithproxy checkout and never silently reports this optional gate as
run when the two paths are absent.

## Recorded validation

On 2026-11-01 the isolated Rhino Debug build passed all 115 configured CTests,
including `auth_broker_tests`, `auth_broker_pam_tests`, `auth_broker_cli_tests`,
clean-room checks and the existing worker/sandbox regressions. The PAM daemon
and test module were built from unchanged Smithproxy `new-AAA` (`f1e93750`).
Local focused transport and real-PAM suites also passed. No live service was
reconfigured or deployed. This evidence covers the host client and diagnostic,
not the still-open addon-to-proxy decision path.

The daemon now lives in [Smithproxy Keyway](https://github.com/astibal/smithproxy-keyway).
Its PAM backend requires explicit `pam.enabled = true`; no system service or
PAM policy is installed automatically. Smithproxy retains only the broker client
and proxy protocol integration.
