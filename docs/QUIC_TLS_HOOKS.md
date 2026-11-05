# Native QUIC handshake hooks

The initial native bridge covers TCP-independent QUIC parent sessions. Enable
`quic_start_server: true` on a content deployment using the mitmproxy script API.
This reserves the parent setup, `quic_start_server`, and TLS established/failed
observations for both sides, including dynamically registered addon callbacks.
Deployments without this option retain their existing stream-only behavior.

## Supported controls

`quic_start_server` receives `QuicTlsData` with a populated `QuicTlsSettings`.
An addon can change `data.conn.sni`, the single offered ALPN protocol, and TLS 1.3
cipher suites. Spider translates cipher wire identifiers to OpenSSL names.
An empty cipher list remains empty; native OpenSSL decides whether it is valid.
Set `data.conn.error` to veto the forwarding handshake before socket creation.
Certificate verification continues to use the original native identity.

Native outcomes reuse `tls_established_client`, `tls_established_server`,
`tls_failed_client`, and `tls_failed_server`. They carry negotiated metadata and
peer certificates on the parent connection, never once per HTTP/3 stream.
Certificate-probe connections do not emit these hooks. Outcomes are sampled at
native progress/retirement boundaries, not from an OpenSSL callback.

## Explicit limits

- The current native QUIC listener binds an IPv4 socket (`AF_INET`). IPv6 QUIC
  listener support is outside this hook patch; TCP/TLS IPv6 coverage does not
  imply QUIC IPv6 support.

- `quic_start_client` and QUIC `tls_clienthello` interception are not implemented.
  The listener can advance downstream TLS before it exposes a session. This
  bridge does not delay handshakes or invent a late start notification.
- Handshakes that fail before a parent setup/session is available cannot produce
  an addon outcome. Certificate-probe failures are not forwarding TLS failures.
- Certificate/key replacement, CA paths, and verification-mode changes are
  rejected explicitly by the adapter. Native trust policy remains authoritative.
- Live `ssl_conn` operations, transport replacement, and destination rerouting
  are unsupported. This is not a live aioquic/OpenSSL connection export.
- ALPN currently accepts one protocol. Both native legs must still negotiate
  compatible protocols; changing the offer does not override that validation.
- HTTP/3 stream inspection retains its existing descriptor/lifecycle model.
  Parent and stream descriptors are separate; this patch does not redesign it.

The wire action is `quic-lifecycle`, with observations in `details.quic`. Its five-field version-1 envelope is
unchanged; the QUIC action selects the QUIC adapter. Setup returns
`control.quic_lifecycle = 1` and `control.quic_start_server = 1`. Start replies
carry `upstream.sni`, `upstream.alpn`, and nullable `upstream.ciphers` (an OpenSSL
TLS 1.3 cipher expression). Later deployments in the chain see accepted changes
from earlier owners. Missing owners or worker failure remain unavailability,
with native strict/fail-open policy; an explicit veto is terminal.

## Live integration

`tests/quic_proxy_integration.py` replaces the recorder in an isolated copy of
Smithproxy's QUIC patch-runner lab. Apply
`tests/fixtures/quic-integration-runner.patch` to that copy, then install the
Python test as `tests/patch-runner/harness/quic-webhook-contract.py`.
The fixture patch is based on runner commit `a04b41ab`; it changes test orchestration
only and must not be applied to production transport sources.

Run the copied runner on the authorized test host:

```sh
tests/patch-runner/test-patch.sh sanity --suite quic --local \
    --dir /tmp/quic-spider-live/run \
    --env SPIDER_INTEGRATION_BIN=/tmp/quic-spider-live/bin/smithproxy-spider
```

The Spider binary's configured Python interpreter must exist on that host with
`deploy/requirements-addon.txt` installed. Use a clean test environment; no
reference mitmproxy runtime is required. A repeat can use `--skip-build` after
the source/binary identity has been verified.

The suite exercises a real HTTP/3 client, transparent Smithproxy, the real Spider
worker and an independent aioquic origin. It verifies parent/stream ordering and
retirement, metadata, combined SNI/ALPN/cipher mutation, veto, empty ciphers,
rejected ALPN, unavailable/strict replies, and disabled subscriptions. Baseline
local/GRE captures and decrypted native packets remain independently validated;
additional hook scenarios do not contaminate the baseline capture window.
