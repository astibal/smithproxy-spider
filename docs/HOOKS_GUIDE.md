# Native proxy hooks: deployment and examples

This guide covers the implemented bridge in Smithproxy master and Spider
mitmproxy-api. The [validation checkpoint](HOOKS_INTEGRATION_CHECKPOINT.md)
records tested revisions; it is not a promise of complete mitmproxy parity.

## Choose the deployment

| Purpose | Deployment | Additional subscription | Contract |
| --- | --- | --- | --- |
| HTTP/1 CONNECT request, response and error | content / flow | none | [CONNECT](HTTP_CONNECT_PRODUCER_PROPOSAL.md) |
| TCP connect, connected, connect error and disconnected | content / flow | negotiated at setup | [Server lifecycle](SERVER_LIFECYCLE_PRODUCER.md) |
| TCP TLS established/failed, both sides | content / flow | negotiated at setup | [TLS lifecycle](TLS_LIFECYCLE_PRODUCER.md) |
| TCP ClientHello | content / flow | `tls_clienthello: true` | [ClientHello](CLIENTHELLO_PRODUCER.md) |
| Upstream TCP TLS start | content / flow | `tls_start_server: true` | [TLS controls](TLS_UPSTREAM_OPTIONS.md) |
| Client-facing TCP TLS start | content / flow | `tls_start_client: true` | [TLS controls](TLS_UPSTREAM_OPTIONS.md) |
| QUIC upstream start and parent TLS outcomes | content / flow | `quic_start_server: true` | [QUIC](QUIC_TLS_HOOKS.md) |
| HTTP/SOCKS proxy authentication | authentication / all / message | native protocol auth enabled | [Authentication](AUTHENTICATION_HOOKS.md) |

Select `script_api: "mitmproxy"` or use `#!mitmproxy` as the first line. The four
explicit subscription flags default to false. Omitting a flag on an update
preserves its previous value; send false to disable it. They apply to content
addons only. Network access is a separate `network_enabled` grant and remains
off by default; a hook receiving network observations does not need that grant.

Use new connections after changing a deployment. Setup ownership belongs to a
specific generation; a replacement cannot adopt old sessions. Dynamic addon
registration is allowed, but does not retroactively enable an unsubscribed
native handshake event. There is no general per-hook subscription map.

## Deploy through the API

The GUI selects API, scope and lifecycle mode, but currently has no checkboxes
for the four TLS/QUIC subscriptions. Use `POST /api/inspection` for these fields.
Authenticate with `X-Spider-Token`; first GET the same endpoint for its current
revision. This is a request shape, not a literal ready-to-send body:

```json
{
  "operation": "deploy",
  "revision": 12,
  "name": "TLS lab",
  "hook": "content",
  "scope": "all",
  "instancing": "flow",
  "script_api": "mitmproxy",
  "tls_clienthello": true,
  "tls_start_server": true,
  "tls_start_client": false,
  "quic_start_server": false,
  "network_enabled": false,
  "script": "#!mitmproxy\ndef tls_start_server(data):\n    pass\n"
}
```

Use the returned chain entry's ID and latest revision in a second request:

```json
{"operation":"enable", "revision":13, "id":"returned-deployment-id", "enabled":true}
```

For an update include the existing ID in the deploy request. Refresh on a
revision conflict rather than overwriting another administrator's chain edit.
`scope: "all"` means all non-bypassed traffic. Production scope/filter choices
still determine which sessions participate; the example deliberately uses a lab.

## Small complete addons

The following files are the source of the examples shown beside the built-in
editor. Each is an independent script, not a fragment to concatenate:

- [CONNECT and TCP lifecycle](../examples/hooks/connect.py): local rejection of
  a lab hostname and successful/error observations.
- [TCP TLS](../examples/hooks/tcp_tls.py): observe ClientHello and narrow upstream
  ALPN/legacy ciphers for a lab hostname.
- [QUIC](../examples/hooks/quic.py): select HTTP/3 and one TLS 1.3 suite; observe
  parent outcomes independently of HTTP/3 streams.
- [Authentication](../examples/hooks/authentication.py): narrow the existing
  SOCKS5 AAA result without logging a password.

Regenerate editor copies with `python3 tools/generate-hook-examples.py` and
verify freshness with `--check`. `hook_examples_tests` loads the complete addons
and invokes every demonstrated callback, including the negative AAA case; these
small examples do not replace the native integration suites. Native `api.*` reference/completion still comes
from the separate typed schema and `tools/generate-api-examples.py`. Addon
examples are not a claim that native-schema completion understands addon types.
For persistent native `init(api, state)`, `main(api, state)`, `exit(api, state)`
scripts, see the [native cookbook](INSPECTION_COOKBOOK.md). These lifecycle
functions are distinct from addon `load/configure/running/done`.

## What an addon can change

| Boundary | Supported changes | Important distinction |
| --- | --- | --- |
| CONNECT request/response | Supported local response, response edits or kill | Does not reroute arbitrary native destinations; follow the CONNECT contract. |
| TCP server connect | Nonempty `data.server.error` veto | Does not change native connect scheduling. |
| ClientHello | Bypass via `ignore_connection`, client error veto, supported upstream offers | ClientHello itself and native policy remain authoritative. |
| TCP upstream start | `conn.sni`, `conn.alpn_offers`, `conn.cipher_list`, error veto | Legacy cipher expression affects TLS 1.2 and earlier only. |
| TCP client start | Error veto | No certificate or client TLS parameter replacement. |
| QUIC upstream start | `conn.sni`, `settings.alpn_protocols`, `settings.cipher_suites`, error veto | One ALPN; TLS 1.3 wire cipher IDs translated by Spider. |
| Authentication | Reject an AAA-accepted attempt | Cannot upgrade failed AAA authentication. |

For example, `data.conn.error = "Rejected by deployment policy"` vetoes a TLS
start. Setting SNI changes the TCP certificate verification identity, whereas
QUIC verification keeps its original native identity. TCP empty cipher lists
mean unspecified defaults; a QUIC empty cipher list remains explicitly empty.
Do not treat these as interchangeable APIs. Detailed validation/default semantics
are in the linked contracts.

## Ordering, failures and lifetime

TCP `server_connected` means confirmed TCP completion, not TLS readiness. Before
upstream TLS start, Smithproxy emits a missing connected observation if TCP is
already ready. If TCP is still pending, native ordering is retained; the bridge
does not defer the handshake to reproduce a reference event sequence.

TLS outcomes may be observed after the native transition. Bounded state history
preserves relevant transitions between observations; this is not execution at
an arbitrary OpenSSL callback. Client and upstream timelines need not interleave
in one universal order. QUIC events refer to a transport parent, not every H3
stream. Failures before parent setup cannot always be reported.

Ordinary observer unavailability follows native fail-open/negotiated strict
policy. An explicit accepted veto is terminal. Authentication is different:
AAA and all enabled authentication observers must accept; unavailable observers
deny that exchange. Native policy cannot be bypassed by an addon approval.

Terminal notification payloads own their metadata and do not retain a destroyed
proxy, CX or SSL pointer. Retirement/finalization orders terminal events before
connection stop; transport destruction is not a place to execute new addon work.

## Deliberate limits and troubleshooting

- No live `ssl_conn`: its compatibility argument exists, but operations or
  replacement raise an explicit error. No certificate/context/trust replacement.
- No DTLS, QUIC ClientHello/client-start hook or native IPv6 QUIC listener.
- No upstream-proxy CONNECT or H2 CONNECT expansion in this bridge.
- A callback defined but never called: check deployment enabled state, content
  scope, explicit subscription, new-session ownership and native interception.
- A connection terminates after a hook: inspect Spider callback errors and native
  warning logs; check whether it was a deliberate veto or strict unavailability.
- Import works locally but not in Spider: install addon requirements in the
  interpreter selected by CMake; workers run isolated. See the repository README.

Use the [release gates](COMPATIBILITY_RELEASE_GATES.md) and final checkpoint for
live TLS, authentication and QUIC test commands/evidence. Documentation examples
alone do not establish packet-level compatibility.

## Plaintext upgrades

[STARTTLS lifecycle extension](STARTTLS_HOOKS.md) defines our own identity and
ordering contract for upgrades on an existing TCP connection. It is separate
from reference mitmproxy parity and from TLS session resumption.

[TLS session resumption](TLS_SESSION_RESUMPTION.md) describes lifecycle identity,
independent upstream/downstream reuse and the live resumption matrix.
