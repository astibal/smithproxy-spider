# Mitmproxy compatibility release gates

This file is the conservative completion ledger for the clean-room addon
adapter. A green object-model or corpus test is not treated as evidence that a
live native producer exists. The adapter must not be described as a complete
drop-in replacement while any required gate below remains open.

Current validation and merge dependencies: [HOOKS_INTEGRATION_CHECKPOINT.md](HOOKS_INTEGRATION_CHECKPOINT.md).

## Foundation

| Requirement | State | Evidence |
| --- | --- | --- |
| Branch is based on the current `fc-api` | Pass | `mitmproxy-api` has merge-base `6dc2d1b` with the current `origin/fc-api` as checked on 2026-10-31. |
| Smithproxy remains the only proxy | Pass | The adapter operates on native Parts and never opens an upstream socket. Runtime source has no reference proxy dependency. |
| Clean-room implementation | Pass | `addon_clean_room_test.py` scans all runtime Python imports and package trees. Requirements and worker manifests reject the reference distribution. |
| Latest major reference is explicit | Pass | Every checked corpus is a v12 artifact and records 12.3.1 metadata in either short or product-qualified form; the release audit verified 12.3.1 as the latest release at implementation time. |
| Explicit selection and persistence | Pass | Selection, loader, backend and worker tests cover explicit Spider/mitmproxy mode, first-line `#!mitmproxy` precedence and persisted effective deployment mode. |
| No transaction mode | Pass | HTTP execution remains on Parts, Rewrite and Translate message boundaries. No transaction-mode transport or API was introduced. |

## Behavioral evidence

| Requirement | State | Evidence |
| --- | --- | --- |
| Reference corpus is executable | Pass | Every checked JSON corpus is named by a registered direct test; `addon_corpus_inventory_test.py` enforces this and prevents runtime leakage. |
| HTTP/1 mutation and control | Pass for implemented operations | Native integration covers headers, bodies, trailers, local responses, pipelining and callback-local `flow.kill()`. |
| Live H1 interception transport | Pass for annotated, callback-driven H1 | Smithproxy `8ab0ddc6` plus Spider webhook reverse forwarding pass three real socket scenarios: peer resume, both lanes paused and kill. See `H1_SUSPENSION_VALIDATION.md`; both project changes are required. Expanded coverage includes pipeline ordering, chunked/gzip/trailer editing and fragmented annotated headers retained through native Parts. Opaque bytes before protocol detection remain outside this scope. |
| HTTP/2 mutation and control | Pass for implemented operations | Native integration covers fragmented headers and bodies, multiplexing, HPACK checkpoints, credit accounting, local responses, informational responses, reset, GOAWAY and `flow.kill()`. |
| Persistent addon state | Pass | One worker owns a deployment generation; multiple connections share script state. Cross-protocol flow capacity and deterministic retirement are tested. |
| Public model and helper surface | Pass for audited surface | Exact class and service inventories, module exports, hooks, helpers, options, commands, filters, I/O and official examples are corpus-tested. |
| Clean full regression | Pass at the recorded checkpoint | The H1 suspension snapshot completed all 112 configured CTests on Rhino on 2026-11-01, plus 18 focused H1/corpus/clean-room tests. The local-response reference probe reproduced its recorded output exactly on a second run. Optional experimental CMake gates were not enabled in this snapshot. Repeat the applicable gates after functional changes. |

## Open native operations

These are real behavioral gaps, not facade TODOs. Their designs exist, but the
objective's approval rules prohibit implementing them implicitly.

| Capability | Current boundary | Required decision |
| --- | --- | --- |
| Long-lived `flow.intercept()` / `resume()` | H1/H2 header, complete-message and generated-response hooks retain native Parts across callbacks; publication uses a callback of the owning connection in either direction. H1 holds the ordered pipeline suffix. Raw suspension and idle wakeup remain open. | Keep the documented local-response kill deviation explicit; see `FLOW_SUSPENSION_API_PROPOSAL.md`. Idle wakeup and its transport are deferred. |
| Header-hook streaming | Reference behavior and executable H1/H2 corpora exist; complete-message hooks work | Approve the phased native operation in `STREAMING_API_PROPOSAL.md`. |
| Request destination changes | Reference reroute corpus and contract exist; incompatible mutation fails closed | Approve `DESTINATION_ROUTING_API_PROPOSAL.md` and the Smithproxy routing boundary. |
| Host shutdown and live replay | Detached `load_flow()` is supported; proxy-owned actions are absent rather than simulated | Choose and approve a scope in `HOST_CONTROL_PROPOSAL.md`. |

## Native producer integrations

The `proxy-hooks` checkpoint wires the following producers. Support is scoped
by the linked contracts; public hook names do not imply live SSL ownership or
arbitrary transport control.

| Producer | Implemented boundary | Remaining limits |
| --- | --- | --- |
| HTTP CONNECT | Regular HTTP/1 `http_connect`, `http_connected`, `http_connect_error`; shared flow and native decisions | Upstream-proxy and HTTP/2 CONNECT remain deferred. |
| Server lifecycle | Native connect/connected/failure/disconnection observations, endpoint metadata and retirement | No reconnect redesign; transport scheduling remains native. |
| TCP TLS | ClientHello, both start hooks, established/failed observations; upstream SNI/ALPN and legacy cipher expressions | No live SSL object, certificate/context replacement, forced handshake ordering, or TLS 1.3 cipher selection through the legacy cipher-list field. |
| QUIC | Opt-in parent `quic_start_server`, both-side TLS outcomes, upstream SNI/single ALPN/TLS 1.3 suites and veto | No `quic_start_client`, QUIC ClientHello interception, early failures before parent setup, or certificate/trust replacement. Parent/stream models remain separate. |
| Authentication | Smithproxy AAA result plus Spider veto for HTTP CONNECT/SOCKS5 | An addon cannot turn a rejected AAA result into acceptance. |

The following producers remain open: raw TCP/UDP messages, WebSocket logical
messages, and complete DNS messages over UDP/TCP. Detached model/corpus tests
must not be presented as live native coverage.

The detailed contracts and acceptance gates are in the producer proposal files
linked from `TODO.md` and `ADDON_COMPATIBILITY.md`.

## Merge gate

Before merge into `fc-api`:

1. resolve or explicitly scope every open capability above;
2. run the complete direct Python suite and all CTests from the final tree;
3. rerun the clean-room and dependency-absence checks;
4. review the staged diff for accidental reference material and unrelated
   project changes;
5. verify the branch base again; and
6. commit, push or merge only after explicit user approval.

## Authentication broker foundation

Spider now has a host-owned `/v1/pap` Unix client and `--auth-check` diagnostic,
with transport and optional real-PAM tests against Smithproxy `new-AAA`.
See `AUTH_BROKER.md`. That diagnostic foundation alone did not deliver addon
decisions to waiting proxy connections. The scoped producer integration below
now supplies that boundary; network access remains a separate deployment grant.

## Authentication integration checkpoint (2026-11-02)

The explicit `authentication` deployment hook connects native policies and
mitmproxy `socks5_auth` / `http_connect` callbacks to the real proxy's AAA result.
This closes the scoped policy-veto producer gap, not the complete CONNECT
lifecycle gate. See [AUTHENTICATION_HOOKS.md](AUTHENTICATION_HOOKS.md).

Release integration remains dependent on merging Smithproxy `new-AAA` into the
intended `main` and `master` branches. The branch dependency is an explicit
project commitment; passing tests on `new-AAA` is not evidence of those merges.
