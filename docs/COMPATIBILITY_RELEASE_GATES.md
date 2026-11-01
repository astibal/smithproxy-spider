# Mitmproxy compatibility release gates

This file is the conservative completion ledger for the clean-room addon
adapter. A green object-model or corpus test is not treated as evidence that a
live native producer exists. The adapter must not be described as a complete
drop-in replacement while any required gate below remains open.

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
| Live H1 interception transport | Native Parts, addon and host tests pass, but real Smithproxy `192944a8` advertises no H1 `content-reverse` capability. All three optional live suspension gates reject interception. | Agree the Smithproxy H1 reverse-output contract; see `H1_SUSPENSION_VALIDATION.md`. Do not claim live support from injected test metadata. |
| Header-hook streaming | Reference behavior and executable H1/H2 corpora exist; complete-message hooks work | Approve the phased native operation in `STREAMING_API_PROPOSAL.md`. |
| Request destination changes | Reference reroute corpus and contract exist; incompatible mutation fails closed | Approve `DESTINATION_ROUTING_API_PROPOSAL.md` and the Smithproxy routing boundary. |
| Host shutdown and live replay | Detached `load_flow()` is supported; proxy-owned actions are absent rather than simulated | Choose and approve a scope in `HOST_CONTROL_PROPOSAL.md`. |

## Open producer integrations

Spider already has bounded dormant adapters and black-box behavior for these
areas. They are not live features until Smithproxy emits the corresponding
native observations or decisions. Every Smithproxy change requires separate
discussion and approval.

- truthful upstream server lifecycle and endpoint/TLS metadata;
- raw TCP and UDP messages;
- HTTP CONNECT lifecycle;
- WebSocket logical messages;
- DNS complete messages over UDP and TCP;
- SOCKS5 authentication decisions; and
- TLS and QUIC lifecycle observations.

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
