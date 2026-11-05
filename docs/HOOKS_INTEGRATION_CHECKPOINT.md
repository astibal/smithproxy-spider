# Hook integration checkpoint — 2026-11-05

This checkpoint closes validation of the implemented CONNECT, server, TCP TLS
and QUIC hook subset. It does not claim full mitmproxy transport equivalence.
No production code changed during this validation follow-up.

## Pre-merge tested sources

| Repository | Branch | Commit |
| --- | --- | --- |
| Smithproxy | proxy-hooks | `5e3b04fc` |
| Spider | proxy-hooks | `1ee74d2` |
| Socle | tls-proto-history | `26386d3` |
| Patch runner | GitHub master tooling | `a04b41ab` |

The P8 runner used production sources and unit tests from the approved branch,
with the master runner tooling and its CPU monitor CMake target overlaid only
for testing. The report's old checkout label (`c4634b4e`) is not the production
source identity; the archived source SHA256 manifest identifies the tested tree.

## Validation

| Layer | Result | Scope |
| --- | --- | --- |
| Full P8 on Rhino | 53/53 sections PASS | Native, traffic, lifecycle, capture, corpus and fuzz; eight section workers, four build jobs. Existing declared lifecycle XFAIL remains visible. |
| Native CTest within P8 | 49/49 PASS | Production branch test registrations plus CPU monitor target. |
| Supplementary master runner tests | 11/11 commands PASS | Registrations absent from the branch CMake: profiles, inventory, publication, port leases, privilege preflight, ProxyNightmare, remote artifacts and CPU monitoring. CPU fault tests report two explicit platform skips. |
| Complete Spider CTest | 124/124 PASS | Protocol/corpus, worker, clean-room, native adapter and backend tests, 392.80 seconds. |
| Live TCP/TLS/CONNECT | 47 scenarios PASS | TLS 1.2/1.3, fragmentation, ClientHello, start hooks, mutations, veto/failure and ordering; includes IPv4/IPv6 lab traffic. |
| Live authentication | PASS | HTTP CONNECT/SOCKS5, Keyway test PAM, native/addon vetoes, denied AAA and unavailable/invalid hook replies. |
| Live IPv4 QUIC/Spider | PASS | Real HTTP/3 client, transparent proxy, real worker, independent aioquic origin; parent/stream retirement, negotiated metadata, once-only start/outcomes. |
| QUIC decisions | 7/7 scenarios PASS | Combined SNI/ALPN/cipher mutation, veto, empty ciphers, rejected ALPN, fail-open unavailable reply, strict unavailable reply, disabled subscription. |
| QUIC observability and cleanup | PASS | Baseline local/GRE identities and semantics, decrypted native packets, Wireshark fields, and no leaked namespaces/listeners or host routing changes. |

Reports and source manifest are archived locally under
`p3-runs/quic-hooks-final-20261105` in the shared Smithproxy workspace. Rhino's
successful full run is `20261105T135631Z-c4634b4e-full`; the QUIC integration run
is `20261105T141648Z-ec95399a-sanity-quic`. The latter label identifies a disposable
fixture snapshot, not an additional published production commit.

The QUIC test fixture required a clean Python runtime matching the interpreter
path compiled into Spider. Extra scenarios take a baseline PCAP snapshot before
creating additional sessions so the GRE audit compares the same capture window.
Initial fixture/runtime failures are not product fixes or passing runs.

## Scoped parity

| Area | Available | Explicit boundary |
| --- | --- | --- |
| HTTP CONNECT | Request, connected and error hooks on regular H1 CONNECT | No upstream-proxy/H2 CONNECT expansion. |
| Server lifecycle | Native connection lifecycle and endpoint observations | No reconnect redesign or altered connect scheduling. |
| TCP TLS | ClientHello, both starts, both established/failed outcomes; upstream SNI/ALPN and legacy cipher expression | No live SSL ownership, certificate/context replacement, or forced handshake ordering; TLS 1.3 cipher suites are not controlled by the legacy cipher expression. |
| QUIC | Parent upstream start, both-side TLS outcomes, SNI/single ALPN/TLS 1.3 suites, veto | No client start, ClientHello interception, certificate/trust replacement or failures before parent setup. |
| QUIC address families | IPv4 listener | The native listener creates `AF_INET`; the attempted IPv6 probe is unsupported, not a passing QUIC test. TCP/TLS IPv6 success does not change this. |

See `QUIC_TLS_HOOKS.md` and the individual producer contracts for exact mutation
semantics. In particular, QUIC SNI overrides do not replace the native
certificate-verification identity.

## Pre-merge preparation (superseded below)

Read-only merge audits used the current GitHub refs; no release branch was moved.

1. **Socle first.** `tls-proto-history` and master `dcf6a78` diverge. The only
   textual conflict is `hostcx.cpp` diagnostics: both branches fixed a missing
   COM pointer. Retain master's `real_socket()` call and its null-safe accessor,
   together with the branch's TLS history/callback changes. This resolves the
   duplicated fix without introducing new transport behavior.
2. **Smithproxy next.** Master `a04b41ab` is three commits ahead on its side;
   `proxy-hooks` has seventeen unique commits. `CMakeLists.txt` merges cleanly.
   The remaining conflict is the Socle gitlink; select the validated combined
   Socle commit. Rerun the applicable gates on the actual merged candidate,
   because the green runs above do not certify a future merge tree.
3. **Spider integration branch.** `github/mitmproxy-api` (`fffd56d`) is an ancestor
   of `proxy-hooks` (ten commits ahead), so that integration is a fast-forward.
   Publishing to `main` is a separate step: main and this branch diverge and
   include the wider API work, not just the QUIC patch.
4. Commit the new integration tests and documentation, review the concrete
   release merge candidate, then publish only with the intended merge approval.

No production refactor, reconnect change, IPv6 QUIC implementation or automatic
release-branch merge was introduced to make the integration tests pass.

## Final merged validation and publication

The user authorized integration into Socle master, Smithproxy master and Spider
mitmproxy-api. The merged candidates were tested again before publication:

| Repository | Target | Tested commit |
| --- | --- | --- |
| Socle | master | `6764e481` |
| Smithproxy | master | `64d4b021` |
| Spider | mitmproxy-api | `ecaa1906` |

Socle retains master's null-safe `real_socket()` diagnostics alongside the TLS
changes. Smithproxy selects that merged Socle revision. The master patch runner
is now part of the merged source: no test-only CMake overlay was used. All 1,046
staged source files were verified against the local source SHA256 manifest.

| Final gate | Result |
| --- | --- |
| Full P8 on Rhino | 53/53 sections PASS |
| Native CTest within P8 | 60/60 PASS |
| Complete Spider CTest | 124/124 PASS, 352.59 seconds |
| Live TCP/TLS/CONNECT | 47 scenarios PASS |
| Live authentication | PASS |
| Live QUIC | 7/7 decision scenarios PASS, lifecycle/order/metadata and capture audits PASS |

The first Spider run hit the worker timeout during an overlapping build; the
complete suite passed on a clean serial rerun. The first QUIC run passed all
functional scenarios but raced the CLI snapshot against stream retirement.
The test origin now withholds FIN until the snapshot explicitly releases it.
This changes only the fixture; production transport behavior is unchanged.
The final Spider follow-up commit contains that fixture fix and this report,
with the same tested production source and binary as `ecaa1906`.

Final evidence is archived under `p3-runs/hooks-merged-20261105` in the shared
workspace. P8 run: `20261105T160143Z-64d4b021-full`. QUIC run:
`20261105T162113Z-ec95399a-sanity-quic`; its commit label identifies the isolated
fixture snapshot, while the binaries are the merged candidates above.

The scoped parity boundaries above remain unchanged. This closes the current
hook integration topic, not every mitmproxy API capability.
