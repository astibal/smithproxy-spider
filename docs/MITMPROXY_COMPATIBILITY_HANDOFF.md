# Spider mitmproxy compatibility development handoff

Latest follow-up, 2026-11-01: native scripts now support optional
`init(api, state)` / `exit(api, state)` around `main(api, state)`, with an opaque
state object retained by one deployment generation. Network access is an explicit
`network_enabled` deployment grant, off by default, including in editor previews.
See [the lifecycle contract](../README.md#native-script-lifecycle) and
[the RADIUS regression](../tests/native_lifecycle_test.py): a real `pyrad` client
is created once in `init`, reused against an isolated UDP peer, and blocked by
the default sandbox. This does not implement the Smithproxy authentication
webhook or delegate its AAA decision to scripts. The checkpoint below records
the earlier H1 milestone and its continuing project constraints.

Checkpoint: 2026-11-01, implementation commit
`777633b9a6da4fb8dfc5a211f0c3bf50beff92a1` on `mitmproxy-api`.
That commit is pushed to `origin/mitmproxy-api`. This document is a subsequent
documentation-only commit on the same branch.

The current work item is complete: callback-driven HTTP/1 interception and
same-connection resume from either direction now use native Spider Parts.
The overall compatibility project is **not** a complete drop-in replacement.
Several native producer integrations and transport operations remain open.
Use the release gates below rather than an old percentage from conversation.

This handoff is intended to replace the very long development conversation
when starting the next task. It records both implementation facts and decisions
which must not be accidentally reopened or silently reversed.

## Start here

1. Read this file, the local `AGENTS.md`, and `COMPATIBILITY_RELEASE_GATES.md`.
2. Inspect `git status`, branch, recent commits, and the actual remote state.
   Preserve any changes made after this checkpoint.
3. Read the current boundary at the top of `FLOW_SUSPENSION_API_PROPOSAL.md`.
   The historical proposal later in that file is not the current design.
4. Read `TODO.md` for unresolved work and its approval boundaries.
5. Discuss the next capability with the user. Do not implement an unapproved
   Smithproxy producer merely because its Spider adapter or proposal exists.

The user wants to continue in a new task to avoid carrying the entire history.
No new task, merge, branch switch, or deployment was performed for this handoff.

## Repository and branch

```text
Working checkout
  /home/astib/Documents/Capture.Zone/worktrees/smithproxy-spider-mitmproxy-api

Branch
  mitmproxy-api

Remote
  ssh://git@github.com/astibal/smithproxy-spider.git

Intended eventual integration target
  fc-api

Observed merge base with local origin/fc-api
  6dc2d1ba989b7805896dd0f66a3987380eb681c5
```

The merge base was checked locally at this checkpoint. Fetch and recheck before
eventual integration; it is not a promise that the remote target will remain
unchanged. Do not merge to `main`, switch to the Saslik checkout, or edit the
appliance repository for this task.

Recent milestones, newest first:

| Commit | Change |
| --- | --- |
| `777633b` | Native H1 lane suspension, ordered publication, addon interception and peer resume |
| `36e4673` | Interception of generated H2 responses |
| `72fc621` | Callback-driven H2 header interception |
| `d654bdd` | Protocol checkpoint allocation and worker JSON overhead reduction |
| `055f9d6` | Packaged addon worker tests split by protocol |
| `7781c21` | Persistent protocol snapshots exposed to flow scripts |

No other project's code was changed by the H1 work item. Earlier approved
Smithproxy work exists in the wider project history, but its current checkout
and branch must be inspected before any future cross-project change.

## Nonnegotiable constraints

- Speak Czech with the user and use informal address. All code, comments,
  documentation and commit messages are English.
- Smithproxy remains the sole proxy engine. Do not put mitmproxy beside it,
  behind it, or inside the production runtime.
- This is a clean-room compatibility layer. No mitmproxy implementation code,
  vendored package, or runtime dependency may enter the project. Independent
  public-API probes and explicitly permitted reference corpora are test assets.
- Scripts written for mitmproxy should run through our own scripting API.
  API resemblance alone is insufficient: hooks, mutations and emitted traffic
  must match the measured behavior within the documented supported scope.
- Testing/deployment uses explicit API selection. First-line `#!mitmproxy`
  overrides that selection. Do not add heuristic script detection.
- Existing native API semantic changes require discussion and approval.
  Generically useful, additive extensions with no impact on existing callers
  are allowed. Changes in other projects require separate approval.
- Tests are authorized. Rhino is authorized for nondestructive development
  and testing within this project; do not touch unrelated services or data.
- The user cares strongly about readable code: short explanatory comments,
  blank lines between functional blocks, shallow nesting, ordinary control
  flow, and no compressed one-liners or excessive syntax sugar. Apply the same
  standards to tests. Avoid splitting coherent operations into tiny helpers
  solely to make functions appear shorter.
- Commit and push were explicitly authorized for this completed work item.
  Merge was not authorized. Follow the next task's instructions for later work.

## Reference and evidence policy

The declared API major is **12**, with behavioral reference **mitmproxy 12.3.1**.
That was the audited release at implementation time. A future release audit is
separate from silently changing the reference expected by existing corpora.

The reference runs in an isolated external environment. The probes under
`tests/probes/` exercise its public interfaces and real loopback traffic.
Checked JSON observations under `tests/corpus/` are consumed by executable
tests. `addon_corpus_inventory_test.py` checks reference metadata, direct test
consumers, CTest registration, and absence of corpus leakage into runtime.

`addon_clean_room_test.py` checks runtime imports, requirements, package trees,
and the bundled module manifest. Passing those scans supports the provenance
boundary; it does not replace reviewing new code and dependencies.

Do not conflate these kinds of evidence:

1. Public object or helper contract tests.
2. A dormant adapter matching a reference corpus.
3. Packaged-worker execution with native Parts and output.
4. A live native producer delivering the required observations and decisions.

A green adapter test does not prove that Smithproxy currently produces the
events. Never call an unsupported hook live merely because its class exists.
Likewise, line/branch coverage is not a feature-completion percentage.

## Runtime architecture

```text
Smithproxy observations and content
             |
             v
Spider C++ inspection host
  connection state, ownership, quotas, worker lifetime
             |
             v
Persistent deployment worker
  addon generation and public flow objects
             |
             v
Compatibility driver and message bindings
  hooks, public mutations, native API calls
             |
             v
Native Parts + H1 commit / H2 Translate
  framing, retained data, ordering, HPACK, flow control
             |
             v
Atomic forward/reverse result and checkpoint updates
             |
             v
Smithproxy publication
```

The facade must not become a second HTTP engine. It owns public objects and
callback lifecycle. Native Spider APIs own message edits and publication.
Compatibility drivers do not manufacture H2 frames or maintain another HPACK
context. They do not open upstream connections.

One persistent worker owns a deployment generation and its script state.
Multiple connections share that generation. Native serialized checkpoints
belong to the host, not only to worker memory. Recreating a native worker can
restore native Parts; it does not magically restore arbitrary Python addon
state. Failed addon generations are invalidated rather than replaying hooks
whose side effects may already have happened.

The worker is a packaged program. Native sources are concatenated into it;
addon modules are separately bundled using `src/addon_worker_modules.txt`.
An import that works from a local source checkout may fail in the isolated
packaged worker. In particular, do not casually import `inspection_api` from
an addon module: use the passed native objects, as existing drivers do.

## File map

| Area | Main files |
| --- | --- |
| Host ownership, publication and instance lifetime | `src/inspection.cpp`, related inspection headers and pool code |
| Native API and generated schema | `src/inspection_api.py`, `tools/generate-api-examples.py`, `docs/API_EXAMPLES_REFERENCE.md` |
| H1 Parts, response order and suspension | `src/inspection_chunked.py` |
| Native retained Parts | `src/inspection_hold.py` |
| H2 views and Translate | `src/inspection_h2.py`, `src/inspection_translate.py` |
| Native observed protocol states | `src/inspection_protocol_state.py` |
| Packaged worker and sandbox | `src/inspection_worker.py`, `src/inspection_sandbox.py`, worker bootstrap/packing tools |
| Explicit mode, persistence and loader | `src/inspection.cpp`, `src/inspection_worker.py`, `src/addon_loader.py`; selection tests in `tests/addon_selection_test.cpp` |
| Public generation, addon manager and facade installation | `src/addon_runtime.py` and its companion modules |
| Native adapter entry point | `src/addon_native.py` |
| Public HTTP bindings and hook state | `src/addon_parts.py` |
| H1 callback lifecycle | `src/addon_h1_events.py` |
| H2 callback lifecycle | `src/addon_h2_events.py` |
| Public model and helpers | Other `src/addon_*.py` modules |
| Packaged addon module inventory | `src/addon_worker_modules.txt` |

The full historical contract and audit trail is in `ADDON_COMPATIBILITY.md`.
For current completion boundaries, prefer `COMPATIBILITY_RELEASE_GATES.md` and
the current sections of the focused proposal documents over old dated entries.

## What the H1 commit implements

### Native ordered lanes

H1 cannot publish arbitrary messages out of pipeline order. Its suspension
identity is **id zero plus an explicit direction**, scoped to one connection.
There is no extra publication ID. Suspending a header retains that message and
the entire younger suffix in its lane.

```python
# In a native flow callback, after selecting an owned H1 header Part:
api.message.suspend(header, timeout_ms=60000)
return api.message.commit()
```

```python
# In a later callback of the SAME connection, from either direction:
parts = api.message.resume(0, side="L")
parts[0].http1.set_header("X-Inspected", "yes")
return api.message.commit()
```

`api.message.suspended_parts(0, side="L")` provides detached inspection copies.
Edits to those copies are discarded. `resume()` returns editable native drafts.
Opposite-direction drafts keep their original lane and publish through reverse
output. They are not inserted into the triggering callback's input Parts list.

Resuming incomplete input removes the logical pause but retains ordinary
reassembly. It does not invent body completion or publish a partial body.
A callback may resume an older message and suspend a younger message in the
same lane before commit. Other duplicate/out-of-order commands are rejected.

`_H1Suspension` is attached to `_H1ResponseTransaction`. Checkpoint version 1
still represents ordinary response ordering. Version 2 adds a nonempty
direction-to-deadline pause map. Saved Parts remain in the existing directional
hold fields. Both directions are prepared before any result is exposed.

The C++ host accepts H1 peer-hold updates only with the appropriate prior
connection-owned pause/hold or validated connection close. Existing mode and
size checks remain. Stateful results cannot outlive a retired owner or closed
connection.

### Response order bug fixed first

Previously, native assembly could advance the response-order ledger for Parts
in a held suffix. A held request could allocate an origin slot before being
sent, and a held response could consume a slot or release a local reply too
early. The publisher now stops ledger advancement at the hold boundary.

Tests cover held requests, held responses, local-response order, emitted
prefixes and one-time release. This fix is useful independently of mitmproxy
compatibility and belongs in the native publisher, not in adapter glue.

### Addon mapping

`H1AddonEvents` processes the incoming lane, then a peer lane released by its
hooks. It tracks hook delivery and public flows but owns no second wire queue.
Header hooks, complete-message hooks and generated-response hooks may pause.
Resume applies retained public edits and runs only hooks not delivered before.

If a hook on a resumed peer releases the original lane again, publication can
wait for the next callback; the driver does not recursively drain both lanes.
The API is callback-driven, not an idle wakeup facility.

Example of a physically possible opposite-direction release: an earlier
request has already reached the server; a later pipelined request is paused.
The earlier response supplies the callback which releases the later request.

```python
#!mitmproxy
pending = {}

def request(flow):
    if flow.request.path == "/pause":
        pending[flow.client_conn.id] = flow
        flow.intercept()

def response(flow):
    held = pending.pop(flow.client_conn.id, None)
    if held is not None:
        held.request.headers["X-Resumed"] = "yes"
        held.resume()
```

This example depends on an earlier response on the same connection. It is not
a useful standalone browser demo if `/pause` is the only outstanding request:
no response can arrive for a request which has not been forwarded.

### Generated responses and kill

A generated response retains its original request anchor while paused. Its
response-header and response hooks have separate delivery state. Publication
uses native `respond()` and the ordinary response-order ledger.

The new independent H1 reference probe records eight cases: interception at
either response hook, with resume, kill, resume-then-kill and kill-then-resume.
Resume hook traces and edited output match the checked corpus.

Reference 12.3.1 leaves bare kill and kill-then-resume pending during the
two-second H1 observation window. Resume-then-kill closes the connection.
Spider keeps its native close behavior for all kill cases and follows the
working resume-then-kill error-hook ordering. H2 has the analogous documented
reset behavior. We suspect a reference wakeup bug but have not proved an
infinite wait or an upstream diagnosis. Do not rewrite the corpus to hide the
difference or advertise byte-for-byte parity for those kill cases.

## Current H2 and state boundaries

H2 suspension retains logical Parts through Translate. Input HPACK continues;
output encoding occurs when the retained Parts are published. Native queues,
stream/window accounting, resets and GOAWAY remain authoritative. Completed
messages, incomplete header-hook holds, generated responses and same-connection
peer resume are covered by the existing H2 work.

H2 uses its native stream identity rather than H1's lane zero:

```python
parts = api.message.resume(stream_id)
return api.message.translate()
```

Native protocol states describe what Spider observed, not a reconstructed dump
of Smithproxy's private state. Existing Parts and annotations are the evidence.
Native tracking is opt-in through `track_states()`; the compatibility adapter
enables the tracking it needs. Do not resurrect the old `track_protocols` name.
See `PROTOCOL_STATE_API_PROPOSAL.md` for receive/publication distinctions.

## Deliberately deferred architecture

- No Smithproxy hold queues or third persistent HPACK context. Those proposals
  were abandoned in favor of Spider's existing native retained Parts.
- Earlier generic controls/operations support is not a mandate to add those
  queues. Keep buffer action and engine controls conceptually separate.
- No idle timer webhook, 200 ms Smithproxy timer, management API wakeup endpoint,
  WebSocket or persistent downstream signaling channel in this implementation.
  These were discussed and explicitly deferred.
- No new transaction mode. Existing Parts/Rewrite/Translate provide the native
  publication boundary.
- No broad coroutine scheduler rewrite as part of resume. A script sleeping
  inside a serialized callback can delay its worker; do not pretend sleep gives
  an idle connection permission to publish.
- Existing `mitmproxy.script.concurrent` support has a constrained prepared
  runner for supported lifecycle callbacks. It is not permission to run traffic
  callbacks concurrently against native connection state. Inspect the current
  implementation before making claims about automatic sleep isolation.
- No editor/GUI work in the current item. The user deferred it in favor of
  compatibility coverage, despite the older TODO label saying “next”.

## Remaining work and approval boundaries

| Area | Current state and next step |
| --- | --- |
| Idle resume | No spontaneous publication. Requires a separately agreed transport/control design. |
| Raw TCP/UDP | Models and dormant adapter/corpora exist; native producer and datagram ownership still need integration approval. Raw suspension is not delivered. |
| Server lifecycle | Need truthful target-selection, connected, failed and disconnected observations. Do not invent server events from client setup. |
| HTTP CONNECT | Dormant decision adapter and reference evidence exist; integrate only after approving the producer contract. |
| WebSocket | Logical-message adapter/corpora exist; native framing/backpressure producer still required. Do not substitute raw TCP chunks. |
| DNS | Complete-message model and extensive UDP/TCP corpora exist; do not infer DNS solely from port numbers. Producer integration remains open. |
| SOCKS5 authentication | Decision adapter and reference behavior exist; producer integration is approval-gated. |
| TLS/QUIC observations | Need genuine native observations before lifecycle claims. |
| Incremental HTTP streaming | Complete-message buffering is not streaming. Follow `STREAMING_API_PROPOSAL.md`; implementation needs approval. |
| Destination changes | Native upstream-selection boundary is required; see `DESTINATION_ROUTING_API_PROPOSAL.md`. |
| Replay/shutdown | Public detached helpers do not imply live proxy replay or shutdown authority. See `HOST_CONTROL_PROPOSAL.md`. |
| Split H1 start lines/headers | Annotated fragments now use native Parts prefix holds, like incomplete H2 Parts; see `H1_SUSPENSION_VALIDATION.md`. Opaque input before producer detection remains outside this scope. |
| Hold failure recovery | Host fail-open behavior with retained prefixes remains explicitly deferred. |
| Opaque diagnostics | Later task: count recognized versus opaque source bytes once, excluding duplicate views and rewritten/resumed bytes. |
| Editor hints | Later UI task for native and facade API help, respecting explicit mode and shebang precedence. |

The hold recovery item is particularly important: a native commit failure does
not mutate the retained checkpoint, but existing host fail-open policy is not
a guarantee of connection closure or no traffic leakage after timeout, worker
failure, deployment change or overload. Do not advertise an end-to-end
fail-closed transport guarantee merely because a native validator rejects a
draft. Deadlines are checked on callbacks, not by an idle clock.

Broader H1 adversarial testing can continue without an architectural expansion:
chunked/trailer/compressed edits combined with suspension, mixed lane pauses,
retirement while paused, and real producer/network integration. Existing native
framing tests remain useful but are not an exhaustive cross-product of every
interception phase and encoding.

## Test evidence for this checkpoint

The final Rhino snapshot built the application and test binaries, then passed
**112 of 112 configured CTests**. A focused run passed **18 tests** across H1
suspension, corpus inventory and clean-room checks. The H1 local-interception
reference probe was run twice; the second JSON output matched the checked
corpus exactly. Generated API examples passed their consistency check.

Optional experimental CMake gates were not enabled in this snapshot. No new
whole-project statement/branch percentage was measured for this commit. Older
coverage figures in the audit trail belong to their recorded revisions.

Important executable evidence:

- `tests/inspection_chunked_test.py`: native lane pauses, peer edits,
  incomplete reassembly, release/re-pause, rollback, deadline boundary,
  termination, response ordering and fresh packaged native workers.
- `tests/addon_h1_suspend_test.py`: same/opposite lane addon resume, deferred
  hooks, pipeline ordering, local replies, reference resume parity and explicit
  kill deviation. Nine test methods include additional matrix subcases.
- `tests/addon_worker_test.py`: persistent packaged worker round-trips native
  H1 checkpoints and preserves public flow state without replaying hooks.
- `tests/inspection_instances_test.cpp`: real host-side checkpoint ownership,
  peer release, replacement output and response-order progression.
- Existing H2 Parts, suspension, worker, hold and cookbook gates remain green.

Do not loosen timeouts to make a lifecycle race disappear. Use explicit
synchronization and assert the actual state transition. Previous worker tests
were deliberately improved on this principle.

## Rhino environment and reproducible commands

Heavy work belongs on Rhino to leave the user's machine available. Authorized
SSH access is `root@rhino`. Use an isolated snapshot; do not overwrite another
task's checkout. The snapshot for this checkpoint is:

```text
/tmp/spider-h1-suspend.qbVhxN
  venv/                         clean Spider test environment
  build/                        configured Debug CMake build
  build-final.log               full application/test build
  ctest-final.log               final 112-test run
  h1-final.log                  focused 18-test run
  h1-local-reference.json       first reference measurement
  h1-local-reference-repeat.json second reference measurement
  h1-probe-repeat.log           reference runner output
```

The separate reference executable is:

```text
/tmp/spider-local-intercept.3XpmGu/reference/bin/mitmdump
```

Do not use the reference environment as Spider's test interpreter. It does not
have the same dependency set, and production must remain independent of it.
Temporary paths are not durable deployment artifacts; the repository preserves
the code, tests, probes and corpus needed to rebuild them.

On Rhino, from the snapshot directory:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DPython3_EXECUTABLE=/tmp/spider-h1-suspend.qbVhxN/venv/bin/python
cmake --build build -j2
ctest --test-dir build --output-on-failure -j2

PYTHONPATH=src:tests venv/bin/python -m unittest \
  addon_h1_suspend_test addon_corpus_inventory_test addon_clean_room_test

venv/bin/python tools/generate-api-examples.py --check
```

To repeat the reference observation, select a new output path:

```sh
venv/bin/python tests/probes/addon_local_intercept_h1_probe.py \
  --reference /tmp/spider-local-intercept.3XpmGu/reference/bin/mitmdump \
  --output /tmp/spider-h1-suspend.qbVhxN/reference-next.json
diff -u tests/corpus/mitmproxy_v12_h1_local_intercept.json \
  /tmp/spider-h1-suspend.qbVhxN/reference-next.json
```

For a new snapshot, include the normal source/test/doc/tool directories,
`CMakeLists.txt`, `README.md`, the required frontend test inputs, requirements,
and existing external headers. In particular, full application builds need
`external/lmhpp/include`; the JSON fallback needs its existing include tree.
Do not copy Git internals, runtime captures, credentials or unrelated workspace
data. Preserve the existing submodule revision rather than updating it casually.

Local focused tests used `/tmp/spider-resume-test-env/bin/python` with
`PYTHONPATH=src:tests`. Most expensive validation was run remotely. Rhino has no
`rg` in this snapshot's shell environment; use ordinary `grep` there if needed.

## Recommended continuation

The next task should start by confirming this checkpoint and asking which
remaining capability the user wants next. A short architecture/readability
review was discussed as a later “TLC” task, but it should not silently become
a broad refactor while adding another feature.

Useful bounded options are additional H1 adversarial wire coverage, a review
of one producer proposal with the user, or the deferred editor assistance.
Do not present raw TCP/UDP, idle resume or streaming as trivial facade-only
finishing work: their native ownership boundaries still matter.

Suggested opening instruction for the new task:

> Continue Spider's clean-room mitmproxy compatibility work from
> `docs/MITMPROXY_COMPATIBILITY_HANDOFF.md` in the `mitmproxy-api` worktree.
> Read the handoff and current release gates, inspect Git state, and summarize
> the next bounded options before changing architecture or another project.
> Communicate in Czech; keep code, comments and commits English and readable.

The implementation is committed and pushed, not merged or deployed. Keep that
distinction explicit when reporting status.
