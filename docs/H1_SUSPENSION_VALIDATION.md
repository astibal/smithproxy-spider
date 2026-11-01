# H1 suspension validation and live transport boundary

Validation date: 2026-11-01, following Spider commit `d3ec179`.

Original acceptance status: the three live acceptance scenarios now pass with Smithproxy
`8ab0ddc6` on `http1-flow-kill` and Spider's H1 webhook reverse-output fix.
The original transport failure below is retained as the reason for both changes.
The expanded fragmentation failure is resolved by native incomplete-header Parts;
see the follow-up section below for the implementation and validation scope.

## Evidence added

`tests/addon_h1_suspend_test.py` covers simultaneous request/response pauses,
peer resume followed by another interception in the request hook, ordered
release of younger requests, and killing a request while both lanes are paused.
It asserts output, hook delivery and cleanup through native Parts.

`tests/inspection_instances_test.cpp` exercises the actual C++ host and packaged
addon worker with both lanes paused. Connection stop, redeploy and disable/enable
retire the old owner. A new addon generation rejects late content on an existing
connection because it did not observe setup. After a failed generation is
replaced and the connection restarts, a fresh request/response succeeds without
replaying retained traffic or old hooks.

These checks do not promise transport fail-closed behavior after retirement.
The host's existing fail-open policy remains unchanged.

## Original real proxy failure (resolved)

The optional `tests/h1_suspension_e2e.py` runs real Smithproxy and Spider
processes with loopback SOCKS clients and controlled HTTP/1 origin sockets.
Only management lease discovery is simulated. Producer annotations and content
webhooks are not synthesized by the test.

The three acceptance scenarios are:

- `peer`: an earlier response resumes a later intercepted request;
- `both`: both directions pause, another connection changes public resume
  intent, and a callback on the owning connection publishes both lanes;
- `kill`: an earlier response kills the intercepted request and closes the
  connection without publishing the held suffix.

Before the correction, all three failed at the first interception against Smithproxy
`192944a8` (`http1-flow-kill`), with socle `decc93fe` and lmhpp `d97ff6ae`:

```text
CommitException: HTTP/1 suspension requires hold and content-reverse support
```

Smithproxy's `MitmProxy::content_webhook()` advertises `content-reverse` only
when `flow_ctx_->can_inject()` is true. `ProtocolViews::can_inject()` requires
an active rewrite adapter, and `src/inspect/protocol_adapter.cpp` currently
registered only the HTTP/2 adapter. Thus those H1 callbacks advertised no
reverse capability. Spider correctly rejects suspension rather than claiming
that it can atomically publish the peer lane.

This was a producer integration gap, not a failed native lane-ordering test.
Do not report live H1 interception as supported based only on injected host
metadata or packaged-worker tests. The fix supplies the capability through the native adapter; it does not fake
metadata in a test relay or relax Spider's capability check.

## Resolution and final evidence

Smithproxy `8ab0ddc6` registers an H1 adapter using the existing
`Http1Connection` parser and the existing directional-output contract. Each
endpoint has independent framing and a request-method FIFO. Held requests do
not advance the server's queue before publication. Protocol transitions based
on ALPN retire both outer H1 views together, and unrelated inspector metadata
remains owned by its original inspector.

The first adapter run also exposed a Spider webhook bug: it forwarded
`replacement_reverse` only for Translate results. The H1 commit result already
contained the correct peer bytes, but they were absent from the webhook reply.
The ordinary replacement path now includes them without introducing Translate
controls or another transport. A direct webhook test covers a local H1 response
with empty forward output and nonempty reverse output.

Final Rhino evidence:

- 236 Smithproxy native tests passed, including eight new H1 view cases;
- seven existing transport suites passed: STARTTLS, H1 need-more in JSON/SXBN,
  and H2 protocol views/injection in JSON/SXBN;
- all 112 standard Spider CTests passed after the webhook fix;
- the subsequently added direct webhook test passed; and
- all three real H1 acceptance scenarios passed again with the final adapter.

These results cover the documented callback-driven scope. Idle publication,
raw-protocol suspension and transport recovery after fail-open remain outside
this change.

## Expanded adversarial coverage: original failure

The test-only checkpoint `2d34ee7` added three real-socket scenarios and
strengthened ordinary pipeline replies with distinct bodies:

- `pipeline` passed: the intercepted request and its three younger requests
  reached the origin in order, and their distinct responses reach the client in order.
- `encoded` passed: a gzip response uses chunk extensions and trailers; the last
  trailer delimiter arrives in a later callback. Nothing reaches the client
  while reception or interception is pending. A request callback resumes an
  edited response after removing its obsolete trailers. The client receives
  valid chunked gzip data with the new decoded body before the younger response.
- `fragmented` failed: after an initial complete request establishes H1,
  sending just `GE` from the next request already exposes `G` to the origin.
  The test stops there; its later header-name and final-CRLF split checks have
  not been reached and are not claimed as validated.

The native HTTP parser can annotate partial start lines and headers, but
`make_message_parts()` previously needed a complete header before creating
a typed H1 message. `NativeAddonAdapter.content()` selects H1 dispatch from those typed
Parts. That path provided no retention for the incomplete header.
The required follow-up was to retain annotated fragments in the native Parts
path with bounded state and preserve hook identity, without adding HTTP
sniffing or another parser to the compatibility facade.

At that checkpoint, Rhino CTest reported **5/6 passed**, with only
`inspection_h1_suspension_e2e_fragmented` failing. Both existing H1 CTest suites (`addon_h1_suspend_tests` and
`inspection_h1_corpus_tests`) also pass. The live log is
`/tmp/spider-h1-lifecycle.Fsa0XT/h1-expanded-e2e.log`.
At that checkpoint, the fragmentation assertion was neither disabled nor
inverted: enabling `SPIDER_TEST_H1_E2E` exposed the open acceptance gate. The option
remains OFF by default. This is evidence of a pre-existing gap, not a claim
that arbitrary fragmented HTTP headers can be intercepted safely.

## Fragmented-header resolution

H1 now follows H2's incomplete-Part lifecycle: `hold_from()` retains an ordinary
suffix in the existing host-owned JSON checkpoint, and `resume_message()` joins
its next annotated input. A pending `http1.header` has `complete == False` and
no `http1` draft. Complete prefix messages may publish while the pending suffix
remains held. The addon dispatches header hooks only when the native header is
complete; its existing body hold then takes over if necessary.

The retained header includes the producer's start-line/header ranges. Resume
rebases and merges those ranges before rebuilding native Parts. It does not
replay producer observations, add a compatibility parser or keep a second
addon-owned byte buffer. Pending headers are limited to 64 KiB in addition to
the existing checkpoint quotas. Edited pending headers and continuations without
valid producer boundaries are rejected. Peer resume also preserves a partial
younger header while publishing the complete prefix.

Unit coverage checks every byte split of request and response headers,
one-byte reception followed by body retention and pipelining, missing
annotations, edited fragments, the header limit, peer publication, repeated
interception before a pending younger header, and exactly
one delivery of each addon response hook. The real `fragmented` scenario now
passes all its start-line, header-name and final-CRLF splits before interception
and peer resume.

Final Rhino validation passed **118/118 CTests**, including all six real H1
scenarios. The complete log is
`/tmp/spider-h1-lifecycle.Fsa0XT/h1-header-regression-final.log`.
The first full run found only a stale generated API reference in the snapshot;
the final run includes the regenerated reference and the repeated-interception
regression. Local native suites also passed 18 hold tests and 51 chunked/H1 tests.

This capability requires native H1 annotations. It does not claim detection or
retention of opaque bytes before the producer has identified HTTP. Existing
fail-open and idle-publication boundaries remain unchanged.

## Reproduce

Build the existing Smithproxy revision and install Spider's test requirements
in an independent Python environment. Configure the optional acceptance gates:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DPython3_EXECUTABLE=/path/to/spider-test-env/bin/python \
  -DSPIDER_TEST_H1_E2E=ON \
  -DSPIDER_E2E_SMITHPROXY_SOURCE=/path/to/smithproxy \
  -DSPIDER_E2E_SMITHPROXY_BINARY=/path/to/smithproxy/build/smithproxy
cmake --build build -j2
ctest --test-dir build -R inspection_h1_suspension_e2e --output-on-failure
```

The option defaults to OFF and does not require the experimental H2 gates.
Each scenario uses temporary configuration and ephemeral loopback listeners.
It waits for host hook completion before checking socket silence; public
resume intent is not treated as an idle publication facility.

The isolated Rhino snapshot is `/tmp/spider-h1-lifecycle.Fsa0XT`. It contains
`build.log`, `ctest-regression.log`, `clean-room-repeat.log`, `h1-focused.log`,
`api-check.log`, and `h1-e2e.log`. The first standard regression run passed
111/112 gates; the clean-room gate lacked a requirements file omitted from the
snapshot. After copying the unchanged `deploy/requirements-addon.txt`, that
gate passed. All 24 focused H1/corpus/clean-room checks and the generated API
consistency check also passed. Those initial live acceptance failures were resolved as described above.

Final logs in the same snapshot are `smithproxy/h1-unit-final.log`,
`smithproxy/h1-transport-regression.log`, `spider-final-regression.log`,
`h1-webhook-test.log`, and `h1-e2e-final.log`.
