# H1 suspension validation and live transport boundary

Validation date: 2026-11-01, following Spider commit `d3ec179`.

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

## Real proxy result: blocked by missing H1 reverse capability

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

All three currently fail at the first interception against Smithproxy
`192944a8` (`http1-flow-kill`), with socle `decc93fe` and lmhpp `d97ff6ae`:

```text
CommitException: HTTP/1 suspension requires hold and content-reverse support
```

Smithproxy's `MitmProxy::content_webhook()` advertises `content-reverse` only
when `flow_ctx_->can_inject()` is true. `ProtocolViews::can_inject()` requires
an active rewrite adapter, and `src/inspect/protocol_adapter.cpp` currently
registers only the HTTP/2 adapter. Thus the tested H1 callbacks advertise no
reverse capability. Spider correctly rejects suspension rather than claiming
that it can atomically publish the peer lane.

This is a producer integration gap, not a failed native lane-ordering test.
Do not report live H1 interception as supported based only on injected host
metadata or packaged-worker tests. Keep the acceptance scenarios failing until
the real producer supplies the capability; do not fake it in the test relay or
relax Spider's capability check.

A Smithproxy change needs a separately agreed contract for H1 reverse output,
including endpoint observation, request/response ordering and native ownership.
No Smithproxy source or runtime behavior was changed in this validation.

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
consistency check also passed. The three live acceptance failures remain open.
