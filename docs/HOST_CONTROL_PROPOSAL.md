# Addon host-control proposal

Status: proposal only. This document does not authorize an implementation.

## Problem

The public mitmproxy 12.3.1 `ctx.master` object exposes host-owned operations
that cannot be implemented by a generation-local Python facade alone. The first
common example is:

```python
ctx.master.shutdown()
```

An independent black-box run records that `shutdown()`:

- accepts no arguments;
- returns `None` synchronously;
- does not set `master.should_exit` before the calling synchronous callback
  returns; and
- causes the reference host to stop shortly afterwards.

The same probe establishes that `master.running` is a zero-argument method,
not a state flag, while `master.should_exit` is an `asyncio.Event`. Exposing a
worker-local lookalike would therefore be misleading: setting that event or
calling a lifecycle method must not appear to control the host unless the
worker-to-host contract actually honors it.

Calling `AddonGeneration.close()` from inside the callback would therefore be
incorrect and reentrant. Exiting the worker process would also be incorrect:
the parent would classify it as lost state, skip orderly `done()` delivery, and
report a worker failure instead of an intentional shutdown.

## Proposed generic worker contract

Add a bounded, host-neutral control channel to successful worker responses:

```json
{
  "control_requests": [
    {
      "action": "shutdown",
      "scope": "deployment",
      "reason": "addon-master-shutdown"
    }
  ]
}
```

This is not a mitmproxy-specific transport primitive. Native Spider scripts and
future scripting APIs could request the same host action through their own
public interface. The response field is accepted only from an already selected
and authenticated deployment worker; it is never copied from request data.

The initial limits would be:

- at most four requests per callback;
- action, scope, and reason must be bounded strings;
- unknown actions or scopes fail the callback before native publication;
- duplicate shutdown requests are coalesced; and
- a control request cannot carry arbitrary JSON or command arguments.

## Proposed execution order

1. `AddonMaster.shutdown()` records one pending shutdown request and returns
   `None`. It does not close the generation or mutate flow publication state.
2. The current addon callback completes normally.
3. The worker emits the request beside the normal callback result.
4. The parent validates the callback result and publishes or rejects the native
   HTTP mutation using the existing atomic path.
5. Only after that transaction settles does the deployment owner stop accepting
   new callbacks for the selected scope.
6. The owner sends the existing dedicated worker shutdown request, waits for
   `done()`, records its bounded shutdown report, and retires the pool.

This ordering preserves the current callback's atomicity and avoids starting
teardown while user code or native publication still owns state.

## Scope decision required

The reference product owns the proxy process, while Spider is an inspection
component beside Smithproxy. There is no perfectly equivalent scope:

### Deployment scope (recommended first step)

Disable and retire only the addon deployment that requested shutdown. Other
deployments and Smithproxy continue running. This is safe and useful, but is a
documented behavioral narrowing from whole-proxy shutdown.

### Spider scope

Gracefully terminate the entire Spider process. This is closer to process-level
semantics but leaves Smithproxy alive without its inspection frontend and may
affect unrelated deployments. It also needs a supervisor restart policy.

### Workspace proxy scope

Stop the Smithproxy workspace and its inspection components together. This is
the closest product-level analogue, but it crosses project and privilege
boundaries and is far too disruptive to authorize from an ordinary addon
without a separate administrative policy.

No scope should be silently selected by the facade. Until one is approved and
implemented end to end, `ctx.master.shutdown` remains absent rather than
pretending that killing a worker is compatible shutdown behavior.

## State and failure semantics

- The request is idempotent within one generation.
- A callback failure discards a shutdown request staged by that callback.
- Native publication failure takes precedence and marks the generation failed;
  cleanup then follows the existing failed-generation path.
- A successful shutdown is not counted as a script error or worker recycle.
- Requests racing with shutdown are either admitted before the deployment is
  marked retiring or rejected with one explicit `deployment_retiring` result.
- `done()` runs once. A failure in `done()` is attached to the shutdown report
  but cannot reactivate the deployment.
- Preview execution treats deployment scope as retirement of the temporary
  preview generation only.

## Required tests

1. Black-box parity for the zero-argument signature, synchronous `None` result,
   and non-reentrant state observation.
2. One request, repeated requests, and requests from nested addon objects.
3. Request followed by a normal body/header mutation on HTTP/1 and HTTP/2.
4. Request from a failing callback: no shutdown action escapes the rollback.
5. Shutdown racing with queued callbacks and connection teardown.
6. Exactly-once `done()` and exactly-once shutdown report delivery.
7. Invalid, oversized, duplicated, and forged control envelopes.
8. Packaged-worker, pool, deployment-controller, and end-to-end tests.
9. Confirmation that no worker restart occurs after intentional retirement.
10. Confirmation that unrelated deployments remain live for deployment scope.

## Future host actions

The same narrow envelope could later carry approved replay or flow-loading
requests, but those actions need separate schemas and authorization. This
proposal does not reserve a generic command tunnel and does not authorize any
other host service.
