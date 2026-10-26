# TODO

## Scripting

- **Hold + fail-open (deliberately deferred):** after `need-more`, only Spider
  owns earlier bytes. Spider/proxy failure, timeout, queue overload or deployment
  changes can release the current fragment without the held prefix. Protect order
  and completeness for HOLD/REWRITE as well as TRANSLATE; retain fail-open for now.
  Design strict/drop control and data ownership recovery/acknowledgement, not just
  disk-backed buffers. Also cover disable/redeploy, filter changes, automatic
  suspension, idle expiry, limits and connection termination while holding data.
- Extend live hold from the last enabled flow deployment to any position in the
  chain; resolve prefix transactions and rollback between scripts.
- Extend H1 Parts to incomplete headers, chunked, compressed and pipelined
  messages. Add H2 frame headers split across callbacks (fewer than 9 bytes).

- Stabilize a richer, typed Python API without exposing raw webhook JSON.
- Add a browsable cookbook ranging from simple payload logging to stateful session analysis.
- Support replaying complete captured sessions through scripts.
- Add explicit script capabilities and separate observe, transform, control, and offline modes.
- Persist backend inspection deployments and traffic rules across server restarts; introduce reusable Python workers after measuring per-callback process overhead.
