# Native TCP server lifecycle

Status: review patch on `proxy-hooks`, dependent on the shared authentication
hook extraction. No merge or publication is included in this review.

A successful addon setup reply advertises `control.server_lifecycle = 1`.
Smithproxy sends these events only after that capability was negotiated, so an
older receiver's strict content policy does not suddenly require a new API.
This is protocol capability negotiation, not a per-hook subscription map.

Smithproxy remains the owner of sockets and policy. `ProxyHooks::server` sends a
synchronous `server-lifecycle` exchange with a version-1 envelope containing the
native connection ID, a monotonically increasing attempt ID and one event:

- `connect`: target selected, before calling the transport's connect;
- `connected`: TCP completion, independently of TLS readiness;
- `error`: an attempt that did not complete, including a valid addon veto;
- `disconnected`: an established transport closed or its session is retiring.

`connect` has exactly one outcome: `error`, or `connected` followed by
`disconnected`. Shutdown and destruction share terminal bookkeeping. The legacy permanent-context reconnect path is unchanged and is outside this
producer contract. UDP and QUIC do not produce these
TCP observations. TLS lifecycle hooks remain separate work.

The message also carries the target and actual socket endpoints. Unknown
endpoints remain null. Terminal observations indicate when the client transport
has already closed via `client_closed`. A separate `session_ending` flag marks
logical session retirement before the original native shutdown path runs. It is
valid only for terminal events. Spider closes its logical descriptors for this
notification; Smithproxy does not close any socket just to produce a hook.
The final client timestamp is still assigned by client teardown.

## Spider mapping

Only existing setup owners receive the observation. The host preserves each
runtime's serial boundary and checks generation ownership before and after
worker execution. A redeployment cannot adopt an existing native connection. Losing the setup
owner is reported as unavailability, so strict mode cannot treat it as success.
The callback exchange is transient and does not enter capture history.

The adapter maps the four events to `server_connect`, `server_connected`,
`server_connect_error` and `server_disconnected`. It reuses the Client and Server
objects already attached to CONNECT and HTTP flows. A reconnect replaces only
the Server object. Duplicate, overlapping and out-of-order observations fail the
addon generation instead of replaying callbacks.

For regular HTTP/1 CONNECT the success ordering is:

```
client_connected -> http_connect -> connection-start/setup
                 -> server_connect -> server_connected -> http_connected
```

A transport error produces `server_connect_error` before `http_connect_error`.
Local CONNECT responses and an early CONNECT kill do not invent a server
attempt. Existing HTTP CONNECT response mutation and framing remain unchanged.

## Decisions and limits

A valid `data.server.error` veto prevents the native connect. The native error
outcome cannot become success by clearing that field. Observer failure remains
fail-open in regular mode; negotiated strict mode stops on an unavailable or
invalid observer response. Native authentication and access policy remain
independently authoritative.

Changing `server.address` is not implemented at this boundary: the adapter
restores the observed address and returns an explicit veto so the proxy does
not silently contact the original target. Policy-aware destination routing is
separate work. This is lifecycle observation and error-veto support, not a claim
that every mutable Server property controls the native transport.

## Validation

The adapter test compares public hook order, state, identity and timestamp
presence with the checked mitmproxy 12.3.1 connection lifecycle corpus. Additional
cases cover failed attempts, reconnect descriptor identity, veto, unsupported
reroute and invalid ordering. Live CONNECT integration checks transport/hook
ordering, native veto, same-object identity, exactly-once terminal delivery and
preservation of the existing CONNECT/AAA scenarios. Test counts and the final
Rhino regression evidence are recorded with the review patches.

## Closed implementation checkpoint

The agreed TCP scope was approved and pushed to `proxy-hooks`: native auth
extraction `b8a42c00`, native producer `bfee15f9`, Spider bridge `7d00a03`.
This closes that implementation scope, not all connection/TLS compatibility.
These branches have not yet been merged into native master / Spider mitmproxy-api.

Final evidence: native build and 20 live CONNECT/server scenarios passed;
real PAM HTTP/SOCKS authentication passed. Native CTest initially passed 45/46:
the PCAP logger temporary-directory cleanup failed, then the isolated full
unit.core rerun passed. Unchanged Spider code passed all 122 CTest entries,
including seven lifecycle adapter cases. No Full P3 rerun is claimed for the
final removal of reconnect integration.

Next: `TLS_HOOKS_INVENTORY.md`. Reconnect work is explicitly deferred beyond
the near-term plan.
