# Proxy authentication hooks

Authentication is enabled independently by `settings.socks.proxy_authorization`
and `settings.http_connect.proxy_authorization`, both defaulting to false.
`--comm-auth` only selects the AAA broker socket. The per-protocol switches are
the current configuration boundary; per-policy profiles remain future work.

Smithproxy owns protocol negotiation, AAA verification, target setup and wire
responses. When a protocol requires authentication,
`--comm-auth /path/to/auth.sock` selects the external AAA/PAM daemon that verifies
its submitted credentials. A missing or unavailable broker denies access. If its
webhook is enabled, it then sends a transient `proxy-authentication` event to
Spider. No credentials enter captured traffic or inspection diagnostics.

The acceptance rule is `AAA accepted AND every enabled observer accepted`.
Timeout, worker failure, malformed output and concurrent deployment replacement
deny the exchange. Disabling the webhook restores direct AAA behavior. A missing
or malformed HTTP Basic header is challenged by Smithproxy before this callback;
the hook runs when credentials are available for verification.

## Deployment

Select **Proxy authentication**, **All**, **Per message**, with no traffic filter.
Choose either the native Spider API or mitmproxy API. This is a separate
deployment from a content addon. A persistent addon generation runs `load`,
`configure`, `running`, the authentication callbacks and `done`; its module
state persists between authentication attempts. Each attempt has fresh connection
and flow descriptors. They are not identities shared with tunneled content.
Network access remains an explicit `network_enabled` grant, disabled by default.

An API deployment uses these fields (enable the returned deployment ID separately):

```json
{
  "operation": "deploy",
  "revision": 0,
  "name": "Proxy policy",
  "hook": "authentication",
  "scope": "all",
  "instancing": "message",
  "script_api": "mitmproxy",
  "script": "#!mitmproxy\ndef socks5_auth(data):\n    data.valid = data.valid and data.username != 'blocked'"
}
```

Supply the current revision from `/api/inspection` instead of the example zero.
An addon containing only one of the two hooks leaves the other protocol's AAA
result unchanged. Content-only hooks and later CONNECT lifecycle hooks are
rejected during authentication generation startup.

```python
#!mitmproxy
from mitmproxy import http


def socks5_auth(data):
    # valid starts with the AAA result; True cannot upgrade a failed result.
    data.valid = data.valid and data.username != "blocked"


def http_connect(flow):
    # This pre-target flow contains the actual CONNECT request and destination.
    if flow.request.host == "blocked.example":
        flow.response = http.Response.make(403, b"policy veto")
```

## Compatibility boundary

- `socks5_auth(data)` receives the submitted credentials, client peer and initial
  AAA decision in `data.valid`. The final value must remain a boolean.
- `http_connect(flow)` receives real request headers, authority, version and
  requested destination. No socket to the target has been opened yet. Unknown
  local socket and server peer metadata remain `None`.
- Accepted AAA removes `Proxy-Authorization` from the addon request and supplies
  `flow.metadata['proxyauth'] = (username, password)`, matching the ordering in
  the recorded mitmproxy 12.3.1 proxy-authentication corpus. Failed AAA retains
  the header and presents a 407 response (503 for unavailable AAA).
- `flow.metadata['smithproxy_auth']` exposes status, verified identity and groups.
  These values are observations; changing them does not change AAA.
- A non-2xx response or killed flow is a veto. Smithproxy sends its own HTTP 407
  or SOCKS5 failure. Addon status, body and headers are **not** a wire replacement.
  A 2xx response or cleared failed-AAA response cannot override failed AAA.
- CONNECT routing changes and interception are unsupported and fail closed.
  Request header edits are local observations only; CONNECT headers never enter
  the tunnel. `http_connected`, `http_connect_error`, upstream proxy hooks and
  arbitrary CONNECT response transport remain outside this authentication hook.
- Older producers without the optional `http_connect` context still support
  native policies and SOCKS5 addons. HTTP authentication addons fail closed
  without that context. The producer sends bounded base64 request bytes plus
  the parsed destination, preserving actual headers rather than inventing them.
- Script prints, exception text and cleanup output are suppressed for
  authentication workers. Scripts are administrator-owned and may retain their
  own state; the runtime does not promise to erase arbitrary addon variables.

## Validation and release dependency

`addon_authentication_test.py` exercises the packaged sandboxed worker, both
hook decisions, persistent state, rejected/unavailable AAA, invalid decisions,
unsupported controls, capability separation and cleanup redaction.
`authentication_host_test.cpp` covers deployment and coexistence with content
addons. `authentication_proxy_integration.py` drives a real temporary PAM
broker, HTTP CONNECT, SOCKS5 and Spider, including native and addon policies,
wire vetoes, error paths, timeout and unavailable webhook behavior.

Validation on Rhino (2026-11-02): both full builds passed, all 14 selected
Spider CTests and all 5 selected native CTests passed, and the live integration
completed successfully for native and addon policies. This is targeted
regression evidence, not a new claim that every compatibility gate is closed.

The native producer is developed on Smithproxy **`new-AAA`**. There is an explicit
commitment to merge it into the intended **`main` and `master`** release branches
in the future. Spider's `mitmproxy-api` integration must retain this dependency.
Do not claim the feature is available on those release branches until the merges
and cross-project integration tests have actually completed.
