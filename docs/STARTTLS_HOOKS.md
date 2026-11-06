# STARTTLS lifecycle extension

This is a Smithproxy/Spider extension. It specifies our plaintext-to-TLS upgrade
contract using the existing connection and TLS hook vocabulary; it is not a claim
of reference mitmproxy STARTTLS behavior. Native signature detection, TLS policy
and handshake scheduling remain authoritative.

## One TCP connection, a new TLS layer

A recognized STARTTLS exchange replaces the COM transport on the existing host
contexts. Socket descriptors, the native connection ID, and Spider's Client and
Server objects retain their identities. The upgrade does not emit a second
`client_connected`, `server_connect` or `server_connected`. TCP setup timestamps
remain the timestamps of the original connection.

Each leg receives a TLS attempt identity. The two legs need not have equal
attempt numbers. ClientHello, start and outcome for a given leg refer to that
leg's attempt. Never compare TLS attempt numbers with TCP attempt numbers.

Successful upgrade has this partial ordering:

```text
client_connected
  server_connect -> server_connected
  plaintext protocol negotiation and upgrade acceptance
  TLS callbacks on the existing descriptors:
    client: ClientHello -> start_client -> established_client
    server:                start_server -> established_server
  protected application bytes
  server_disconnected -> client_disconnected
```

This diagram specifies per-leg dependencies, not a universal cross-leg order.
Upstream completion can trigger client-facing TLS within a native call; sampling
and callback nesting determine the interleaving. An observable failed attempt has a failed
outcome instead of establishment; later application I/O failure does not rewrite
an already successful handshake as a failed handshake. Events require an actual
native observation, not a guessed transition based on plaintext payload. A failure
before a TLS attempt can be observed must not manufacture a TLS start or outcome.

## Deployment and content

Use a content/flow mitmproxy addon and opt into the desired `tls_clienthello`,
`tls_start_server` and `tls_start_client` options before opening the connection.
Replacement COM objects inherit that opt-in. Defining a hook alone does not
subscribe it. All mutation, veto and strict/fail-open rules from
[TLS controls](TLS_UPSTREAM_OPTIONS.md) still apply.

A lifecycle-only addon may leave non-HTTP plaintext unchanged while observing
TLS hooks. Spider must not send an opaque SMTP greeting to its H2 translator.
This does not add SMTP/IMAP/FTP parsers or claim arbitrary `tcp_message` support:
raw content hooks still require the native raw-transport producer contract.
If an addon dynamically registers content hooks, the normal content adapter
requirements apply to subsequent callbacks. This extension does not replay
plaintext already forwarded before registration.

A [complete observer example](../examples/hooks/starttls.py) is also available
in the built-in editor help. It keeps no global per-connection state and can
observe concurrent sessions.

## Validation

The live test uses the existing native signature-suite dialogs: SMTP, IMAP,
POP3, FTP, XMPP and HTTP-proxy upgrade. The last is a native signature test,
not support for the separate `http_connect_upstream` addon hook.

```sh
python3 tests/connect_proxy_integration.py --starttls-only \
  --proxy /path/to/smithproxy --spider /path/to/smithproxy-spider \
  --native-source /path/to/smithproxy-source \
  --fixture /path/to/smithproxy-source/etc/smithproxy.cfg
```

It starts disposable local listeners and uses policy DNAT, without changing host
firewall rules. Each dialog runs with TLS 1.2 and TLS 1.3. It checks real encrypted application exchange, retained addon
object identities, one TCP lifecycle, per-leg TLS start/outcome identity and
terminal retirement. The fixture relaxes certificate checks for its disposable
self-signed origin; this is not a production trust configuration or coverage of
certificate rejection. Error/timeout and resumption cases are separate gates.

## Observed success sequence

In the six-dialog TLS 1.2/1.3 integration matrix, each successful upgrade emitted:

```text
tls_clienthello -> tls_start_server -> tls_established_server
                -> tls_start_client -> tls_established_client
```

This records the tested native path; the partial-order contract above remains
binding rather than this incidental total ordering. Both established observations
preceded protected application-content delivery. TLS identities were stable per
leg; the original TCP identity and setup timestamp survived the upgrade.

The initial probe exposed an adapter bug: an opaque plaintext greeting entered
H2 translation and invalidated the worker before TLS began. The small adapter
fix skips that path only for non-HTTP content with no currently registered
HTTP/raw content hooks. Tests also verify that dynamically adding a content hook
restores the normal producer requirements. Native COM scheduling was unchanged.

Validation on 2026-11-05: 12/12 live STARTTLS cases, 47 existing live TLS/CONNECT
scenarios, and 125/125 Spider CTest entries passed (358.06 seconds for CTest).
The final gates used disposable local listeners, not Rhino. The initial restricted
CTest invocation could not create worker IPC sockets; the complete rerun with
those permissions passed. Native production code and the tested native binary
were unchanged. Evidence and source/binary hashes are archived in the shared
workspace under `p3-runs/starttls-hooks-20261105`.

## Negative upgrade paths

Run the independent SMTP failure gate with `--starttls-failures-only`, using
otherwise the same command arguments as above. It covers rejection (454),
disconnect after acceptance (220), a truncated ClientHello, and silent upstream
handshakes both with and without a later socket wakeup.

- Rejection leaves the connection plaintext and emits no TLS events.
- Acceptance can create a native TLS attempt before a complete ClientHello
  reaches an interception point. Such an attempt may emit `tls_failed_*`
  without a preceding `tls_start_*`; no start event is invented.
- A silent upstream emits server start followed by server failure. Each leg
  has at most one failure and retains its attempt identity.
- Every case retains one TCP lifecycle, with server disconnection before
  connection stop. No failed handshake emits establishment.

The silent case requires Socle `c6175be` or later (Smithproxy `f81dbca7`).
The existing periodic timer enforces the configured handshake deadline even
without socket activity, with approximately one-second timer granularity.
It does not retry OpenSSL while waiting for that deadline.

Validation on Rhino, 2026-11-05: all five negative cases passed, alongside
12 positive STARTTLS and 47 TLS/CONNECT cases. The test waits for natural
session retirement before stopping the proxy; teardown cannot manufacture
its expected terminal events. Evidence is archived under
`p3-runs/tls-timeout-wakeup-20261105` in the shared workspace.
