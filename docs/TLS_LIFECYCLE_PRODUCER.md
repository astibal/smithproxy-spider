# Native TLS outcome observations

This contract covers TCP TLS in Smithproxy `proxy-hooks`, using Socle's bounded
protocol-state history (`a57b195`). It does not alter TLS scheduling or verification.

## Supported events

Spider advertises `control.tls_lifecycle = 1` after a successful addon setup.
Smithproxy sends synchronous `tls-lifecycle` observations to that setup's owners:

- `tls_established_server` and `tls_established_client`;
- `tls_failed_server` and `tls_failed_client`.

`client` is the client-facing leg; `server` is the upstream leg. This is not the
local OpenSSL role. Each native COM/socket instance receives an attempt identity
and at most one outcome per leg. A later TLS I/O error does not change an accepted
handshake into a failed handshake. STARTTLS can introduce a new COM instance on
an existing connection; in-place renegotiation and reconnect redesign are outside
this contract.

The native observer samples both legs before application-byte processing and
again at socket events and retirement. If both outcomes become visible together,
the upstream observation is delivered first. This preserves observation order at
these boundaries, not an exact timeline of transitions inside a COM call.

The 32-entry history suppresses adjacent duplicates and is cleared after sampling.
If it overflows, native code logs the gap and will not infer a failed handshake
from an incomplete history. Recorded/current `established` remains positive
evidence of success. The observer does not synthesize an outcome for an ambiguous
gap. This is a bounded observation contract, not a lossless event stream.

## Envelope and metadata

`details.tls.envelope` contains `version: 1`, `connection_id`, a positive
`attempt`, `side` (`client` or `server`) and `event` (`established` or `failed`).
The response echoes the envelope with `action: tls-lifecycle`, `id`, and a boolean
`proceed`. Invalid/unavailable replies are fail-open unless strict control was
already negotiated. A valid addon error on an established connection may veto it.

Available connection values are SNI, negotiated ALPN (base64 on the wire), cipher,
TLS version and the public peer certificate chain (PEM on the wire). Descriptors
are shared with HTTP and server lifecycle hooks. `timestamp_tls_setup` is the
worker's observation time, not a native high-resolution handshake timestamp.
After a successful handshake without ALPN selection, `conn.alpn` is `b""`; before
a known outcome it remains `None`.
Failure diagnostics are currently the generic `TLS handshake failed`; OpenSSL's
error queue is not drained or consumed by observation.

A successful TLS handshake is distinct from later HTTP replacement or certificate
policy handling. These hooks do not override native verification decisions.

## Explicit compatibility boundaries

`TlsData.ssl_conn` is an unsupported-operation sentinel, not a live PyOpenSSL
connection and not a fake null success. Accessing OpenSSL methods or replacing it
fails the addon callback explicitly. Certificate values are available through
`data.conn.certificate_list`. Certificate/client key configuration, raw SSL I/O,
context layers, precise handshake timestamps and offered cipher/ALPN inventories
are not supplied by this outcome-only transport contract.

`tls_start_*` and `tls_clienthello` remain rejected at deployment: their mutation
semantics need a separate pre-handshake control contract. DTLS and QUIC are not
mapped onto these TCP TLS outcomes. A plain HTTP CONNECT tunnel does not terminate
TLS and therefore must not generate native TLS outcome hooks.

## Validation

`addon_tls_native_test.py` checks shared descriptors, once-only delivery, failures,
explicit SSL limitations, malformed metadata and the established-event subset of
the pinned mitmproxy 12.3.1 corpus. The CONNECT integration fixture also runs real
transparent TLS inspection with policy DNAT, TLS 1.2/1.3 and fragmented ClientHello,
then verifies upstream/client handshake failures and the existing CONNECT cases.
The fixture uses disposable certificates and runs on Rhino in an isolated network
namespace. It does not install host firewall rules.

## Reference failure behavior

A live black-box run against mitmproxy 12.3.1 is retained in
`tests/corpus/addon_tls_failures_v12.json` and reproducible with
`tests/probes/addon_tls_failure_probe.py`. For an upstream TLS failure, the
reference can complete client TLS and then return an HTTP error. Socle may fail
both TLS legs instead. The producer reports Socle's actual outcomes and does not
imitate a successful client handshake that never happened. For a client trust
failure after successful upstream TLS, the reference observes server established
then client failed, as does this integration. These are native transport behavior
differences, not an assertion of complete mitmproxy transport parity.
