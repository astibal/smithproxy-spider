# Native QUIC handshake hooks

The initial native bridge covers TCP-independent QUIC parent sessions. Enable
`quic_start_server: true` on a content deployment using the mitmproxy script API.
This reserves the parent setup, `quic_start_server`, and TLS established/failed
observations for both sides, including dynamically registered addon callbacks.
Deployments without this option retain their existing stream-only behavior.

## Supported controls

`quic_start_server` receives `QuicTlsData` with a populated `QuicTlsSettings`.
An addon can change `data.conn.sni`, the single offered ALPN protocol, and TLS 1.3
cipher suites. Spider translates cipher wire identifiers to OpenSSL names.
An empty cipher list remains empty; native OpenSSL decides whether it is valid.
Set `data.conn.error` to veto the forwarding handshake before socket creation.
Certificate verification continues to use the original native identity.

Native outcomes reuse `tls_established_client`, `tls_established_server`,
`tls_failed_client`, and `tls_failed_server`. They carry negotiated metadata and
peer certificates on the parent connection, never once per HTTP/3 stream.
Certificate-probe connections do not emit these hooks. Outcomes are sampled at
native progress/retirement boundaries, not from an OpenSSL callback.

## Explicit limits

- `quic_start_client` and QUIC `tls_clienthello` interception are not implemented.
  The listener can advance downstream TLS before it exposes a session. This
  bridge does not delay handshakes or invent a late start notification.
- Handshakes that fail before a parent setup/session is available cannot produce
  an addon outcome. Certificate-probe failures are not forwarding TLS failures.
- Certificate/key replacement, CA paths, and verification-mode changes are
  rejected explicitly by the adapter. Native trust policy remains authoritative.
- Live `ssl_conn` operations, transport replacement, and destination rerouting
  are unsupported. This is not a live aioquic/OpenSSL connection export.
- ALPN currently accepts one protocol. Both native legs must still negotiate
  compatible protocols; changing the offer does not override that validation.
- HTTP/3 stream inspection retains its existing descriptor/lifecycle model.
  Parent and stream descriptors are separate; this patch does not redesign it.

The wire action is `quic-lifecycle`, with observations in `details.quic`. Its five-field version-1 envelope is
unchanged; the QUIC action selects the QUIC adapter. Setup returns
`control.quic_lifecycle = 1` and `control.quic_start_server = 1`. Start replies
carry `upstream.sni`, `upstream.alpn`, and nullable `upstream.ciphers` (an OpenSSL
TLS 1.3 cipher expression). Later deployments in the chain see accepted changes
from earlier owners. Missing owners or worker failure remain unavailability,
with native strict/fail-open policy; an explicit veto is terminal.
