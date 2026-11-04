# TLS hook inventory and proposed next cut

Status: investigation only. No production code or deployment capabilities changed.
Baseline: native `bfee15f9`, Spider `7d00a03`, Socle `90f3ca5`.
Reference: mitmproxy 12.3.1, not an unpinned current API.

## Existing Spider surface

`src/addon_tls.py` supplies ClientHello parsing, ClientHelloData, TlsData and all
seven event value types. Loader/worker tests intentionally reject unsupported TLS
hook deployment. Detached values are not an implemented handshake producer.
`tests/corpus/addon_tls_transport_v12.json` records this one reference scenario:

```
tls_clienthello
  -> tls_start_server -> tls_established_server
  -> tls_start_client -> tls_established_client
```

This is not a universal order for every TLS mode or connection strategy. Keep
client/server identity consistent with the existing TCP descriptor objects.
Native SSLCom is_server means client-facing; mitmproxy's server suffix means
upstream-facing. Mapping by the SSL role name alone would invert the events.

## Candidate native boundaries

Paths below are relative to the native repository. These are candidates to
validate before implementation, not authorization to refactor TLS control flow.

| Public hook | Native candidate | Required boundary |
| --- | --- | --- |
| tls_clienthello | socle/sslcom.tpp: waiting_peer_hello and completed ClientHello parsing | Complete hello, before bypass and upstream TLS choices; partial reads must not dispatch |
| tls_start_server | socle/sslcom.tpp: upgrade_client_socket / handshake_client | Before the first upstream SSL_connect; include immediate and deferred paths |
| tls_start_client | socle/sslcom.tpp: accept_socket / handshake_server | Before the first downstream SSL_accept, including certificate-triggered startup |
| tls_established_server | immediate upstream completion and handshake success | After upstream handshake and applicable native verification decision, before dependent client-side activity |
| tls_established_client | immediate accept_socket success and resumed handshake success | Before decrypted application bytes reach content hooks |
| tls_failed_server / tls_failed_client | terminal handshake error/timeout paths | Once for the affected TLS layer, with error metadata; WANT_READ/WANT_WRITE are not failures |

The existing MitmProxy::observe_readiness is useful for sampling readiness but
is insufficient for all seven events. It cannot emit a before-handshake event
or reliably recover transitions completed inside one nested COM call.

A concrete ordering trap: SSLMitmCom::check_cert can initialize the client-facing
SSL object and resume its delayed accept while the upstream handshake call is
still on the stack. Emitting upstream establishment only after that call returns
may place it after downstream start/completion. Also, resumed handshake sets
sslcom_status(true) before check_cert returns; that assignment alone is not an
accepted-session notification boundary. Audit fast paths and certificate-cache
shortcuts alongside this path. Do not change verification policy to fit hooks.

## Compatibility boundary that must remain explicit

Pinned upstream source:
https://github.com/mitmproxy/mitmproxy/blob/v12.3.1/mitmproxy/proxy/layers/tls.py

`tls_start_*` lets addons supply a live `TlsData.ssl_conn`, which the TLS layer
then consumes. Established/failed data also exposes the SSL object. Our worker
cannot receive the native process's OpenSSL object through JSON. Sending null
and silently accepting arbitrary TLS addons would overstate compatibility.

ClientHelloData also has effective decisions (`ignore_connection` and
`establish_server_tls_first`). Recognizing their names or changing a detached
value is insufficient: native bypass/ordering must actually honor them, or the
unsupported operation must be rejected explicitly. Existing native policy must
retain authority. The reference corpus alone does not prove these mutations.

## Recommended next patch

Start with a small native TLS observation boundary, covering establishment and
failure on each side. Keep it internal until producer/worker semantics and
supported data access are specified; do not advertise full mitmproxy TLS support.
If small generic COM notifications are required, put only transport facts there.
ProxyHooks owns message construction, exchange and response interpretation;
Smithproxy must not reproduce handshake scheduling or certificate policy.
Use CxMap bookkeeping keyed to a TLS instance, including STARTTLS replacement.
Do not add reconnect behavior or a second handshake state machine.

Then bridge the explicitly supported observation subset to Spider. Treat
ClientHello decisions and start-hook SSL ownership as a separate design cut;
never silently ignore unsupported mutations or imply an interchangeable SSL API.

Tests before enabling any subset: fragmented ClientHello, immediate/deferred
handshake completion, TLS1.2/1.3, verification failure, peer rejection, timeout,
STARTTLS, exactly-once delivery, metadata/identity, and no application callback
before establishment. Compare both-side ordering to fresh pinned reference runs,
including certificate/cache variants and error paths. Keep native CONNECT/AAA
and existing server hook tests as regressions. QUIC/DTLS and reconnect remain out
of scope for this cut.

## Outcome producer follow-up

The outcome-only native/Spider patch is described in [TLS_LIFECYCLE_PRODUCER.md](TLS_LIFECYCLE_PRODUCER.md). It enables established/failed observations with explicit SSL-object and history-overflow limits; start/ClientHello interception remains separate.

The follow-up ClientHello wire patch is documented in
[CLIENTHELLO_PRODUCER.md](CLIENTHELLO_PRODUCER.md). It adds an explicit deployment
subscription, parsed ClientHello, termination and native bypass. TLS-start
SSL ownership and handshake-order overrides remain unsupported.
