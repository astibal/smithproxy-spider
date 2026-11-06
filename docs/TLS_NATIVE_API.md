# Native TLS and QUIC metadata API

Native scripts keep `init(api, state)`, `main(api, state)` and `exit(api, state)`.
An opted-in session notification invokes the same main function and opaque state.
`api.phase` is `tls`, `api.message` is None, and `api.tls` contains:

| Field | Meaning |
| --- | --- |
| event | TlsEvent.CLIENT_HELLO, START, ESTABLISHED or FAILED |
| side | TlsSide.CLIENT (client-facing) or SERVER (upstream-facing) |
| transport | TlsTransport.TLS (TCP TLS) or QUIC (parent transport) |
| attempt | Native attempt identity; independent on each side |
| client_hello | ClientHelloDraft for CLIENT_HELLO, otherwise None |
| start | TlsStartDraft or QuicStartDraft for START, otherwise None |
| outcome | OutcomeDraft for ESTABLISHED/FAILED, otherwise None |

The side names describe proxy legs, not OpenSSL client/server roles. QUIC
parent callbacks do not turn HTTP/3 stream content into TLS messages.

## Subscription and ownership

Native subscriptions require `hook: content` and `instancing: flow`.
Deployment booleans are `tls_clienthello`, `tls_start_server`, `tls_start_client`,
`tls_lifecycle` (established/failed on either TCP TLS leg), and
`quic_start_server` (QUIC upstream start and both-side outcomes).
All native subscriptions default off. Addons retain automatic TLS outcomes and
explicit interception subscriptions. Only a deployment that completed setup
owns later events; redeployment cannot adopt a live session. Duplicate or stale
attempts cannot replay user code. STARTTLS keeps separate native attempts.

## Drafts and publication

Edit fields directly and return `draft.commit()`. Merely calling commit without
returning its result publishes nothing. A result snapshots the values; later
edits cannot change it. Foreign or superseded commit objects are rejected.
`original()` returns the same deeply immutable snapshot on repeated calls.
These operations edit metadata, not TLS records, scheduling or native policy.

- ClientHello: existing SNI, offered ALPN and OpenSSL TLS <=1.2 expression;
  CONTINUE, BYPASS or TERMINATE.
- TCP upstream start: SNI, subset/order of native ALPN offers and OpenSSL TLS
  <=1.2 expression; CONTINUE or TERMINATE. Native scripts may explicitly clear
  ALPN; the addon adapter retains mitmproxy's empty-as-unspecified convention.
- TCP client-facing start: native settings are observational; CONTINUE or
  TERMINATE is supported, changing the settings is rejected.
- QUIC upstream start: SNI, exactly one ASCII ALPN offer, and
  `openssl_ciphersuites` (TLS 1.3 expression); CONTINUE or TERMINATE. None keeps
  native defaults; an empty expression remains an explicit empty expression.
- Established: immutable facts plus CONTINUE/TERMINATE. Failed: immutable facts
  and CONTINUE only; acknowledging a failure cannot make the handshake succeed.

Outcomes expose sni, alpn (bytes or None), cipher, tls_version, error and
certificates (tuple of public PEM bytes). PEM framing/base64 is checked;
native snapshots do not instantiate or validate an X509 object. The adapter
parses its own Cert facade. Private keys and live SSL operations are not exposed.
Unknown metadata remains None; empty negotiated ALPN remains empty bytes.

```python
def main(api, state):
    tls = api.tls
    if tls is None:
        return

    if tls.event is TlsEvent.START:
        start = tls.start
        if tls.side is TlsSide.SERVER:
            start.sni = "origin.example"
            if tls.transport is TlsTransport.QUIC:
                start.openssl_ciphersuites = "TLS_AES_128_GCM_SHA256"
        return start.commit()

    if tls.event is TlsEvent.ESTABLISHED:
        outcome = tls.outcome
        api.print(tls.side.value, outcome.cipher, len(outcome.certificates))
        return outcome.commit()

    if tls.event is TlsEvent.FAILED:
        api.print(tls.side.value, tls.outcome.error)
```

## Wire contract

ClientHello retains `tls_clienthello_schema: 2`. The setup response negotiates
`tls_schema: 2` for other TCP TLS events and `quic_schema: 2` for QUIC.
Without negotiation, producers retain schema 1. Identity envelopes remain
version 1 and keep connection_id, attempt, side and event. Unknown schemas are
rejected. The schema converters live at the transport edges; native scripts
and mitmproxy adapters use the same draft validation and publication.

Schema 2 requests contain `schema`, `envelope`, and either `start` or `outcome`.
Start fields follow the API names: sni, alpn_offers, openssl_cipher_list for TCP
or openssl_ciphersuites for QUIC, and decision. ALPN offers are individually
base64-encoded bytes. Outcome fields also follow the API; alpn is base64 bytes
or null, certificates are public PEM strings. Replies carry the same identified
start draft, or only `outcome: {decision: "continue" | "terminate"}`. Immutable
certificate chains are not echoed. Existing strict/fail-open handling and
all-or-nothing native offer validation remain unchanged.

No Socle changes, new handshake controls, certificate injection or live SSL
ownership are part of these patches. Further capabilities remain in
[TLS_API_ROADMAP.md](TLS_API_ROADMAP.md).
