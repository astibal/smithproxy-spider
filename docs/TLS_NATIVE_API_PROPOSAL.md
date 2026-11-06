# First-class TLS API: ClientHello review cut

Status: ClientHello approved on 2026-11-06. Follow-up patches are uncommitted for review.
ClientHello is the first review boundary. Extend other hooks only after this
shape is approved; keep the subsequent patches uncommitted for review.

## Script surface

Keep init/main/exit and the existing return-to-publish commit convention.
No second Python callback registry is introduced for native scripts.

```python
def main(api, state):
    if api.tls is not None and api.tls.event == TlsEvent.CLIENT_HELLO:
        hello = api.tls.client_hello

        original = hello.original()

        hello.sni = "origin.example"
        hello.alpn_offers = [b"h2", b"http/1.1"]
        hello.openssl_cipher_list = "ECDHE+AESGCM"

        return hello.commit()
```

To extend the original native cipher expression instead of replacing it:

```python
def main(api, state):
    if api.tls is not None and api.tls.event == TlsEvent.CLIENT_HELLO:
        hello = api.tls.client_hello
        original = hello.original()

        # This is the proxy's original OpenSSL expression, not the peer's
        # numeric cipher-suite list. Preserve it and append an exclusion.
        if original.openssl_cipher_list is not None:
            hello.openssl_cipher_list = original.openssl_cipher_list + ":!AES128"

        return hello.commit()
```

Appending OpenSSL operators does not guarantee adding usable suites: operators
can also remove them. This example adds a restriction. A missing expression
means unspecified native defaults; do not stringify None or guess a replacement.
The expression controls TLS 1.2 and earlier, not TLS 1.3 suites.

`TlsEvent` is an enum exported by the native scripting API. `api.tls` is absent
(None) for unrelated invocations. TLS metadata does not masquerade as content
bytes or editable message Parts.

Proposed ClientHello value:

- `sni`, `alpn_offers` and `openssl_cipher_list`: editable fields directly on
  the prefilled draft. No intermediate `upstream` object.
- `original()`: return the stored immutable snapshot of original input values,
  including the received hello's SNI, ALPN offers, cipher IDs and extensions.
  Nested collections must also be immutable and must not alias mutable draft
  storage. Repeated calls may return the same immutable snapshot; they need not
  copy or parse the hello again. Edits and commit never change this snapshot.
  Native policy can constrain the effective draft independently of the received
  offer. `original().openssl_cipher_list` holds the initial native expression,
  or None when unspecified. It is a native setting, not a field parsed from
  ClientHello; the original peer cipher IDs remain a separate observation.
- `decision`: enum CONTINUE, BYPASS or TERMINATE; default CONTINUE.
- `commit()`: validate and snapshot the entire draft, returning a dedicated
  result for the worker. Returning it publishes the decision. Uncommitted edits
  do not escape; later mutation cannot modify a committed result.

These are meta edits, not a claim that the original ClientHello is rewritten.
Keep native policy restrictions and existing availability behavior. Native
validation owns shared constraints; the adapter owns mitmproxy-specific defaults
and conversions (such as unspecified empty cipher lists).

## API-shaped wire

Retain the action and identity envelope. Negotiate a new payload schema rather
than silently changing the existing version-1 contract. The new body mirrors
the API tree; binary values use an explicit base64 codec at the JSON boundary.

Illustrative committed payload, inside the existing identified reply:

```json
{
  "tls": {
    "event": "client_hello",
    "client_hello": {
      "decision": "continue",
      "sni": "origin.example",
      "alpn_offers": ["aDI=", "aHR0cC8xLjE="],
      "openssl_cipher_list": "ECDHE+AESGCM"
    }
  }
}
```

The corresponding request additionally carries the immutable source data under
`original`, which backs the Python `original()` method. The committed reply
does not resend that snapshot. Enum values become
stable strings on the wire; script comparisons use enum members. ALPN keeps the
API field name and sequence shape, with each bytes value base64 encoded; it is
not the old opaque length-prefixed aggregate. Document encoding explicitly.
The schema number/capability spelling must be finalized with the implementation.

## Layer responsibilities

| Layer | ClientHello change |
| --- | --- |
| Socle | Reuse complete-hello boundary and configure_upstream_hello; no new callback, scheduling or parser duplication required for editable fields. |
| Smithproxy ProxyHooks | Encode/decode negotiated API-shaped payload, validate complete reply, convert ALPN sequence to native wire list, return existing native decision. |
| Spider shared TLS module | Decode observations into native values, own draft validation/commit and reply serialization, without importing addon modules. |
| Spider worker/Inspection | Allow native lifecycle owners as well as addons, invoke native main with api.tls, recognize committed TLS result; preserve ordering, timeouts and retirement rules. |
| mitmproxy adapter | Map shared values to ClientHelloData, translate supported mutations into the same draft and commit path; retain explicit errors for unsupported operations. |
| Editor/docs | Export enum/types, completion hints, examples, supported fields and phase restrictions. |

The existing independent received-hello parser may need to be extracted from
addon_tls.py so native values do not depend on a mitmproxy-labelled type.
Do not duplicate validation and serialization in the two scripting frontends.

## Verification plan

On Rhino: native draft/commit tests, immutable snapshots, invalid fields,
no-commit behavior, unavailable capability, mixed native/addon deployment order,
old/new wire negotiation, existing pinned addon corpus, live fragmented hello,
SNI/ALPN/cipher mutation, bypass/veto and strict/fail-open regressions. Run full
P8 before release. No local builds or test load.

Review production-only HTML and plain diff separately from tests/documentation.
After approval, extend this same model to starts/outcomes/QUIC without adding
new handshake features; prepare all patches for review without committing.

## First implementation review

The ClientHello patch now implements the surface above. The setup response
advertises `tls_clienthello_schema: 2` alongside the existing subscription.
New producers send `details.tls.schema = 2` and `details.tls.client_hello`;
old producers/receivers retain the existing version-1 wire representation.
The identity envelope is unchanged. Replies place `schema` and `client_hello`
beside the echoed envelope. The original received body is transported as
`client_hello.original.body_base64`; Spider parses it into immutable values.
The native OpenSSL expression prefills the draft and original snapshot.

Native deployments currently require flow instancing and the explicit
`tls_clienthello` deployment option. Their main function receives `api.phase`
`tls`, `api.tls`, the same session identity and state, and no content Message.
Invalid edits raise ValueError. No returned commit means no published edit.
The commit captures the settings independently of later draft mutations.

The existing restriction allowing only one enabled content deployment when an
addon is active remains unchanged. Native deployment chains are supported;
mixed native/addon deployment chains are not newly enabled by this patch.
The separate frontend paths use the same draft implementation and validation.

Socle sources and handshake scheduling are unchanged. ProxyHooks reuses its
existing offer validation and observer application path. Unchanged effective
cipher expressions do not create a new explicit override/cache partition.

The follow-up API and wire negotiation are documented in [TLS_NATIVE_API.md](TLS_NATIVE_API.md).
