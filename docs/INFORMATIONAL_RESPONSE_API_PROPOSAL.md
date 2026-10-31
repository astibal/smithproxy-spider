# Native HTTP/2 informational-response design

Status: approved and implemented as a general additive API.

## Problem

Mitmproxy 12.3.1 has two connected HTTP/2 behaviors that Spider cannot safely
reproduce with header drafts alone:

1. a request carrying `Expect: 100-continue` receives a local `100` before its
   body is sent, and the expectation is not forwarded upstream;
2. informational responses received from upstream are consumed without being
   published to the client or exposed as ordinary response hooks.

Suppressing upstream 1xx headers without first creating the local continue
would deadlock a client that waits for `100` before sending the retained body.
Publishing a local header block from the adapter would bypass native HPACK,
ordering and checkpoint ownership. The operations therefore belong in native
Translate, while the compatibility policy remains in the addon adapter.

The black-box contract is recorded by `tests/probes/h2_expect_probe.py` and the
checked corpora `addon_h2_expect_v12.json` and
`addon_h2_expect_matrix_v12.json`. Exactly one case-insensitive
`100-continue` value triggers the local response and is removed before the
completed request hook and upstream publication. Duplicate or other values are
left intact and do not trigger a continue. A valid expectation still triggers
for a zero-length, already-ended request. In every case, upstream `103` and
`100` are hidden and response hooks observe only the final `200`.

## Native operations

### Emit an informational response

```python
api.connection.http2.emit_informational_response(
    request_headers,
    status=100,
    headers=(),
)
```

The anchor is a complete callback-local initial request HEADERS Part. The
operation emits one response HEADERS block in the reverse direction without
`END_STREAM`. It accepts statuses `100..199` except `101`, ordered byte header
pairs, and no body or trailers. It returns the selected stream ID.

This operation does not inspect or remove `Expect`; the caller edits the
request headers through the existing draft API. It is useful outside the
compatibility adapter for any protocol policy that needs a bounded local 1xx
response.

### Suppress an informational response

```python
api.connection.http2.suppress_informational_response(response_headers)
```

The anchor is a complete callback-local response HEADERS Part whose original
status is `100..199` except `101` and which does not carry `END_STREAM`. The
operation consumes the source header block without publishing it and returns
the selected stream ID. The original classification is authoritative: editing
a final status into 1xx cannot make it suppressible.

The two operations are deliberately separate. Emission is a reverse-output
policy attached to a request; suppression is a source-consumption policy
attached to an observed response. Combining them would falsely require every
suppressed 1xx to correspond to a locally emitted one.

## Native semantics

Both operations are staged until `api.message.translate()` succeeds. On
successful publication, native Translate must:

- advance the source HPACK decoder for suppressed headers but not the
  client-facing encoder;
- encode emitted headers only through the client-facing HPACK encoder;
- retain the request stream and both directions' ordinary flow-control state;
- preserve header-block ordering against queued response headers and DATA;
- publish reverse output and both HPACK checkpoints atomically;
- reject duplicate emission or suppression for the same callback anchor;
- preserve multiplexed siblings and permit a later final response;
- roll back completely on validation, quota or serialization failure.

Informational HEADERS carry no DATA and consume no body window. They still
participate in connection output ordering and HPACK state, so neither operation
may be implemented as raw frame injection or byte deletion in the adapter.

## Adapter policy

For an H2 request with exactly one original `Expect` field whose value equals
`100-continue` case-insensitively, the compatibility driver:

1. dispatch `requestheaders` with the expectation still visible;
2. if the addon leaves the request active, remove `Expect` from the native
   request draft;
3. stage local status `100` through `emit_informational_response()`;
4. keep the final request hook waiting for the complete native body.

Every valid upstream informational response is staged through
`suppress_informational_response()` and does not create `responseheaders` or
`response`. Final-response processing remains unchanged.

Duplicate or non-matching values remain visible to the completed request hook
and are forwarded unchanged. The adapter must not emit a continue after the addon creates a local final
response, terminates the request, or removes/replaces the request in a way that
makes the original request unpublishable.

## Risks

- **Deadlock:** suppressing 1xx without a local continue can leave a waiting
  client and retained request body blocked forever.
- **HPACK divergence:** skipping source decode or advancing the destination
  encoder for an unpublished block corrupts later header blocks.
- **Wrong ordering:** reverse `100` must precede final response output but must
  not overtake older response traffic on another queued stream incorrectly.
- **Duplicate policy:** fragmented callbacks and worker retries must not emit a
  second continue.
- **Control conflicts:** local final responses, termination, GOAWAY and reset
  must have explicit precedence over an informational response.
- **Admission:** a waiting request body still needs the existing bounded body
  reservation and input-credit policy; the new API must not enlarge quotas.

## Required evidence

- checked mitmproxy 12.3.1 corpus for exact, mixed-case, duplicate, invalid
  and absent `Expect`, with and without a body;
- every split of request and informational HEADERS/CONTINUATION input;
- local `100` before body admission with one-byte fragmented DATA;
- source and destination HPACK dynamic-table continuity after suppression;
- multiplexed final responses while another stream waits for continue;
- final response, local response, kill, reset and GOAWAY races;
- output quota and malformed-anchor rollback;
- packaged-worker and production C++ checkpoint-boundary tests;
- independent TLS/ALPN client and origin wire probe.

## Verification

The native Translate suite covers both Easy and Expert safety modes. It tests
every informational request-header split, every upstream informational-response
split, multiplexed stream identity, source and destination HPACK continuity,
control-operation conflicts, final-response ordering, reset and GOAWAY races,
and atomic rollback after aggregate reverse-output quota failure. The complete
suite passes **190/190**; the compatibility Parts suite passes **113/113**.

`tests/probes/h2_informational_native_probe.py` is the independent wire check.
It negotiates H2 over TLS on both sides of the production Translate bridge. A
client waits for the locally generated `100`, sends its body, and receives only
the final `200`; the origin receives the body without `Expect`, while its `103`
is consumed before downstream publication. The probe has no mitmproxy import or
runtime dependency. Run it with a disposable certificate:

```sh
python3 tests/probes/h2_informational_native_probe.py \
  --certificate /path/to/cert.pem \
  --private-key /path/to/key.pem
```

## Implemented boundary

The approval authorized only the two additive
`ConnectionHttp2` operations and their Spider-owned Translate implementation.
It does not authorize Smithproxy changes, HTTP/1 behavior changes, new body
limits, automatic streaming, destination rerouting, or adapter-owned frame
construction.
