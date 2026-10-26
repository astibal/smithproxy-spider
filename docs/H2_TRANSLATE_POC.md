# H2 translate: isolated proof of concept

> Subsequent live integration is described in [H2_TRANSLATE_LIVE.md](H2_TRANSLATE_LIVE.md).
> This document preserves the scope of the original isolated experiment.

**Experiment, not a public production API.** `tools/h2_translate_poc.py` is not
included in the worker or editor schema. It adds the `python-hpack` test dependency;
the system nghttp2 library provides an independent receiving decoder in tests.

## Experimental contract

One `TranslateConnection` represents one new connection starting with its first
HPACK block, not one H2 stream. Each direction has an input Decoder and output
Encoder. The input table sees original headers; the output table sees modified
headers. A later original index may therefore become another index or literal.

Scripts must explicitly return `api.message.translate()`. Plain `commit()`,
`return None` or discarding the result is an error. No hidden translation runs
after the callback; the next callback must explicitly translate again. Working
tables are published only after successful script return. Failure marks the
experimental connection unusable. This is **not** production drop or strict-handshake
implementation.

```python
def script(api):
    for part in api.message.parts:
        if part.headers is not None:
            part.headers.set_header(b"x-lab", b"changed")
    return api.message.translate()
```

The next callback needs no further edit, but still needs translation:

```python
def script(api):
    return api.message.translate()
```

## Deliberately narrow scope

- Flow instancing only, complete annotated blocks in the current callback.
- HEADERS + CONTINUATION, logical byte-valued headers and Huffman.
- The output encoder owns indexing. `never` preserves never-indexed semantics;
  draft `without`/`incremental` do not select the output HPACK strategy here.
- DATA/control frames remain byte-for-byte; edits are rejected.
- Explicit indexes, raw HPACK, Parts-list changes, hold, Opaque, SETTINGS and
  orphan CONTINUATION are rejected, not silently ignored.
- Default 4096 B tables, without SETTINGS/ACK negotiation. This is not a complete
  H2 state machine or flow-control translator. PUSH_PROMISE is not independently
  certified by this POC's tests.
- No activation on an already running or partially captured connection. The
  harness caller must supply every callback in order; arbitrary omitted input
  cannot be detected.

## Running

```sh
python3 tests/inspection_translate_poc_test.py
cmake -S . -B build -DSPIDER_TEST_TRANSLATE_POC=ON
ctest --test-dir build --output-on-failure -R inspection_translate_poc
```

Tests cover an edited insertion followed by an original index across streams and
callbacks, multiple blocks per callback, L/R and independent connections, 200
deterministic messages with eviction/repeated indexes, CONTINUATION and larger
output, unchanged DATA/PING, mandatory explicit calls and atomic failure.

Verification on 2026-10-25: the expanded 13-test harness passed; the full suite
including the experiment passed 23/23 (27.89 s). A negative control demonstrates
that without translation a later original index returns the wrong value. This
is an in-process experiment with trusted scripts, not a sandboxed worker or a
production latency measurement. State copying provides simple transactions here.

At the time of this experiment, live deployment still required strict activation
confirmation, production state placement/lifetime, worker protocol, HPACK/SETTINGS,
hold/reassembly, resource limits and deployment-change behavior. The experiment
does not switch or modify existing rewrite behavior.
