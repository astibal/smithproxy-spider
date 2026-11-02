# Addon compatibility: implementation inventory

Status: development, not a full compatibility release. Audited 2026-10-31.
Target: mitmproxy addon API major **12**. Behavioral reference: **12.3.1**.

Version target verification (2026-10-31): mitmproxy's official
[release history](https://github.com/mitmproxy/mitmproxy/blob/main/CHANGELOG.md)
lists 12.3.1 as the latest release, and the official
[addon API changelog](https://docs.mitmproxy.org/stable/addons/api-changelog/)
still identifies 12 as the latest API major. The isolated reference environment
and all checked-in black-box corpora use that exact 12.3.1 release.

The reference is used only as a black-box test oracle. The implementation is
Spider-owned Python and uses native Parts, hold, Rewrite and Translate. It does
not run a second proxy or depend on mitmproxy at runtime. Reference package
implementation sources must not be used to implement this adapter.

`COMPATIBILITY_RELEASE_GATES.md` is the concise completion ledger. It separates
implemented behavior from approval-gated native operations and producer work;
this longer document records the supporting design and test evidence.

## Read the status by layer

The public `mitmproxy.http.Message` base type is exported alongside Request and
Response. Reference object introspection confirms their shared base-class
relationship. A packaged-worker test exercises evaluated type annotations,
`isinstance`/`issubclass`, and a shared message helper whose header mutation is
verified in the emitted HTTP/2 bytes. This is the existing Spider-owned message
implementation, not a second conversion layer.

Adapter shutdown also closes the generation when a pending-flow `error` hook
raises `SystemExit` or `asyncio.CancelledError`. It runs `done` once, retires
remaining connections and retained message state, and preserves the original
abort if `done` itself aborts (the latter becomes the explicit exception cause).
Regression tests exercise both abort types across two connections and repeated
close calls. This is adapter lifecycle cleanup, not permission to resume a
generation after a fatal callback.

HTTP/2 reset handling retains the arrival order of reset frames coalesced into
one native callback. Duplicate resets deliver no second error for a released
flow. A native-Translate regression uses two multiplexed streams and reverse-order
resets, verifies callback order and confirms that retained flow/message state is
released. This does not establish complete GOAWAY or reset/reference parity.

The optional termination probe also accepts `--reset-stream --error-code N`.
Reference 12.3.1 was observed with upstream CANCEL (8), REFUSED_STREAM (7), and
unknown code 123. All three deliver `error` before the coalesced successful
response for the sibling stream. Their error strings use
`stream reset by client (CANCEL)`, `(...REFUSED_STREAM)` and `(...123)` respectively,
even though the reset in this probe comes from the upstream peer. The adapter
now preserves that compatibility wording and standard code names, deriving the
code from the complete native control Part, not by parsing another frame stream.
Tests cover every split of these reset frames and defer error delivery until
the complete payload arrives.

Only CANCEL was forwarded as a reset in these observations. REFUSED_STREAM and
123 produced synthetic 502 responses instead, with no upstream retry observed
in the bounded probe window. The adapter now makes the same decision through
the generic native `fail_reset_stream()` operation. These probes cover upstream
resets, not a complete matrix of client-initiated resets.

The H2 addon driver uses the approved native
`ConnectionHttp2.fail_pending_requests()` operation for upstream GOAWAY. Native
Translate selects requests without a final response before the control frame,
consumes GOAWAY, creates bounded 502 responses through the existing HPACK and
flow-control scheduler, and discards late source frames. Existing completed
responses remain intact. Repeated GOAWAY cannot duplicate error delivery, and
every two-fragment split delays notification until the control payload is
complete. The operation remains atomic across malformed input and fan-out quota
failure.

HTTP/2 server push is deliberately not presented as an addon HTTP flow. The
target mitmproxy 12 protocol contract does not advertise PUSH_PROMISE support;
that support was removed in mitmproxy 7. A native PUSH_PROMISE observed on an
existing connection therefore remains native pass-through data and does not
invent a request callback or a second `HTTPFlow`. A regression verifies that it
neither disturbs the parent stream nor changes its request/response lifecycle.

The optional `tests/probes/h2_goaway_probe.py` loopback probe established the
reference 12.3.1 contract (2026-10-30). With two complete GET
requests on streams 1 and 3, an origin sends a final response for stream 1,
followed by GOAWAY with last-stream ID 1. For both NO_ERROR and PROTOCOL_ERROR,
the reference calls `error` for stream 3 before `response` for stream 1 and
sends a synthetic HTTP 502 for stream 3. With `--leave-first-pending`, NO_ERROR
also fails stream 1, despite its ID being within the accepted range. Both error
hooks carry the connection-termination reason, including the GOAWAY error code.
No new upstream connection was observed during the four-second retry window.
Every synthetic 502 response ends its selected stream, while the reference
does not forward a connection-level GOAWAY to the client. A final response for
stream 1 sent by the origin shortly *after* GOAWAY is not accepted: the
reference has already failed both streams. With reference request streaming
enabled, GOAWAY during an incomplete POST body produces `requestheaders` and
`error`, but no completed `request` hook for that stream; both client streams
still receive complete 502 responses. Sending the remaining request DATA after
that response produces no reset, second hook or client connection termination;
the reference consumes it without forwarding it upstream. A `103 Early Hints`
response immediately before GOAWAY produces neither a response hook nor client
informational headers; both streams receive the same terminal 502. The checked
matrix records
response-before-GOAWAY, pending, and response-after-GOAWAY against both
NO_ERROR and PROTOCOL_ERROR, pending GOAWAY with unknown code 123, plus the
incomplete POST case. Two additional corpora record RST_STREAM immediately
before and after GOAWAY. All twelve corpora replay exactly against mitmproxy 12.3.1.
They do not imply that other request methods,
response fragmentation or retry timing are covered.

Spider now matches the checked GOAWAY selection, hook order, response fields,
error document and downstream suppression through protocol-owned native
actions rather than addon-only errors. GOAWAY followed by RST_STREAM also matches
the reference connection-level failure behavior. RST_STREAM immediately before
GOAWAY uses the stream-local native failure action first, preserving the
reference response order. Isolated upstream resets match the checked eight-code
matrix: `CANCEL` remains a downstream reset, while the other observed codes
produce a complete 502 and preserve multiplexed siblings. A final response-header
hook followed by reset, including across separate reads, does not leak the
incomplete response downstream. The error hook and ordering are preserved.

An expanded standalone-reset oracle now fixes the decision boundary across
eight error codes. Reference 12.3.1 emits a downstream reset only for `CANCEL`
(8); `NO_ERROR`, `PROTOCOL_ERROR`, `INTERNAL_ERROR`, `FLOW_CONTROL_ERROR`,
`REFUSED_STREAM`, `ENHANCE_YOUR_CALM`, and unknown code 123 each produce a
complete local 502 while a multiplexed sibling completes normally. The compact
black-box record is `tests/corpus/addon_reset_matrix_v12.json`. The generic
native response policy is implemented as
`ConnectionHttp2.fail_reset_stream()`: it consumes one callback-local upstream
reset and emits a bounded protocol-owned response without exposing a stream-ID
control plane. Informational headers immediately before the reset are hidden;
final headers invoke `responseheaders` but remain unpublished, matching the
additional reference observations. The API contract and acceptance gates are
recorded in `docs/RST_STREAM_FAILURE_API_PROPOSAL.md`.

Destination changes are explicitly unsupported by the current H2 publication
path. Editing Request host, port, or scheme (including a URL assignment that
changes them) fails before native drafts are modified and invalidates the addon
generation rather than claiming the upstream connection was redirected. Editing
only `host_header`/authority remains a supported header mutation. Tests verify
that distinction in translated bytes and that rejected rerouting does not replay
the request callback. Actual destination changes still require native routing
support; rejecting them is a safety boundary, not completed compatibility.

Completed `request` and `response` hooks may replace their corresponding message
object, for example with an edited `flow.request.copy()`. The existing native
binding retains the original destination and byte representation; the selected
object supplies desired fields, body and trailers through the same draft API.
Multiplexed hold tests verify retained replacement identity, single callback
delivery, reverse-order responses and resulting wire bytes. A replacement must
keep the message kind and HTTP/2 version, provide a byte body and obey all existing
destination, quota and streaming restrictions. `Response.make()` defaults to
HTTP/1.1; this is not automatic protocol conversion. Header hooks may also replace
their message object. A body or trailer value assigned there is provisional, as
in the reference: it is visible inside that callback, while the subsequently
observed body and trailers replace it before the completed-message hook. Other
header edits remain. Tests cover fragmented and coalesced input in both directions,
the black-box reference behavior and the packaged worker. A synthetic response
assigned in a request hook is now staged through the native local-response
transaction described below. No new flow or upstream connection is created by
ordinary object replacement.

A usable Python object does not imply that every transport operation is
supported. `Flow.kill()` is connected end to end for HTTP. The native H1
transaction suppresses the selected message and returns the strict negotiated
callback-local close action; Smithproxy discards both callback directions and
closes only that connection. The native H2 Translate transaction suppresses the
selected unpublished message, emits one client-facing
`RST_STREAM(INTERNAL_ERROR)`, preserves sibling streams and discards late DATA.
TCP and UDP message objects are not evidence of working TCP/UDP transport hooks.

HTTP/1 request and response hooks now run through Spider's typed HTTP/1 Parts.
The compatibility driver does not parse start lines, headers, chunk framing or
content codings. Native Parts supplies those values, owns retained-body
checkpoints and publishes the resulting Rewrite transaction atomically. The
driver pairs sequential requests and responses, preserves one flow object across
both directions, and dispatches header and completed-message hooks once across
fragmented callbacks. Packaged-worker tests cover Content-Length retention,
start-line/header/body mutation, gzip preservation, two sequential exchanges,
and informational responses that do not consume the pending request.

Pipelined callbacks are supported when the producer annotates every message:
generic Parts creates independent ordered groups and the addon driver preserves
FIFO request/response identity, including a completed prefix before a retained
final body. Mixed typed and opaque callbacks fail before addon hooks run instead
of silently publishing an unobserved message. A fragmented start line or header
cannot be classified until the producer supplies a typed annotation; the adapter
deliberately does not add a second HTTP parser. The approved generic
chunked-trailer helper is now connected: it preserves ordered duplicates,
repairs the `Trailer` declaration, and rejects fields that framing, routing or
representation processing require before message completion. Native local
responses preserve request pipeline order and use complete valid chunked
framing when trailers are present. Changing the destination, streaming a body,
remains unsupported. Interim responses remain on the native wire
and are not exposed through the regular response hooks, matching the tested addon
callback behavior.

The multipart form-view corpus now contains 68 independently observed cases
against reference 12.3.1. This includes filename/name parameter ordering,
duplicate names and fields, folded or injected physical header lines, empty
names, and binary names. The facade matches the reference's limited form view,
not a general MIME parser: it does not preserve upload filename metadata when
rewriting the form. An integration test edits a field with `filename` preceding
`name` through an addon hook and verifies the native translated HTTP/2 payload
and repaired Content-Length. Unedited raw upload bodies remain untouched.

HTTP/1 chunked trailers are a documented deliberate extension rather than exact
failure parity. A raw loopback probe against reference 12.3.1 sends a valid
chunked request with trailers. The reference raises `NotImplementedError: HTTP
trailers are not implemented yet.`, forwards no request bytes and returns no
client response; a second run reproduced the checked-in observation. Spider's
native Parts implementation already validates, exposes and rewrites complete
chunked trailers. The compatibility adapter keeps that useful native behavior
instead of reproducing a reference proxy crash.

### Raw transport prerequisites

The native rewrite machinery already provides the byte-mutation primitive:
`Message.parts` exposes unannotated bytes as `Opaque` drafts, `set_bytes()` edits
them, and `Message.commit()` assembles the result. A raw addon adapter should
reuse this path rather than introduce framing or a second transport engine.
However, an opaque part is not a transport classification or a datagram boundary.
Its `complete` flag can be true while `content.complete` is unknown. An empty
callback produces no opaque part at all.

Read-only inspection of the local Smithproxy checkout at `495d0aa5` identified
three producer-side prerequisites that must be resolved before enabling live
TCP/UDP hooks (no producer code was changed):

- `src/proxy/mitmproxy.cpp::content_payload_layer()` returns `http3` for an
  observed HTTP/3 application and `tcp` otherwise. This is not a trustworthy
  TCP-versus-UDP transport discriminator. Do not infer transport from this field
  or from the human-readable session label.
- `content_webhook()` receives a buffer, not an explicit sequence of datagram
  boundaries. UDP requires one message per original datagram, including explicit
  semantics for empty datagrams and for replacing or dropping a datagram.
- `content_webhook()` returns early for an empty buffer. Therefore an empty UDP
  datagram cannot simply be represented as an ordinary empty content callback
  through this path without an explicit producer-side contract.

Proposed integration boundary, pending approval for the other project:
observed transport and endpoint metadata at connection setup; ordered TCP byte
chunks or explicitly delimited UDP datagrams at content delivery; and a terminal
reason distinguishing clean close from transport failure. TLS/application-layer
classification must remain separate from the outer socket transport (for
example, decrypted HTTP/3 over UDP is not a raw UDP addon message).

For TCP, callback chunk boundaries are observations, not application-message
boundaries. Tests must compare resulting byte streams across fragmentation
patterns rather than promise identical OS read sizes. For UDP, the inverse is
essential: tests must preserve datagram identity, zero-length payloads, ordering,
and one-datagram replacement semantics. Reusing a stream buffer without this
contract could merge or split datagrams while still passing byte-equality tests.

These requirements do not authorize changes to Smithproxy. The packaged Spider
worker now accepts raw hooks and contains a strict adapter for the proposed
versioned envelope. Without that envelope no raw flow is created and no raw hook
is invoked. Until the producer contract is approved and tested, this remains an
integration boundary rather than an operational transport feature.

| Area | Implemented and tested | Still required |
| --- | --- | --- |
| Selection | Explicit UI/backend mode; library versions retain selection; first-line `#!mitmproxy` wins, including BOM/CRLF; effective deployment mode persisted; isolated preview runs a fresh complete addon lifecycle | Preview intentionally does not reuse deployed addon state or expose live transport holds |
| Imports and registration | Scoped Spider-owned module facade, module hooks, addon objects/trees, signature checks, async dispatch, ctx.master.addons registration, trigger, lifecycle-handler and targeted invocation APIs; clean-room `mitmproxy.log`, `mitmproxy.flowfilter`, `mitmproxy.io`, `mitmproxy.script.concurrent`, generation-local `mitmproxy.contentviews` with current and legacy-v11 registration, registry change notification and public message render/reencode helpers, `mitmproxy.net.encoding`, `mitmproxy.net.server_spec`, `mitmproxy.coretypes.serializable`, `mitmproxy.options`, `mitmproxy.optmanager`, public exception hierarchy, URL/status/cookie helpers, string helpers and public human-formatting helpers; canonical `http`, `flow` and `connection` module aliases; independently verified public HTTP, WebSocket, DNS, TCP and UDP hook values | Replay/shutdown services and broader dynamic lifecycle coverage |
| Lifecycle and state | Load/configure/running/done runtime; awaited `client_connected`/`client_disconnected` around each native connection with one descriptor identity shared by every HTTP flow and raw transport flow; independently verified public client/server hook values; one worker per deployment generation; multiple connections share state; parent-owned per-call CPU budgets; connection-bound native checkpoint lifetime; bounded graceful retirement with history report; failed worker is not silently recreated; exact 128-flow capacity, reuse and mass-retirement regressions | Truthful server-connect lifecycle requires producer events for target selection, upstream connect and upstream disconnect; broader resource-policy and adversarial concurrent-retirement stress tests |
| HTTP headers | Ordered duplicate byte fields, case-insensitive lookup, multi-value operations, inherited mapping operations, atomic replacement, direct field assignment, copy/state, and adversarial differential coverage | Additional coverage only as real addon corpora expose new behavior |
| HTTP messages | Public Message/Request/Response and MessageData/RequestData/ResponseData types; exact core class attribute inventory; construction, content/text/JSON, gzip/deflate/identity/Brotli/Zstandard, URL/query/form views including multipart, request/response cookies, timestamps, copy/state, request cache/compression helpers | Remaining adversarial view and mutation semantics |
| Flows | Identity, metadata, copy, error, local intercept/resume/kill state; HTTP/TCP/UDP/DNS state export, data-model restoration and backup/revert; saved WebSocket message restoration; byte-compatible tagged-netstring FlowReader/FlowWriter and filtered/path loading; typed live connection descriptors shared for the connection lifetime, with unknown HTTP endpoint fields left empty | Observed production endpoint/TLS metadata and direct saving of live flows that require complete connection state |
| Options | Typed declarations, updates, subscriptions, merge/setter/toggler helpers, scalar string configuration, typed and text deferred registration processing, public argparse generation, rollback on OptionsError, nested configure, the 29-option v12 default inventory, and bounded per-deployment text overrides applied before initial configure/running | Projection of applicable live Spider transport settings and remaining context services |
| Commands | Generation-local decorated and loader command registration; typed and awaited asynchronous calls; all reference command argument annotations; textual conversion and return validation; type-manager metadata; quoted execution; incremental parsing and public parser helpers; duplicate-owner replacement and decorator metadata; shared state in the packaged worker | Native proxy commands and host-owned interactive command services |
| Flow filters | Clean-room public parser and matcher for documented HTTP, TCP, UDP, DNS, WebSocket, metadata, connection, replay, body/header and boolean expressions; case-sensitivity switch; adversarial lexer/parser corpus; packaged-worker use | Interactive view-selector resolution remains a host command-service concern |
| HTTP/2 execution | Native interpreted Parts; headers and complete-message hooks; body/trailer edits; holds; multiplexing and native credit accounting; local `100 Continue`; upstream informational-response suppression; stream-reset and GOAWAY error delivery | Broader edge-case coverage and the remaining control decisions below |
| HTTP/1 execution | Native typed Parts; sequential and annotated-pipelined request/response pairing; header and complete-message hooks; retained bodies and prefix publication; start-line/header/body/trailer edits; chunked and compressed body preservation; informational-response pass-through; bounded ordered local responses | Mixed opaque pipeline classification, fragmented-head producer annotations and the remaining transport decisions below |
| Transport control | Request/response object replacement in headers and completed-message hooks through existing native drafts; header-hook body assignments have the reference's provisional callback semantics; protocol-owned H1/H2 local responses with reverse output and atomic checkpoints; HTTP/1 callback-local close and HTTP/2 stream reset for `flow.kill()`; a late `.stream` selection in a completed-message hook remains observable but has no retroactive transport effect; unsupported decisions fail explicitly | Intercept/resume transport effects, destination changes, header-hook streaming |
| Other protocols | TCP/UDP message and flow models; strict bounded Spider-side raw lifecycle adapter over an explicit versioned producer envelope; dormant HTTP CONNECT lifecycle adapter backed by five reference wire corpora; WebSocket message/data models; DNS constants, questions, records, messages, offset decoding, JSON/state conversion, HTTPS/SVCB helpers and RFC 1035 wire codec; TLS/DTLS ClientHello parsing plus detached TLS, QUIC TLS and proxy-context event values; the complete mitmproxy 12 event-name inventory; independently verified `Socks5AuthData`/`Socks5AuthHook` values and fail-closed recognition of `socks5_auth` | Smithproxy raw and HTTP CONNECT producers with end-to-end wire integration; WebSocket, DNS, SOCKS5 authentication, TLS and QUIC hook capabilities |

### Official example workflow audit

The 30 dedicated [mitmproxy 12 addon examples](https://docs.mitmproxy.org/stable/addons/examples/)
were reviewed again on 2026-10-31. This is a workflow audit, not permission to
copy their implementation. Spider's clean-room tests use independently written
scripts and black-box observations. The checked
`tests/corpus/addon_official_examples_v12.json` manifest partitions every named
example into supported, producer-gated, host-gated or native-gated work and
links each classification to local evidence. A test guards completeness,
uniqueness and the existence of every cited artifact.

The result is 20 supported workflows, four producer-gated workflows, three
host-gated workflows and three native-operation-gated workflows. These counts
are an auditable example inventory, not an API-completion percentage.

The anatomy/counter, standard logging, asynchronous hooks, custom options,
configure callbacks, query/form/header/body mutation, trailers, custom commands,
flow filters, custom and interactive content views, and saved-flow read/write
workflows all have corresponding adapter tests. Generation state and mutations
are also verified through the packaged worker and native HTTP publication, not
only by constructing facade objects in isolation.

The examples that require proxy-owned operations remain deliberately outside
the completed set: shutdown, WSGI/ASGI hosting, destination
rerouting, replay, streaming, WebSocket injection and live TCP/DNS processing.
Their public value objects may exist, but loading a transport hook or attempting
an unsupported HTTP decision fails explicitly. TCP and UDP hooks can now load
because the packaged worker has the strict raw adapter described above, but no
hook is invoked without the explicit producer envelope. This distinction
prevents a small example from appearing to work while its actual network action
is silently ignored. DNS, WebSocket, TLS and QUIC hooks remain detached-model
capabilities until native producers provide their transport boundaries and
observations.

This is an inventory, not a percentage. Passing an object contract test does not
close a live-transport requirement, and a recognized hook name does not promise
that a transport driver can deliver it.

The mitmproxy 12 content-view redesign is implemented as a generation-owned
registry rather than an inert `contentviews.add()` facade. A black-box 12.3.1
corpus fixes the documented public types, default properties, registration,
selection and interactive re-encoding behavior. The deployed addon worker serves
bounded list, render and re-encode operations from the same persistent generation;
a formatter exception is reported without discarding the addon's module state.
Spider's payload viewer discovers those views from the enabled deployment, shows
their syntax label and can turn an interactive wire view back into a pending
replacement. Derived L7 views remain read-only because rebuilding framing and
content codings belongs to native Translate, not browser-side glue. Input, output
and edited text are each limited to 1 MiB, and worker-control fields are rebuilt
server-side rather than accepted from the HTTP request.

Dynamic registration investigation: `tests/probes/addon_registration_probe.py`
uses public reference Master/AddonManager operations without starting a proxy
server. Fourteen recorded scenarios distinguish lookup registration from the active
root chain, parent/child lifecycle ordering, duplicate names, deferred options,
late addition and children created inside `load()`. In the reference, `add()`
does not itself synthesize `configure` or `running`; `register()` returns the
registered object without adding it to the active chain. Children can be created
by their parent's `load()` callback and must then receive their own lifecycle.
Spider now discovers the startup tree in parent-first load order, including
children created or replaced by load callbacks. It validates the discovered
objects before publishing registration; cycles, duplicate identities,
invalid child lists and the 256-object limit remain guarded. The former expected
failure is a normal passing lifecycle regression. Registered-object lookup and
active-root state are separate. Initial preflight validation remains stricter than
reference loading for unsupported handlers present before load callbacks run.

The bundled `addon_manager.py` matches those registration scenarios,
including mutation during event delivery and distinct remove/clear visibility
during `done`. It reuses the existing hook validator and invocation machinery.
It is exposed through `ctx.master.addons` for add/register/get/remove/clear/chain;
`ctx.master.options` refers to the same options object as `ctx.options`.
Runtime tests verify scoped imports and one-time reporting of registration-hook
failures. A packaged-worker test adds an addon during a request, mutates real H2
output on two connections with shared addon state, and verifies one shutdown hook.
The generation-local Master also exposes the running worker event loop and the
same legacy `Log` object as `ctx.log`, including the reference back to its
Master. A live 12.3.1 corpus fixes that identity and the public Master surface.
Proxy-wide `shutdown`, `should_exit`, `run`, `running` and `done` services remain
deliberately absent because Spider has no worker-to-host control contract for
those operations. Failure cleanup and dynamic lifecycle edge cases still need
broader adversarial coverage; these tests are not an exhaustive manager claim.

`master.load_flow(f)` is now implemented as the reference's asynchronous,
detached lifecycle replay. An independent 12.3.1 corpus covers HTTP request,
response and error ordering; incremental TCP and UDP message history; terminal
end/error selection; DNS request/response/error; and open and closed WebSocket
history. The transport message list object is replaced while the original
message objects retain identity, matching the reference observation. This
operation invokes addon hooks only. It does not send bytes, start a replay, or
publish mutations to Smithproxy. The generation's declared hook capabilities
still apply, so the method does not make unsupported live TCP, UDP, DNS or
WebSocket hooks loadable in the HTTP adapter.

`docs/HOST_CONTROL_PROPOSAL.md` records the independently observed synchronous,
non-reentrant `master.shutdown()` boundary and proposes a bounded generic
worker-to-host control envelope. The unresolved scope is explicit: retiring one
deployment is safe but narrower than reference behavior, stopping Spider leaves
Smithproxy alive, and stopping a whole workspace crosses a privileged project
boundary. No behavior is implemented until that scope and native contract are
approved.

Registration errors propagate to the caller: a failing child `load()` leaves the
new tree unpublished and inactive, without synthesizing `done()`. Scripts can
catch the error themselves; otherwise the enclosing broadcast hook reports it.
By contrast, invalid deferred options fail after lookup publication but before
activation, so explicit removal can still find the registered object. Both cases
are reference-tested. Distinct children sharing a name in a single registration
receive separate callbacks, with lookup retaining the last visited child; names
already present before registration are rejected. Identity and cycle guards stay
in place. Startup worker tests verify that a caught registration error does not
fail startup or invent cleanup callbacks for the rejected addon.

The facade exposes public `Hook`, `ConfigureHook`, `RunningHook`, `DoneHook` and
`UpdateHook` values under `mitmproxy.hooks`, and `LoadHook`/`Loader` under
`mitmproxy.addonmanager`. A reference corpus checks event names, argument lists
and payload identity, including custom dataclass hook naming. `trigger()` and
`trigger_event()` dispatch supported events synchronously/asynchronously and
retain callback failures for the worker's report. Both propagate `OptionsError`
to the caller, verified against reference public calls. Constructing an event
does not grant transport capability: arbitrary custom events and automatic
delivery of unsupported hooks remain outside the current adapter.

An interrupted broadcast retains failures from recipients that already ran.
Regression tests cover a later `OptionsError` in synchronous and asynchronous
triggers, cancellation of an asynchronous recipient, and exactly-once diagnostic
delivery through worker logs or the generation shutdown report.

`invoke_addon_sync()` and awaited `invoke_addon()` target an addon and its child
tree without requiring registration. Unlike broadcast triggers, they propagate
ordinary callback exceptions directly and stop delivery on that error. Twelve
reference scenarios cover ordering, children added during the callback, missing
or non-callable handlers, async handlers and exceptions. Runtime tests exercise
targeted calls and scoped imports from a deployed request hook. Existing cycle,
duplicate-identity and object-count guards still constrain the traversed tree.

One independently observed reference edge is intentionally stricter in Spider.
If an ordinary function returns an awaitable from `invoke_addon_sync()`,
mitmproxy 12.3.1 discards it and returns `None`; a native coroutine additionally
emits an unawaited-coroutine `RuntimeWarning`. Spider closes a returned coroutine
and raises `AddonManagerError` for every awaitable instead of leaking asynchronous
work. The awaited `invoke_addon()` path executes and awaits both coroutine and
custom-awaitable results in both implementations. A dedicated black-box corpus
and regression fix this safety deviation explicitly.

Startup failures retain the prepared module scope so addons registered by early
module statements can be retired even if a later statement raises. The worker
reports the original startup failure and captures cleanup output separately in
its logs. Tests cover successful cleanup, ordinary cleanup exceptions and aborted
cleanup, plus idempotent generation close and removal of scoped import entries.
Partially failed registration trees have a separate black-box contract. A
failed tree publishes none of its parent or child lookup entries and does not
invent cleanup for objects whose registration never completed. Registration
side effects are independent transactions: a separate addon successfully added
by a parent or child before a later load failure remains active and receives its
normal `running` and `done` lifecycle. Likewise, `add(first, broken, never)`
retains the successfully completed first root, rejects the broken root and never
visits the last root. Spider matches these boundaries without attempting to
roll back arbitrary user code.

The path-component view has 130 reference observations covering repeated slashes,
URL parameters, query/fragment preservation, percent escapes, Unicode, invalid
UTF-8 octets and assignment errors. Components follow the full request URL rather
than treating a leading double slash as a new authority. Native H2 publication
also verifies edited components with retained parameters and binary octets.

Brotli and Zstandard content handling uses the independent `Brotli` and
`zstandard` Python packages. They are runtime requirements for addon mode and
are listed in `deploy/requirements-addon.txt`; test requirements include that
manifest and add independent verification tools.
No reference proxy code is imported. A 56-case reference corpus checks encoded
bytes, empty/binary/repetitive bodies, truncated streams, trailing bytes,
concatenated frames and strict/lenient decoding. Tests also cover mutation in the
worker sandbox and publication of recompressed H2 responses through native
Translate. Exact compressed-byte comparisons describe the tested codec versions,
not a promise that all future encoder versions produce identical bytes.
The 12.3.1 release raises the safe Brotli decoder floor to 1.2.1. The addon
runtime requirement and CMake preflight enforce that minimum instead of merely
checking that some Brotli version imports. Verification uses zstandard 0.25.0;
the reference environment uses Python 3.14.4 and Brotli 1.2.1.
An isolated worker test actively blocks importing both codec packages and checks
legacy native execution, explicit Spider mode and addon syntax validation. Those
paths do not require addon codecs; only executing addon mode loads them.

Multipart form support has 44 independent black-box observations against 12.3.1,
including malformed boundaries, byte values, duplicates, filenames, transfer
encoding headers, live views and serialization failures. The view intentionally
matches the reference's loss of line separators inside values; it is not a
lossless MIME editor. Reading the view does not rewrite the original body.
Mutation uses the existing message content setter and native Translate publication,
including content-length updates. Tests cover compressed bodies, generated
boundaries in the sandbox and actual H2 publication.

Live views and owned dictionaries now share only mapping operations: views do
not expose standalone state serialization, and preserve the owner's field
sequence and setter input identity. A separate 37-case reference corpus covers
query, URL-encoded forms, multipart forms, request cookies, response cookies and
custom views. This includes detached copies and asymmetric equality with owned
dictionaries. In 12.3.1, the list-backed `multipart_form.add()`/`insert()` raises
`TypeError`; the adapter now preserves that behavior. Use assignment or
`set_all()` to edit multipart fields. These observations cover specific public
operations, not a claim of exhaustive MIME edge-case compatibility.

Option convenience operations have a separate 30-case reference corpus covering
`merge()`, `setter()` and `toggler()`, including unknown options, sequence-type
mismatches, notification timing and partial updates. Helpers use the normal
update path rather than writing stored values directly. A lifecycle test verifies
that configure-hook rejection propagates through each helper and restores the
previous values. String configuration through `set()` has a separate 38-case
reference corpus: booleans (including toggle), integers, strings, optional values,
duplicate specifications, invalid input and batched notifications. Parsing
finishes before any values change; configure-hook rejection still uses normal
rollback. The reference rejects string conversion of the tested `Sequence[str]`
declaration with `NotImplementedError`, which this adapter preserves.

`set(..., defer=True)` retains unknown option specifications until explicit
`process_deferred()` calls or automatic addon registration processing. A 12-sequence reference corpus
checks replacement, duplicate values, partial registration, batched notification,
parse failures and configure rejection. Successfully processed entries disappear;
failed batches remain pending. Startup registration applies pending values before
initial configure/running delivery; a later explicit process call is then inert.
Dynamic registration also processes pending values through the same option API.

Deployment option overrides reuse that public string parser instead of adding a
second configuration path. The control plane stores a bounded list of
`name=value` specifications with the deployment generation. A worker applies
them after `load()` has declared addon options and before the initial
`configure()` and `running()` callbacks. Warm-up is transactional: invalid text,
an unknown name or `OptionsError` leaves an already enabled previous generation
untouched. Preview runs accept the same list but retain their deliberately fresh
generation lifetime. These values configure the addon registry only; familiar
proxy options remain compatibility defaults and do not silently change Spider's
listeners or transport.

Exporting a script with mitmproxy mode selected adds `#!mitmproxy` to the
downloaded Python file when needed. Existing directives are retained without
duplication, and native scripts are exported unchanged. Export does not change
the editor or saved library version. This keeps the selected mode portable
outside the browser's local library.

## Current execution boundary

The connected H2 driver delivers `requestheaders`, `request`, `responseheaders`,
`response` and `error`. Header callbacks do not imply a complete body. Whole-message
callbacks wait for native body completion; the adapter does not invent completion
from the end of an arbitrary Part. Native Translate performs framing, HPACK,
stream/window accounting and publication.

Informational-response investigation (2026-10-30): an isolated loopback probe
against 12.3.1 sent `103`, `100`, then `200` over negotiated HTTP/2. Only the
final `200` reached `responseheaders`/`response`; the reference also suppressed
the informational headers on the client wire. Spider classifies informational
headers before constructing a complete response binding, avoiding their mistaken
interpretation as trailers when several header blocks arrive together. The
approved native `suppress_informational_response()` operation now consumes each
source block while advancing only the source HPACK decoder. Addon hooks and the
downstream encoder observe only the final response. Original status classification
is captured before script edits; rewriting `200` as `103` cannot bypass the native
operation. Split-boundary regressions cover every input byte and retain the final
body reservation without publishing `103` or `100`. No H2 framing or flow-control
implementation exists in the facade.

The addon driver rejects H2 status `101` and informational headers carrying
`END_STREAM` before invoking response hooks or publishing the message. These
invalid responses must not be skipped as ordinary interim headers: doing so
would retain a flow awaiting a final response that cannot arrive. Regression
tests verify rejection, unchanged source bytes and refusal to reuse the failed
driver. This is adapter validation, not a change to native Translate policy.

The follow-up `Expect: 100-continue` loopback probe confirmed that reference
12.3.1 sends its own H2 `100` to a client waiting to send a request body. The
request-header hook sees `Expect` and no body; the whole-request hook sees the
body with `Expect` removed. The origin also receives no `Expect` header. Origin
`100` and `103` responses are then suppressed, and response hooks see only `200`.
Thus informational suppression alone is insufficient for compatibility: a
native interim-response publication path must first handle the waiting client.
The approved `emit_informational_response()` operation emits that reverse header
block through the peer HPACK encoder even while the request head is held for its
body. The adapter removes exactly one case-insensitive `100-continue` value after
`requestheaders`, emits one local `100`, and leaves duplicate or other values
untouched. A bodyless request follows the same policy. Local final responses and
request termination take precedence, so they cannot race a continue response.

`tests/probes/h2_expect_probe.py` is an opt-in reproducer with independent H2
client/server peers and assertions for these observations. Its normalized
baseline and six-case policy summary are checked in as
`tests/corpus/addon_h2_expect_v12.json` and
`tests/corpus/addon_h2_expect_matrix_v12.json`. The matrix establishes that one
case-insensitive value triggers local continue even for a bodyless request,
while duplicate or invalid values remain untouched. It accepts an explicit
reference executable, a disposable test certificate and key; none is bundled or
used by Spider at runtime. For example:

```sh
python3 tests/probes/h2_expect_probe.py \
  --reference /path/to/reference/mitmdump \
  --certificate /path/to/disposable/cert.pem \
  --private-key /path/to/disposable/key.pem
```

The approved generic native operations, atomicity requirements and risk boundary
are recorded in `docs/INFORMATIONAL_RESPONSE_API_PROPOSAL.md`. Their implementation
is part of Translate; the compatibility facade only chooses when to invoke them.

The probe uses only loopback sockets and disables certificate verification only
for its isolated test endpoints. It is not part of the offline CTest suite.

The backend currently requires flow instantiation and a single enabled deployment
in the chain. Retained bodies are bounded at 256 KiB in the H2 event driver.

Reservation policy: when the original source headers contain exactly one numeric
Content-Length, the addon driver reserves that encoded size, bounded by the
configured 256 KiB per-body maximum. The native ledger validates the original
field independently, so a script edit cannot hide an oversized input. Two
concurrent 100,000-byte bodies now reserve 200,000 bytes in the default adapter
and retain both streams within the existing aggregate budget. Missing, duplicate
or malformed lengths deliberately retain the conservative 256 KiB reservation;
two such unknown-size bodies can still contend for the aggregate limit. Growing
an immutable reservation safely would require a separate native policy rather
than speculative early credit. A connection-stop test also uses an explicit
64 KiB body limit for two pending streams on each of two connections; it verifies
that an ordinary error-hook exception does not prevent remaining error delivery
or release, and that the other connection stays live. Do not silently increase
native credit limits or claim general concurrent unknown-size body support.
The default generation flow table and native adapter connection table each have
a 128-entry limit. These are deliberate current limits, not claims of parity.
An addon-owned connection retains its native checkpoint until `connection-stop`;
the native-script idle-expiry setting does not independently discard half of
its state. Instance and memory quotas still apply, and closing the connection
releases its instance slot. The UI disables idle expiry for addon deployments.

The production worker does not yet receive HTTP endpoint or TLS observations.
The adapter creates one typed Client/Server descriptor pair at connection setup
and shares those exact objects with every HTTP flow on that connection. Unknown
fields remain `None`; scripts requiring real addresses or TLS metadata are not
yet supported. Do not synthesize plausible-looking endpoint data from labels.

`client_connected` is awaited after native `connection-start` and before the
first HTTP, TCP or UDP hook. `client_disconnected` is awaited after pending
protocol error/end hooks and before descriptor retirement. Both hooks observe
the same Client object used by every flow; its state is OPEN in the first hook
and CLOSED with `timestamp_end` populated in the second. A checked-in black-box
mitmproxy 12.3.1 corpus fixes this ordering and identity contract. The packaged
worker repeats the contract through the production JSON boundary.

Server lifecycle hooks are deliberately not synthesized at connection setup.
The reference emits `server_connect` only after the target is known,
`server_connected` after the upstream socket opens, and `server_disconnected`
when that socket closes. Spider needs corresponding producer observations before
it can expose those hooks without lying about state or ordering.

### Deferred producer integration TODO

- Treat these hooks as deferred compatibility work, not as permanently
  unsupported API. Complete them after the current HTTP lifecycle work.
- Smithproxy must emit ordered target-selected, upstream-connected and
  upstream-disconnected observations for the current native connection.
- The connection-start observation should include real client peer/local
  endpoints so Spider can populate the existing Client descriptor.
- Spider will map those observations to `server_connect`, `server_connected`
  and `server_disconnected`, preserving one Server identity and awaiting each
  addon hook before the next transport event.
- Differential tests must compare success, connect-error, reconnect and clean
  teardown ordering with the checked mitmproxy 12.3.1 lifecycle corpus.

This is intentionally deferred; no synthetic server event is emitted meanwhile.

`addon_connection.py` now contains the initial Connection/Client/Server data model:
state flags, endpoint/TLS fields, identity equality, detached copies, legacy
accessors and state serialization/restoration. Its
public-behavior tests also run against the reference. Connection, Client, Server
and ConnectionState are exported through `mitmproxy.connection`; Cert is exported
through `mitmproxy.certs`. Both Spider-owned modules are bundled into the worker.
A separate 34-scenario corpus covers the immutable public `ProxyMode` values and
parser through `mitmproxy.proxy.mode_specs`: regular, transparent, SOCKS5,
reverse, upstream, WireGuard, local, TUN and DNS modes, listener overrides,
IPv6 listener spelling, state identity and invalid input. Restoring a Client now
accepts all of these serialized descriptors. They remain data only: parsing a
mode does not bind a listener, create a tunnel or change native routing.
Restoration tests cover certificate chains and the reference's observable input
mutation and partial updates on failure. No production descriptor or live
endpoint routing has been changed by this groundwork.
Flow state restoration uses these descriptors and is available in packaged
workers. A sandboxed worker test restores a detached flow with client/server
descriptors and a public certificate, then verifies a derived header in actual
H2 output. Cryptography is an addon runtime dependency; native execution and
compile-only validation are tested with that dependency deliberately unavailable.
Tests verify detached restoration and in-place updates:
loading does not reopen sockets, while updating retains existing connection
objects and their open-destination restrictions. Saved WebSocket message data is
also restored; that does not deliver live WebSocket transport hooks.

WebSocket model investigation has a separate 28-scenario reference corpus
(`tests/corpus/addon_websocket_v12.json`), reproducible with the isolated
`tests/probes/addon_websocket_probe.py` process. It covers opcode validation,
text access and replacement, malformed UTF-8, drop flags, message copy/state,
close metadata and container restoration. Reference restoration mutates the
supplied state dictionary, replacing serialized message tuples with objects.
Updating an existing container instead consumes its input dictionary, replaces
the message list, and preserves partial updates on missing or extra fields.
Both paths and their object-identity behavior are covered separately.
The Spider-owned `addon_websocket.py` model matches these observations and exports
WebSocketMessage/WebSocketData through `mitmproxy.websocket`, with WebSocketData
also available through `mitmproxy.http`. A packaged-worker test restores messages
inside a detached HTTP flow and verifies that editing the restored message does
not modify the source. The independent wsproto dependency supplies only its public
Opcode enum; no wsproto framing or proxy processing is used. Live WebSocket
transport hooks remain unimplemented and are still rejected at registration.
`WEBSOCKET_PRODUCER_PROPOSAL.md` records the required cross-project boundary:
Smithproxy retains framing, masking, fragmentation, compression and control-frame
ownership, while Spider receives complete logical messages through synchronous
pass/replace/drop decisions. Active message injection remains a separate host
capability. The proposal changes no code and does not enable these hooks.

The tested 12.3.1 reference has two non-obvious backup behaviors: an existing
snapshot survives `backup(force=True)`, and `modified()` is true immediately
after `backup()` because the backup itself participates in the state comparison.
The adapter preserves both behaviors. `revert()` clears the snapshot and does
not restore the live transport flag. These methods are data operations, not
rollback of traffic already forwarded by the native engine.

`addon_certs.py` provides the initial public-certificate value adapter using
cryptography (42 or newer): PEM state, SHA-256 fingerprints, validity times,
public keys, name/SAN views, CA/CRL extensions, key-family descriptions and
copy/equality. It does not handle private keys or install trust.
Its source is bundled into production workers, but the configured Python runtime
must provide cryptography. The optional deployment requirements declare it, and
the test requirements include the same manifest. The README explains interpreter
selection and isolated worker imports. Downstream appliance/package integration
has not been changed here. The deprecated PyOpenSSL conversion methods are
implemented as lazy boundary conversions, independently reference-tested and do
not retain a legacy wrapper inside the public value.

Inspection of the current producer confirms that `connection-start` carries
`details.info.session`, a display label, rather than structured socket/TLS
descriptors. Spider's existing session filter parses this label for filtering;
that does not establish the full connection-object contract. A structured
metadata extension has been proposed to the user and awaits approval before
any Smithproxy changes. It must distinguish original destination from connected
peer, represent unavailable fields explicitly, and support later handshake
updates without breaking older webhook producers.

Cookie views expose `mitmproxy.net.http.cookies.CookieAttrs` through the scoped
import facade. Attributes are case-insensitive with last-value lookup, but
preserve duplicate fields and their spelling. Editing a returned attribute
object does not update a response until that cookie is assigned back to the
view. Public Cookie and Set-Cookie parsing, formatting, grouping, expiry and
refresh helpers reuse those same primitives. Unsupported nested modules remain
absent; imports must never fall back to a reference package installed on the
machine.

The legacy `ctx.log` callable and its debug/info/warn/error/alert methods forward
to standard Python logging. The named legacy methods emit DeprecationWarning,
as in the reference. The scoped `mitmproxy.log` facade also exposes the observed
`ALERT` level, level/color metadata, `LogEntry` value and deprecated `Log`
adapter used by public addon examples. Addon workers capture INFO and above by
default, using the current callback's bounded log buffer rather than retaining
the startup stream. Standard Python logging configuration remains available to
the addon. The deprecated `add_log` hook is accepted and delivered when addon
code explicitly triggers `AddLogHook` through `ctx.master.addons`. Ordinary
`ctx.log` and standard Python records deliberately do not synthesize this hook,
matching the observed mitmproxy 12.3.1 behavior and preventing a second event-log
pipeline or recursive logging loop. A checked-in black-box corpus fixes that
boundary, and the production worker repeats it through its packaged runtime.
All **513** direct addon tests pass under branch instrumentation. The native
adapter and logging facade both have **100%** branch coverage; the complete
6,404-statement production addon set remains at **98%** aggregate branch
coverage.

The scoped `mitmproxy.utils.strutils` module exposes the audited public string
helpers, including byte/text conversion, control-character escaping, bounded
line display, hexdumps, binary/XML heuristics and protected-area escaping. Their
type errors and edge cases are fixed by independent reference observations.
`mitmproxy.utils.human` also provides the observed size, duration and local-time
formatters. These are explicit public subsets, not a claim that every internal
utility module is compatible.

`mitmproxy.net.encoding` and HTTP message content properties share one codec
implementation. Identity, gzip, deflate, Brotli, Zstandard and ordinary Python
character codecs retain value types and error policies observed from 12.3.1.
Stable reference bytes fix the HTTP compression settings; tests also cover
concatenated/trailing/truncated gzip input and ensure invalid content never
becomes a partial successful decode. This is application content processing,
not an additional HTTP or transport engine.

The clean-room `mitmproxy.flowfilter` facade parses and matches documented HTTP,
TCP, UDP, DNS, WebSocket, metadata, replay, endpoint, header/body and boolean filter
expressions over Spider-owned flow models. Regex flags and their public text are
captured when a filter is parsed, so changing the case-sensitivity environment
later cannot make the description disagree with the compiled expression.

The scoped `mitmproxy.dns` facade provides the independently observed v12.3.1
constant conversion, question, resource-record, message and flow-state contract.
Its Spider-owned RFC 1035 codec accepts compressed names, emits deterministic
uncompressed names, preserves DNS message flags and record boundaries, and is
available inside packaged workers. `tests/corpus/addon_dns_model_v12.json` fixes
the public state, JSON, wire and error behavior. This model does not by itself
enable `dns_request`, `dns_response` or `dns_error`: those hooks remain rejected
until a native DNS transport can deliver and publish their decisions.

`constrain_encoding()` matches the reference header transformation. Content
decoding is tested separately rather than inferred from advertised encodings.
The reference's resulting encoding order varies with `PYTHONHASHSEED` (verified
with seeds 0, 1 and 2). Spider uses a stable order; contract tests compare encoding
tokens, not arbitrary reference ordering. This is not byte-for-byte equivalence.

`Response.refresh()` shifts Date, Expires, Last-Modified and cookie expiry dates
relative to the stored response start time. It leaves payloads, observation
timestamps, Age and Max-Age unchanged. Invalid ordinary date headers remain
unchanged; invalid cookie Expires attributes are removed, matching the reference.
This helper is not a replay transport implementation.

## Where implementation work belongs

### Command service and remaining contract work

`tests/probes/addon_command_probe.py` captures original observations of the
public command API in a separate reference environment. The checked-in
`addon_commands_v12.json` contains 95 call/parsing observations and a nine-step
registration lifecycle trace against 12.3.1. The Spider-owned implementation
passes these cases and is included in the packaged worker. A live worker test
uses a decorated command to mutate outgoing H2 headers on two connections while
retaining one generation-local counter. Separate-generation tests check state
isolation. This supports addon-defined commands, not mitmproxy's native proxy
or UI command inventory.

The observed distinction matters: `call()` binds arguments but does not enforce
their annotated types, whereas `call_strings()` converts textual inputs (including
strict lowercase `true`/`false`). Signature mismatches become `CommandError`;
exceptions raised inside the command body remain their original exception type.
Command-line execution also has its own argument-mismatch diagnostic.
Textual calls validate the result against the declared return type; typed calls
return it unchanged. Float arguments are rejected during registration rather
than treated as an additional feature absent from the reference API.

Decorated commands are unavailable during their first owner's `load`, but are
available after registration and during `done`. They remain callable after
`addons.remove()` and `addons.clear()` in the reference. Re-registering the same
owner consequently finds its previous command during `load`. Command ownership
cannot be tied to active event-chain membership without breaking this behavior.
`loader.add_command()` publishes a command immediately during `load`; subsequent
decorated collection can replace the same path. The lifecycle corpus tests both
publication points and checks that the decorated version wins afterward.
Invalid decorated declarations are logged and skipped during automatic
collection, allowing valid sibling commands and event hooks to remain active.
Direct `add()` and `loader.add_command()` propagate the registration error.
Validation happens before replacing a registry entry, so a failed replacement
leaves the old command callable. The contract covers missing argument types,
unsupported argument/return types and preservation of the previous callable.
The Spider registry remains generation-local, without introducing a second
worker or bypassing sandbox limits. It limits distinct command paths to 1024.
Textual conversion handles `str`, `int`, `bool`, `Flow`,
`collections.abc.Sequence[Flow]` and `collections.abc.Sequence[str]`.
The separate `addon_command_types_v12.json` corpus records 57 reference cases
covering registration, conversion, resolver delegation and return validation.
In particular, `HTTPFlow`, `typing.Sequence[Flow]` and `list[Flow]` annotations
are rejected rather than silently accepted as equivalent declarations.

Flow arguments delegate to an explicitly registered `view.flows.resolve`
command. The adapter does not synthesize a global live-flow inventory or the
reference proxy's filter engine. Without that command, conversion fails with
`CommandError`. A single-flow argument requires exactly one match; sequence
arguments preserve the resolver's object identity. A packaged-worker test
registers an addon-owned resolver and verifies that the selected flow's header
mutation reaches the native H2 replacement output. String sequences split on
commas, including empty elements. Return validation checks iterable elements
without copying or normalizing the result: sets, dictionary keys and iterators
are accepted when their elements match. Validation consumes iterators. The
reference excludes text and bytes for string collections, while empty text
and bytes pass the flow-collection check. These observed edge cases are tested
explicitly, not recommended as addon authoring patterns. Unsupported types fail
explicitly instead of inventing proxy selection or filesystem services.

The extended command-type corpus adds 76 observations for `bytes`, `CmdArgs`,
`Cmd`, `Path`, `Marker`, `CutSpec`, `Data` and dynamic `Choice` annotations.
`Cmd` resolves only commands registered in the current generation; `Choice`
delegates its options to an addon command. `Path` expands a leading user home
but not environment variables or globs. `CmdArgs` remains literal. `CutSpec`
splits comma-separated fields, and `Data` is deliberately return-only. Marker
aliases use the separately packaged `emoji` data rather than copying a marker
table from the reference project. This is a compatibility superset for newer
emoji aliases; the corpus fixes the reference behavior for representative
boolean, ASCII and named markers. A packaged-worker integration test executes
Choice, bytes, CutSpec and Marker commands and verifies their resulting header
mutation in native H2 output. `TypeManager` and the generation-local
`CommandTypes` registry expose the same parser and validator implementation used
by command invocation. Their lookup, display names and basic bool/command/choice
completion behavior are covered by the same corpus. Independently observed
completion contracts also cover the fixed cut-field inventory, rejection of
input-only `Data`, and filesystem completion for empty prefixes, directories,
unmatched paths and user-home spelling. The marker inventory intentionally
remains the documented independent compatibility superset rather than a copied
reference table.

Execution uses an original command-word scanner rather than a
shell tokenizer: quoted and unquoted sections are distinct arguments, unfinished
quotes retain their opening character, and backslashes do not escape whitespace.
String conversion decodes supported character escapes while preserving Unicode,
unknown escapes and trailing backslashes. The corpus covers adjacent quotations,
unfinished input, invalid hexadecimal escapes, literal shell punctuation and
Unicode/escaped-backslash combinations.

An additional 49-case reference corpus covers the public incremental command
parser and its `ParseResult`/`CommandParameter` metadata, leading and repeated
spaces, tab expansion, quoted and incomplete arguments, unknown commands,
optional parameters, `typename()`, `unquote()`, `parsearg()`, `argument()` and
`verify_arg_signature()`. The packaged-worker test exercises this interface from
an actual addon generation. Public `parsearg()` deliberately retains quotation
marks; `unquote()` remains a separate helper, matching the observed API rather
than imposing shell semantics.

The registration-edge corpus separately fixes public decorator metadata and
replacement order. Methods are discovered in attribute-name order, so the last
valid method for a shared path wins. A later owner replaces an earlier owner,
and collecting the earlier owner again replaces it back. An invalid direct or
automatically collected replacement leaves the previous valid command callable.
Collecting one owner repeatedly is idempotent from the caller's perspective.
An empty decorator argument falls back to the callback name rather than
creating an empty registry key; Unicode command paths remain valid. Native
proxy commands and host-owned interactive services are deliberately not
synthesized inside a generation-local script worker.

The asynchronous command contract is explicit rather than inferred from async
hook support. In v12.3.1 the public decorator returns a normal wrapper whose
result is awaitable. Typed `call()` returns that awaitable unchanged, so an
async hook can await it and retain generation-local state. Textual
`call_strings()` and `execute()` validate the coroutine object immediately and
reject it as an invalid result instead of awaiting it. The Spider-owned manager
matches this behavior in a black-box corpus. A packaged worker test awaits one
typed command from two live connections and verifies the shared counter in
translated HTTP/2 headers.

**Facade-only work:** cookies/forms, message helpers, serialization, connection
views and import/context compatibility belong in the adapter. They should not
require changing native transport semantics.

**Native integration work:** first inspect existing APIs for HTTP/1 complete
messages, endpoint metadata, termination, suspension and synthetic responses.
If an operation cannot be represented safely, propose a general native API
extension with its semantics, backward-compatibility impact and tests before
changing that API. Do not implement a second parser or transport engine in the
facade to work around a missing native primitive.

The approved native body/trailer replacement helpers are one such reusable
extension. Future candidates are not automatically approved by this document.

### Native synthetic-response primitive

This approved reusable Spider operation is implemented as a native transport
transaction, not a mitmproxy-specific escape hatch:

```python
api.message.respond(
    status=200,
    headers=(),
    body=b"",
    trailers=(),
)
```

The operation is valid only while publishing a complete inbound request
that has not emitted any request bytes to its original destination. It would
suppress that request and publish a complete response in the opposite direction.
Calling it after publication, on a response, or on an incomplete/ambiguous
message would fail closed before emitting synthetic bytes.

For HTTP/2, the implementation enters the existing Translate reverse-output
path for flow-control accounting, frame-size limits, output queues,
cancellation, resets and bounded checkpoints. Existing `replacement_reverse`,
peer-hold and shared flow-control primitives already own reverse transport. The
transaction privately clones the peer-direction HPACK output checkpoint and
publishes its update together with the current checkpoint, shared control state,
both holds and synthetic output. This is a bounded extension of Translate state
ownership, not a second HPACK implementation or a Smithproxy change.
Synthetic HEADERS, DATA and trailers must be queued as output-only units: they
must not be passed through the source-input accounting path or invent
WINDOW_UPDATE debt. The original request still has to be consumed from the
source direction so that native input ownership and credit are settled.

For HTTP/1, the same public operation uses a bounded native response-order
checkpoint. Origin and local-response slots preserve pipeline order, the
selected request is suppressed, and queued local responses are inserted only
after all older origin responses. It reuses native typed Parts and validation
and does not introduce another parser.

The mitmproxy adapter maps assignment of a locally constructed
`flow.response` onto this operation. The facade only validates and converts
the object model; all protocol framing and transport ownership would remain in
native Rewrite/Translate code.

Regression coverage includes:

- HTTP/1 sequential and pipelined requests, including chunked bodies, trailers,
  informational input and a client disconnect while the response is queued;
- HTTP/2 fragmented headers, multiplexed streams, exhausted connection and
  stream windows, cancellation, RST_STREAM and GOAWAY;
- atomic peer HPACK checkpoint publication, including failure before state or
  wire output is committed and a later real peer-direction response;
- exact Content-Length/body/trailer validation and bounded-output failures,
  including an explicit policy for bodies on 1xx/204/304 responses and native
  lowercase validation for HTTP/2 field names;
- rejection after any original request publication, with no partial output;
- an adapter test proving that a local `flow.response` produces the same model
  observed from mitmproxy 12.3.1 while Spider remains the only proxy engine.

### Native flow-control actions

The reference probes show that `flow.kill()` is one logical addon action but
not one generic socket operation. Both paths use the native message termination
API. For HTTP/1 it produces an explicitly negotiated callback-local connection
close without response bytes. For HTTP/2 it emits
`RST_STREAM(INTERNAL_ERROR)` and keeps the multiplexed connection alive. The
message/stream anchor lets Rewrite/Translate select the protocol effect; the
adapter does not close arbitrary sockets or manufacture an HTTP error response.

Completed H2 `request` and `response` hooks now support callback-driven
`intercept()`/`resume()` through native logical Parts suspension. The hook
returns without publishing the message. A later hook can edit the retained
public flow and resume or kill it; the next callback of the owning connection
publishes it through the original direction, including reverse output. The
original completed hook is not repeated. Native body/trailer replacement,
local-response and termination validation also applies to reverse drafts.
Tests cover independent H2 peers and the packaged persistent worker.

Header-hook and generated-response interception now build on the same native
H2 path. H1 interception uses native ordered-lane suspension: a paused message
also retains younger pipeline messages, and a callback in either direction may
resume the lane. Deferred hooks run once, native commit repairs framing, and
local responses retain their original request anchor until publication.
The H1 black-box corpus `mitmproxy_v12_h1_local_intercept.json` fixes local
response hook order and edited output. Bare kill on a paused local response
waits in the reference observation window; Spider instead applies its native
connection-close operation, matching the working resume-then-kill hook order.
This difference is explicit, not a claim of identical transport behavior.

Raw transport interception and idle asynchronous
resume are not covered by these mappings. The following describes the additional
requirements for idle asynchronous resume, not a prerequisite for the supported
callback-driven model. A separate host suspension token is not part of the
current design: native stream identity and the owning connection scope holds.

Unrestricted asynchronous `intercept()`/`resume()` needs a different contract. Waiting inside
the current worker invocation would consume the three-second callback budget,
block every connection sharing that deployment worker and make resume dependent
on another callback arriving. A correct implementation needs:

1. host-owned suspended content bound to its connection and logical stream;
2. atomic return from the addon callback without forwarding the staged message;
3. a separate resume/kill control path that can wake the suspended transport
   without re-entering or recreating the original hook;
4. worker-generation ownership and cleanup when a deployment retires, fails or
   loses its connection;
5. bounded suspension count, bytes and lifetime, with deterministic teardown.

An addon-local `asyncio` task is not sufficient in the current IPC model: the
worker event loop runs while processing a request and is not an independent
transport control plane. Implementing a short sleep inside the hook would pass
a demo but would not provide mitmproxy-compatible interception.

Required tests include H1 close versus H2 stream reset for termination, two H2
streams where only one is killed, resume after the normal callback timeout,
deployment retirement with suspended flows, connection loss, duplicate resume,
and quota exhaustion without forwarding held bytes.

## Evidence and release gates

- `addon_*_contract.py` and `tests/corpus/addon_*_v12.json`: deterministic
  black-box observations compared with Spider-owned objects, without a reference
  dependency in the normal test run.
- `tests/probes/addon_local_response_probe.py` and
  `tests/corpus/addon_local_response_v12.json`: opt-in loopback observation of
  actual mitmproxy 12.3.1 hook order and HTTP/1 wire output for responses created
  in `requestheaders()` or `request()`. The corpus fixes the otherwise
  non-obvious behavior that `request()` still follows an early local response,
  both response hooks run, and their mutations reach the client. Trailers remain
  visible to both response hooks but disappear from an ordinary Content-Length
  HTTP/1 local response.
- A separate bounded HTTP/1 probe records the explicit chunked case. Reference
  12.3.1 sends the response head and one data chunk, but neither the zero chunk
  nor trailers, and then remains idle beyond the probe deadline. This is evidence
  of a reference failure, not a compatibility target: Spider's native helper
  must either publish a complete valid chunked response or reject the operation
  atomically. It must never reproduce an indefinitely incomplete message.
- The companion HTTP/1 pipeline probe sends two complete requests before reading
  either response. Reference 12.3.1 processes the local-response lifecycle for
  the first flow before dispatching the second and returns the two mutated
  responses in request order. This is a concrete ordering target for the proposed
  native reverse-output queue, not permission for the adapter to serialize a
  response itself. Three consecutive isolated runs reproduced the corpus.
- `tests/probes/addon_local_response_h2_probe.py` and its H2 corpus repeat that
  observation over one real TLS/ALPN HTTP/2 connection with four multiplexed
  streams. They cover responses created in either request hook, response-hook
  mutation, final HEADERS, content-length repair, DATA delivery, ordered duplicate
  trailers and END_STREAM behavior without contacting an origin server. The
  reference also preserves an explicitly assigned body on status 204 and emits
  it as DATA with a matching Content-Length. That surprising behavior is recorded
  as an exact compatibility target. The native local-response helper now makes
  that protocol policy explicit and its differential test verifies the resulting
  DATA and Content-Length. A trailer added with mixed-case spelling by the response
  hook is emitted with that spelling, which strict HTTP/2 clients reject. Spider
  must retain its native lowercase validation rather than reproduce invalid wire
  bytes; compatibility comparison should canonicalize this field name. Three
  consecutive isolated reference runs reproduced the multiplexed corpus exactly.
- `tests/probes/addon_h2_flow_control_probe.py` records a separate bounded
  flow-control case. Two local responses share one real TLS/ALPN HTTP/2
  connection; one body is 150 KiB and therefore crosses the initial stream and
  connection windows, while the other is a small sibling stream. The corpus
  compares statuses, application fields, body lengths, body digests and clean
  stream termination rather than implementation-specific DATA segmentation.
  Spider's native event-driver test drains the same pair through its real
  reverse-output queues and credit ledger. Three consecutive isolated reference
  runs reproduced the corpus exactly.
- `tests/probes/addon_early_body_probe.py` and
  `tests/corpus/addon_early_body_v12.json` record the counterintuitive header-hook
  body behavior. Assigning `content` is callback-visible and adjusts
  `Content-Length`, but the subsequently observed body replaces that provisional
  value before the completed-message hook. Spider reproduces the callback
  semantics. Native HTTP/1 publication still repairs inconsistent framing rather
  than reproducing the reference's truncated wire output.
- `tests/probes/addon_kill_probe.py` and `tests/corpus/addon_kill_v12.json`
  observe actual `flow.kill()` behavior. Killing in either request hook closes
  the client connection without HTTP bytes, immediately changes `live`,
  `killable` and `error`, suppresses later request/response hooks, and delivers
  one `error()` callback with `Connection killed.`.
- The companion HTTP/2 kill probe fixes a protocol-specific distinction: the
  same flow transition emits `RST_STREAM(INTERNAL_ERROR)` for the selected
  stream and leaves the multiplexed client connection available. A future
  native action must therefore be message/stream aware rather than a generic
  socket-close flag.
- A two-stream H2 probe proves isolation rather than inferring it from an open
  socket: the killed stream receives `RST_STREAM(INTERNAL_ERROR)` and never
  reaches the origin, while its peer stream on the same client connection runs
  through request and response hooks and returns normally.
- The request-side H2 probe also has a `requestheaders` late-DATA case. The
  client sends a valid eight-byte body in two DATA frames after the header hook
  has killed the stream but before it receives the reset. The reference invokes
  no completed-request hook, forwards neither headers nor body to the origin,
  emits one error hook, and completes the sibling stream normally. Three
  isolated runs reproduced the corpus exactly.
- `tests/probes/addon_kill_response_probe.py` and the companion multiplexed H2
  probe cover `flow.kill()` from `responseheaders` and `response`. HTTP/1 emits
  no response bytes in either case. HTTP/2 resets only the selected downstream
  stream with `INTERNAL_ERROR`; sibling streams finish normally. A kill in
  `responseheaders` receives one later `error()` hook, while a kill in the
  terminal `response` hook does not. The H2 corpus groups hooks per flow so it
  fixes strict lifecycle order without treating cross-stream scheduling as an
  API guarantee. Its responseheaders case deliberately leaves the upstream
  response body incomplete and observes no second wire reset.
- The H2 response probe also has an opt-in late-DATA case. The origin sends
  fragmented response bodies on all live streams and, after the
  `responseheaders` kill, sends two valid DATA frames for the killed stream.
  The reference still publishes no response headers or body for that stream,
  resets only its downstream side with `INTERNAL_ERROR`, and completes both
  siblings normally. Three isolated runs reproduced the corpus exactly. This
  fixes the required discard behavior without assuming that the reference
  sends an upstream reset: none was observed.
- `tests/probes/addon_streaming_probe.py` records the basic HTTP/1 streaming
  lifecycle against a disposable origin. Once streaming is enabled from a
  headers hook, both completed-message hooks receive `raw_content is None`,
  while the unbuffered request and response bodies still reach the origin and
  client. This separates transport delivery from the intentionally absent
  buffered message body.
- The TLS/ALPN HTTP/2 streaming probe establishes the same public lifecycle on
  a real H2 client and origin connection. Request and response data reaches the
  opposite endpoint, final hooks still receive no buffered `raw_content`, and
  normal HEADERS/DATA/END_STREAM delivery is preserved.
- `tests/addon_streaming_contract_test.py` registers both HTTP/1 and HTTP/2
  reference corpora as executable compatibility gates. It fixes hook order,
  the transition selected in each headers hook, absent buffered content in
  completed-message hooks, and unchanged end-to-end body delivery.
- The response-pipeline contract registers the pipelined local-response and
  HTTP/1 trailer corpora. It preserves local-response hook and wire ordering,
  response-hook mutation, and the reference's explicit live and chunked-local
  trailer limitations instead of silently treating those cases as supported.
- The reroute contract fixes the reference's upstream-selection semantics for
  destination changes made in either request hook. The original destination
  is not contacted, the Host header changes with the connection target, and
  the selected origin response reaches the client. Native production remains
  approval-gated as described below.
- The transport reference contract registers the TCP, UDP and TLS corpora. It
  guards directional message mutation, message-history growth, endpoint wire
  results, ClientHello observation, and client/server TLS handshake ordering.
- `tests/probes/addon_intercept_probe.py` records a real suspended request and
  asynchronous resume. `intercept()` keeps the flow live, toggles
  `intercepted`, and blocks forwarding after the request hook returns. A later
  `resume()` clears the flag and continues the same flow through the ordinary
  response hooks to the client. The strengthened corpus records stable flow
  identity and proves that the origin receives the request only after the
  background resume; four registered contract tests guard ordering, state and
  final wire output.
- `tests/probes/addon_reroute_probe.py` uses two disposable origins to prove
  that changing request `host` and `port` in either request hook selects the
  new upstream, updates the Host header and never contacts the original
  destination. This is connection routing behavior, not merely a header draft
  edit, so the facade must not claim support until a native upstream-selection
  primitive exists.
- `tests/probes/addon_tcp_probe.py` exercises the public raw TCP lifecycle in
  reverse mode. `tcp_start`, directional `tcp_message` callbacks and `tcp_end`
  are observed on a real connection; size-changing mutations in both directions
  reach the origin and client. This corpus is the transport acceptance target
  for the existing TCP flow/message facade.
- `tests/probes/addon_udp_probe.py` records the equivalent datagram lifecycle in
  reverse UDP mode. One client datagram and one origin datagram each produce a
  directional `udp_message`; size-changing mutations preserve datagram
  boundaries and reach the opposite endpoint before `udp_end`.
- `tests/probes/addon_websocket_transport_probe.py` upgrades a real HTTP/1
  connection through the reference proxy and exchanges RFC 6455 frames with a
  disposable origin. The resulting transport corpus fixes the public lifecycle
  as `websocket_start`, one callback per directional message, and
  `websocket_end`. Size-changing text mutations reach both peers, the same
  message list grows before each callback, and the closing handshake remains
  intact. This is the live acceptance target; the existing detached WebSocket
  data model alone does not satisfy it.
- `tests/probes/addon_dns_transport_probe.py` sends a real UDP DNS query into
  reference DNS-server mode. The addon creates a local answer during
  `dns_request`, then mutates that answer during `dns_response`; the final
  address, TTL, query identity and response flags are verified from the wire.
  The corpus therefore distinguishes a useful DNS compatibility contract from
  registration of otherwise disconnected hook names.
- `tests/probes/addon_tls_transport_probe.py` places the reference between a
  local TLS client and origin and records the public TLS connection state. In
  eager mode the observed order is client hello, server-side start and
  establishment, then client-side start and establishment. SNI is available on
  the ClientHello and both established connections, while ALPN and TLS version
  are absent from start hooks and populated after each handshake. This lifecycle
  cannot be represented by disconnected HTTP callbacks after decryption.
- `addon_parts_test.py` and `inspection_translate_message_test.py`: native
  message mapping, completion, mutation and publication behavior.
- `addon_worker_test.py` and `addon_sandbox_test.py`: real worker IPC, sandbox,
  generation state and native translation, rather than a mock transport.
- `addon_deployment_test.cpp` and `inspection_pool_test.cpp`: backend selection,
  deployment lifecycle, shared worker state, teardown races and worker loss.
- `inspection_translate_windows_test.py`: native H2 flow-control regression
  coverage; this alone does not prove complete addon compatibility.
- `inspection_cpu_guard_test.cpp`: supervisor CPU-budget tests, including
  exhaustion and ownership. The pool now spawns and reaps workers through this
  guard. Each IPC exchange grants at most its remaining wall-clock budget
  (capped at three seconds of CPU), followed by a 100 ms idle allowance.
  `inspection_pool_test.cpp` additionally exercises a real addon over 1,400
  connections, exceeding both 4,096 IPC calls and two cumulative CPU seconds
  while preserving PID and script state. Native scripts keep their existing
  cumulative kernel CPU limit and rolling retirement policy. Direct standalone
  workers without the supervised launch flag retain the old hard CPU limit.
  Healthy addon retirement sends a dedicated shutdown request and allows cleanup at most
  500 ms of wall time and CPU time before forced termination. Cleanup is outside
  the pool and configuration mutexes. Tests cover asynchronous `done()` exactly
  once, repeated retirement and CPU-bound or sleeping cleanup that never returns.
  A structured native-script error keeps its healthy worker and remaining pool
  capacity; it is not confused with an IPC failure. Workers that time out,
  violate the worker protocol, exceed a hard resource limit or otherwise lose
  their channel are terminated. Invalidated addon generations are also retired
  because arbitrary addon globals cannot be rolled back. None of these failure
  paths retry user cleanup. Cleanup output
  and failures return in a separate bounded IPC report, retained in the pool's
  `shutdown` status. Normal callback responses remain separate. A one-time handoff
  records the report in the existing bounded inspection history, tagged with
  `phase: shutdown` and the old script ID. Either configuration retirement or
  the finishing in-flight callback delivers it. The frontend labels these entries
  as shutdown rather than an unnamed session. Standalone EOF shutdown still uses
  stderr for its diagnostics.
  If a callback fails after retirement begins, history explicitly records
  `cleanup_skipped: true` rather than retrying cleanup in the failed worker.
  The deployment integration test covers a callback timeout during removal.
  A concurrent-retirement test initially missed its history entry in one parallel
  run. The former test relied on an awaited sleep and could let the callback finish
  before removal reached the pool. It now uses an explicit release barrier: the
  callback first owns the generation worker, deployment removal retires that busy
  owner, and only then does the test permit the callback to finish. This establishes
  the intended ordering instead of increasing a timeout. The rebuilt integration
  binary passed once in isolation and four times in parallel with the deterministic
  barrier. Detailed callback and history diagnostics remain enabled; this test
  proves its retirement ordering but is not a claim that every possible race is
  covered.
  After tightening admission synchronization and adding timeout-during-removal
  coverage, the full 55-test CTest suite passed, followed by ten consecutive
  deployment integration runs (2026-10-30). A later 20-run `until-fail` stress
  passed outside the restricted development sandbox in 176.87 seconds. The same
  binary predictably loses its worker channel inside that sandbox because process
  IPC is denied; one successful unsandboxed run before the stress separated this
  environment failure from the retirement race under test.

Before release, expand this inventory against the target public API, exercise
the missing live paths, compare observable results with the reference, and
document every remaining incompatibility. Do not label the implementation a
1:1 drop-in replacement while the table above still contains required gaps.

Earlier regression checkpoint (2026-10-30): rebuilt the bundled worker and C++
targets after dynamic registration, hook invocation and interrupted-broadcast
diagnostic changes. All 55 CTest entries passed with two parallel jobs (94.43 s).
The isolated 12.3.1 registration probe also reproduced the stored corpus exactly.
This validates the current regression suite, not the unimplemented capabilities
listed above.

WebSocket checkpoint (2026-10-30): rebuilt with an independent virtual environment
containing wsproto 1.3.2 and no mitmproxy installation. The full 56-entry CTest run
passed 55 entries; the addon worker suite exposed excessive test-only source
quoting at the 120 KiB launcher guard. The dependency-absence test now prefixes
its import blocker to the ordinary production launcher instead of re-quoting the
worker source, retaining the same size guard. All 15 worker tests then passed,
including a separate successful CTest rerun. The entire suite has not yet been
rerun after that harness-only correction at that checkpoint.

Subsequent complete rerun: all 56 CTest entries passed with two parallel jobs
(97.93 s), including the corrected dependency-absence harness and packaged
WebSocket support. The independent test environment has no mitmproxy package.

Command-type and proxy-mode checkpoint (2026-10-30): the extended command
corpora now cover 57 collection/return cases and 76 public annotation/type-manager
cases against mitmproxy 12.3.1. A separate 34-case corpus covers proxy-mode
parsing and state. Packaged-worker tests exercise live H2 mutation through Flow,
Choice, bytes, CutSpec and Marker commands, plus non-regular proxy-mode state.

Command-parser checkpoint (2026-10-30): public incremental parsing, parser
helpers and registered `Command` metadata/dump behavior were added from
independent 12.3.1 observations. Targeted command, connection and packaged-worker
tests passed (9, 13 and 19 tests respectively). The worker was then rebuilt and
the complete serial CTest suite passed: **57/57 tests**, 217.93 seconds.
After rebuilding the embedded worker, all 57 CTest entries passed serially
(220.61 s). A preceding two-job run passed 56 entries and exceeded the existing
15-second `inspection_tests` timeout by 0.12 seconds; the same test passed alone
and in the serial suite in 14.41 seconds.
The former zlib/Base64 worker launcher measured 121,877 bytes against its
122,880-byte build guard, leaving only 1,003 bytes of headroom. A local comparison
of identical trusted source gave 103,740 base64 bytes with standard-library LZMA
versus 121,768 with zlib; average decode times over 20 runs were 4.30 ms and
1.81 ms respectively. Packaging has not yet switched compression formats; this
measurement identified a near-term build-capacity issue, not an API limitation.

Public-helper checkpoint (2026-10-30): clean-room log values, documented flow
filters and the selected public string helpers were added to the packaged worker.
Command parsing, options (including optional scalar declarations), addon-manager
identity helpers and flow-filter compilation state were rechecked. After rebuilding
the embedded worker and all C++ targets, the complete serial CTest suite passed:
**60/60 tests**, 216.01 seconds. The normal test environment does not import or
require mitmproxy.

The launcher subsequently switched to standard-library LZMA (XZ, preset 6),
without changing the 120 KiB size guard or lazy module loading. Its measured size
was 103,849 bytes with Base64, leaving 19,031 bytes of headroom at that checkpoint.
Build and eight selected
CTest suites passed, covering native execution, addon deployment, persistent pool,
sandbox, worker protocol and reproducible packaging. This is capacity headroom,
not a promise that future unlimited source growth will fit the exec argument.

HTTP/1 execution checkpoint (2026-10-30): direct publication tests passed 55
cases and the packaged worker passed 21 cases, including real HTTP/1 request and
response pairing plus a retained body resumed from a native checkpoint. The
native API, hold and chunked suites passed 13, 13 and 21 cases respectively.
The generated worker and all C++ targets rebuilt successfully. The complete
CTest suite then passed **60/60 tests** serially in 218.25 seconds outside the
restricted development sandbox. A preceding sandboxed run denied loopback
sockets, forkserver IPC and worker CPU-clock supervision; those environment
failures are not recorded as product test results.

HTTP/1 pipeline and trailer checkpoint (2026-10-30): typed publication tests
now pass 59 cases. They cover fully annotated request and response pipelines,
interim responses, and completed prefixes followed by a retained request or
response body. The packaged worker passes 22 cases. Native hold and chunked
suites pass 14 and 23 cases respectively; the latter includes ordered trailer
replacement, declaration repair, forbidden fields and exact no-op publication.
All 13 generated API-example tests pass on empty, HTTP/1 and HTTP/2 fixtures.
After rebuilding the embedded worker and C++ targets, the complete serial CTest
suite passed **60/60 tests** outside the restricted sandbox in 221.96 seconds.

The first end-to-end differential wire corpus now runs one human-written addon
unchanged through mitmproxy 12.3.1 and through Spider's packaged persistent
worker. Across three separate connections it compares stateful request numbering,
method and target replacement, request and response body replacement, status and
reason replacement, duplicate header order, repaired Content-Length and decoded
mutation with gzip preserved on the wire. The
corpus deliberately excludes transport-owned headers such as the reverse
proxy's rewritten Host value. This is a real output comparison, not just two
independent object-model assertions. A companion live TLS probe negotiates H2
on both sides of the reference proxy and compares the same addon's request and
response mutations with Spider's native H2 Translate output. Both corpora are
deterministic on a second reference run. These are still initial scenario
families and do not claim broad wire equivalence yet.

A second live HTTP/1 corpus sends two requests back-to-back before reading a
response. The same addon keeps generation state, stores per-flow sequence state,
rewrites both request targets and then changes each matching response status,
reason, headers and formerly empty body. The reference origin and client output
match Spider's single-callback typed request/response pipelines exactly,
including FIFO flow identity and repaired Content-Length. The reference probe
reproduced the corpus on a second isolated run. This covers one complete
pipeline shape; partial heads and mixed opaque/typed groups remain governed by
the explicit producer-boundary limitations above.

The corresponding live TLS/H2 corpus opens streams 1 and 3 together and makes
the origin complete stream 3 first. Reference 12.3.1 and Spider agree on shared
request numbering, per-flow metadata, rewritten request paths, reverse-order
response hooks, status/header/body mutation, repaired Content-Length and final
stream identity. Both downstream and upstream reference legs negotiate H2, and
the corpus reproduced exactly on a second run. This closes the tested
multiplexed-order scenario, not the separately documented GOAWAY, reset, push,
streaming or synthetic-response gaps.

A dedicated live TLS/H2 trailer corpus sends request and response bodies followed
by trailing HEADERS. The addon reads an existing trailer, removes another field
and installs two ordered duplicate trailers in each direction. The origin/client
observations from reference 12.3.1 and Spider's native Translate output agree
exactly, and a second isolated reference run reproduced the corpus. This tests
complete trailer mutation on one stream; malformed trailers and multiplexed
trailer scheduling remain covered by native validation rather than this live
reference scenario.

The original single-stream H2 differential scenario also runs with each body
split across two native callbacks. Request and response hooks still run once,
held headers and prefixes publish only with the completed body, and the combined
wire output remains equal to the live 12.3.1 corpus. The test carries independent
HPACK checkpoints for the two directions while sharing the connection-level
flow-control checkpoint, matching production state ownership rather than
accidentally teaching one peer about the other peer's dynamic table.

The corresponding HTTP/1 scenario also splits both request and response bodies
across native callbacks. It resumes from the retained Parts checkpoint and
compares the joined request and response bytes with the same live 12.3.1 corpus
used by the complete-message test. This proves that fragmentation does not alter
the addon's observable mutation result for that exchange; it does not claim that
unannotated partial start lines or headers can be classified by the adapter.

A second HTTP/1 differential matrix adds 64 stateful request/response pairs.
It varies input methods, query mutation, body sizes, gzip placement, header
removal, ordered duplicate replacement, request/response status changes and
decoded body rewrites. Comparison canonicalizes header-name groups to avoid
claiming that transport-owned field placement is addon behavior, but preserves
duplicate value order. All 128 transformed messages match the checked-in v12.3.1
reference corpus, and a second reference run reproduces it exactly.
The same 128-message semantic matrix is also emitted through native H2 Translate
using isolated per-flow checkpoints and compared with those reference outcomes;
HTTP/2 omits the HTTP/1 reason phrase by design. The independent live TLS/H2
corpus above remains the protocol-specific reference check rather than implying
that an HTTP/1 observation alone proves H2 behavior.

The growing compatibility facade later reached the guard again. The launcher
encoding therefore changed from Base64 to deterministic Base85 while retaining
the same XZ payload, one shell-independent argument and the original 120 KiB
guard. No runtime module, file extraction or reference dependency was added.
The same facade checkpoint adds the public connection type aliases, WebSocket
opcode/state types, and the complete 64-entry HTTP status-code and reason-phrase
contract observed from 12.3.1. These are detached values only; they do not claim
new transport capabilities. After rebuilding the Base85 launcher and all native
targets, the complete serial CTest suite passed **61/61 tests** outside the
restricted sandbox in 229.07 seconds. The integration test that repeatedly
starts workers now has a 30-second outer CTest watchdog; its internal deadlines
are unchanged and the successful full-suite run completed it in 15.10 seconds.

Public HTTP-helper checkpoint (2026-10-30): the remaining documented string
utilities match a 52-case black-box corpus, including hexdump formatting,
binary/XML heuristics and protected-area escaping. The public URL module matches
76 independently observed 12.3.1 cases across text/byte URLs, authorities,
default ports, query encoding and validation. Public Cookie and Set-Cookie
parse/format/group/expiry helpers reuse the same duplicate-preserving message
model and have dedicated expiry and refresh tests. These helpers are also
available through the canonical nested modules and `mitmproxy.http` attributes.

The nested HTTP helper surface also provides the independently observed v12
Content-Type parser/assembler and charset inference rules, Content-Length and
Transfer-Encoding validation, and multipart form encode/decode helpers. The
multipart public helper and `Request.multipart_form` now share one implementation;
the existing 68-case multipart corpus and native publication tests therefore
guard both paths. Deprecated multipart aliases are not advertised as complete.

Shared-facade and generation-stress checkpoint (2026-10-30): public
`mitmproxy.net.encoding` now owns the content codec implementation also used by
HTTP message objects, and `mitmproxy.utils.human` exposes the observed formatting
helpers. Exact gzip/deflate/Brotli/Zstandard bytes and boundary behavior are
covered, with packaged-worker imports. A native integration regression opens 48
flows on one addon deployment, proves that every callback observes one process
and monotonically shared script state, then removes the deployment while all
flows remain owned. Every pending flow receives teardown before one final
`done()` callback. After rebuilding the embedded worker and all native targets,
the complete serial CTest suite passed **65/65 tests** outside the restricted
sandbox in 235.41 seconds.

After adding the explicit 12.3.1 version contract and the nested HTTP helper
tests, rebuilding the embedded worker and every native target, the complete
serial CTest suite passed **69/69 tests** outside the restricted sandbox in
238.67 seconds. Generated API documentation and whitespace checks remain
separate release gates.

Worker-packaging and public-surface checkpoint (2026-10-30): the deterministic
Bzip2/Base85 launcher now uses bounded argument chunks instead of relying on one
near-limit exec argument. The production C++ supervisor and direct bootstrap
tests use the same argument vector. The public facade also exposes the observed
12.3.1 exception hierarchy, options module, and HTTP Data state classes. The
targeted deployment, public-surface, worker and bootstrap CTest groups passed
4/4 outside the restricted sandbox. A subsequent serial run passed 69 groups
and found two stale test inventories after the new exception module was added;
both corrected groups then passed directly and through CTest. A deliberately
stopped confirmation run passed its first 30/30 groups, including both fixes.
This is not recorded as a complete 71-group rerun.

DNS facade checkpoint (2026-10-30): the detached DNS model now includes public
copy/JSON conversion, offset decoding, HTTPS/SVCB values and ALPN/ECH helpers.
An independently generated 12.3.1 corpus covers their state, JSON and wire
representations. The 13-case DNS model suite, 23-case packaged-worker suite,
reference-corpus verifier, bytecode compilation and whitespace checks pass.
Live DNS hooks remain outside this detached-model checkpoint.

Built-in option checkpoint (2026-10-30): `mitmproxy.options.Options` now exposes
the independently observed 29-option v12.3.1 default inventory, while
`mitmproxy.optmanager.OptManager` remains the empty generic registry used for
custom option contract tests. Defaults, types, constructor updates and changed
state match the reference corpus. These values do not create proxy listeners;
applicable live Spider settings still need an explicit projection contract.
The 17-case option, 30-case runtime and 23-case packaged-worker suites pass.

Server-spec checkpoint (2026-10-30): the clean-room
`mitmproxy.net.server_spec` facade matches 890 independently recorded 12.3.1
parse outcomes across every public scheme and default, explicit and default
ports, IPv4, IPv6 zones, IDNs and rejected syntax. Proxy-mode validation reuses
the same parser while preserving its existing public errors. This is a pure,
cached parser: it performs no DNS lookup, opens no socket and grants no transport
capability. The server-spec, proxy-mode and packaged-worker suites pass together.
After rebuilding the embedded worker and native targets, the complete serial
CTest suite passed **72/72 tests** outside the restricted sandbox in 214.52
seconds.

The public human helper module now also matches the observed address formatter
and binary size parser, including IPv6 bracket formatting, optional unit suffixes
and invalid-input errors. These helpers are exercised from a deployed addon in
the packaged worker; they do not inspect or alter live connection state.

Serializable-object checkpoint (2026-10-30): public
`mitmproxy.coretypes.serializable` bases now underpin the facade's headers,
messages, flows, connections, proxy modes, certificates, WebSocket values and
DNS values. The generic dataclass contract validates and reconstructs supported
primitive, optional, sequence, tuple, mapping, literal, enum and nested
serializable fields; unsupported broad unions and opaque `Any` values fail
explicitly. A 50-case black-box corpus now fixes the reference's less obvious
numeric coercion, sequence conversion, enum/literal failure and input-state
consumption behavior instead of relying on an inferred implementation. Ten
affected model and packaged-worker suites pass against that corpus. The full
suite passed **73/73 tests** immediately before the corpus refinement; the
affected targeted suites passed again afterwards. This adds no wire parser,
socket behavior or transport authority.

Saved-flow checkpoint (2026-10-30): the facade now supplies clean-room
`mitmproxy.io` reader, writer, filtered writer and path-loading APIs, backed by
an independent implementation of the public tagged-netstring format. A
black-box 12.3.1 corpus fixes primitive encoding, reverse mapping order,
malformed-input behavior, filtering and deterministic HTTP flow bytes. The
public `split()` and `parse()` helpers also match the reference's memoryview
contract, return types and error messages without expanding the module's star
exports. The same deterministic flow is byte-for-byte identical in both
writers, and files written by either implementation are read by the other.
Deterministic TCP, UDP, DNS and WebSocket observations additionally verify
ordered stream chunks, preserved datagram boundaries, complete DNS
request/response state and saved WebSocket close/message state through the
same format. This is persistent observation
interchange only; restoring a flow never resurrects live sockets or grants
transport control. After rebuilding the packaged worker, the full
suite passed **74/74 tests** with two parallel jobs in 109.64 seconds outside
the restricted sandbox.

Live addon flows now receive `Client` and `Server` descriptor objects even when
the native callback has no endpoint metadata. Their address fields remain
`None`; the adapter does not invent values from display labels. Addons can use
the public descriptor surface consistently, but `Client.get_state()` correctly
rejects an incomplete address observation. Consequently direct saving of such
a live flow remains unavailable until the producer supplies real endpoint
metadata. A packaged-worker integration test saves and restores a detached flow
with explicit descriptors and applies the restored request to native H2 output.

Core class-surface checkpoint (2026-10-30): an independently recorded v12.3.1
corpus now fixes every public class attribute on the 18 central addon value
classes: HTTP messages and flows, connections, TCP/UDP values, DNS values and
WebSocket values. Spider's facade matches that inventory exactly. The comparison
also found and corrected the reference's class-level `DNSFlow.response` default;
this is a zero-impact facade addition, not live DNS transport support. Exact
attribute presence complements the behavioral corpora but does not make every
attribute a supported live transport operation.

Expanded differential checkpoint (2026-10-30): the HTTP mutation corpus now
contains 64 deterministic request/response pairs, or 128 transformed messages.
Both the HTTP/1 Rewrite and HTTP/2 Translate drivers reproduce its application
semantics. Additional live corpora cover fragmented HTTP/1 and HTTP/2 messages,
ordered HTTP/2 trailers and the reference's explicit HTTP/1 trailer limitation.
The asynchronous command corpus also fixes the distinction between awaitable
typed calls and rejected textual calls in v12.3.1. After rebuilding every
native target and the embedded worker, the complete serial CTest suite passed
**74/74 tests** outside the restricted sandbox in 223.57 seconds.

Synthetic-response reference checkpoint (2026-10-30): isolated 12.3.1 probes
now cover two pipelined HTTP/1 requests and four multiplexed HTTP/2 streams,
including creation from either request hook, response-hook mutation, a body on
status 204 and ordered duplicate trailers. Separate bounded evidence records
the reference's incomplete HTTP/1 chunked-trailer output; that failure is an
explicit safety divergence, not behavior Spider should reproduce. The affected
corpora reproduced in three consecutive reference runs. Canonical module aliases
imported by `http`, `connection` and `flow` also match an independent reference
inventory without adding another implementation layer. The same corpus fixes
the nine modules that define `__all__` and their exact export order; other
facade modules no longer invent restrictive star-import lists absent from the
reference. The production worker rebuilt successfully, and the public-surface
plus packaged-worker CTest groups passed 2/2. HTTP/2 body reservations now use
an unambiguous source `Content-Length` when available, while unknown or
ambiguous lengths retain the conservative configured maximum. This permits
multiple bounded streams to share the aggregate budget without allowing addon
header mutations to weaken native accounting. The Parts, public-surface and
packaged-worker CTest groups pass 3/3; their direct Python suites cover 64 Parts
and 35 packaged-worker cases.

Coverage checkpoint (2026-10-30): all 356 direct `addon_*` unit and publication
tests pass under branch instrumentation. The 5,264 executable statements across
the production `addon_*.py` modules have 94% combined statement/branch coverage.
This measurement exposed and corrected one stale expected `__all__` order after
the canonical-module inventory changed. Loader coverage rose from 81% to 98%
with explicit tests for post-load child discovery, failed atomic discovery,
sync/async callback boundaries, scoped imports and single-shot execution. Native
adapter coverage rose from 83% to 93% with dedicated fail-closed lifecycle tests.
The complete Parts suite originally passed 66 cases, including explicit H1/H2
rejection of kill, intercept and streaming decisions. Local responses have
since moved onto the native transport primitive described above. Coverage is a
regression signal, not a substitute for the
remaining live-transport capabilities in the table above.

Saved-flow I/O checkpoint (2026-10-30): a new black-box v12.3.1 corpus fixes
`read_flows_from_paths()` failures for a missing path and a directory. Spider now
matches the public `FlowReadException` text and intentionally exposes no chained
filesystem exception, avoiding host-path leakage through `__cause__`. The reader
also has a regression proving that a complete flow prefix is yielded before a
corrupt trailing record is reported. The independent reference probe and all 11
local saved-flow tests pass.

Full regression checkpoint (2026-10-30): after the adaptive H2 reservation,
loader-boundary, transport-decision and saved-flow I/O changes, every generated
worker and native target was rebuilt. The complete two-job CTest suite passed
**74/74 tests** outside the restricted sandbox in 112.70 seconds.

Concurrent lifecycle checkpoint (2026-10-30): an independent 12.3.1 corpus
fixes the complete public `mitmproxy.script.concurrent` surface and execution
contract. Exactly `running`, `update` and `done` are accepted; traffic hooks
remain rejected as in the reference. Regular and coroutine callbacks execute
on one generation-owned thread, discard return values, propagate exceptions
and retain the same module and addon state as every other connection served by
that worker. The runner uses an event loop and an ordinary nonblocking pipe
created before the sandbox is installed. A generation-local FIFO publishes
callbacks and wakes the selector through that pipe, so progress does not depend
on CPython's private socket wakeup or on an unrelated event arriving later.
Seccomp permits only pthread's exact shared-process clone flags, the prepared
epoll descriptors and already-created internal descriptors. `fork`, process-
shaped clone flags, new sockets and external network operations remain denied
in both the main worker and the inherited callback thread. Contract,
public-surface, kernel-policy and
packaged-worker integration tests cover this boundary; it does not enable
concurrent traffic callbacks or create another transport scheduler.
All **369** direct addon tests pass, including the reference corpus and the
thread/process sandbox boundary. After rebuilding the embedded worker and all
native targets, the complete two-job CTest suite passed **75/75 tests** outside
the restricted outer sandbox in 113.75 seconds.

Content-view and deployment-options checkpoint (2026-10-30): the clean-room
content-view facade now supports generation-local registration, lookup,
priority selection and rendering without importing a second presentation
stack. The public `ContentviewResult` value matches the 12.3.1 data contract.
Spider does not advertise the reference `ContentviewRegistry` class: a newly
constructed reference registry contains its built-in `auto` renderer, while a
Spider generation deliberately contains only addon-provided views. Exporting
the name without that behavior would be false compatibility. Per-deployment
addon option overrides use the same typed option parser
as the runtime and are applied after `load`, but before the initial `configure`
and `running` callbacks. Omitted overrides preserve the deployed values;
invalid values reject preview or deployment atomically. Native scripts cannot
receive compatibility-only options. Packaging uses one explicit worker-module
manifest shared by CMake and its regression tests, preventing the embedded
worker from silently omitting a newly added facade module. All **377** direct
addon tests pass. After rebuilding the embedded worker and native targets, the
complete serial CTest suite passed **76/76 tests** outside the restricted outer
sandbox in 232.72 seconds; a headless browser smoke test also exercised the
option field through preview and deployment.

Worker-ownership checkpoint (2026-10-30): one runtime object now owns the
generation's event loop, addon adapter, concurrent callback runner and startup
diagnostics. Startup failure, normal shutdown and aborted cleanup therefore use
the same idempotent lifecycle instead of coordinating module-level globals and
duplicate teardown paths. This is an internal simplification only; the worker
protocol and its failure diagnostics are unchanged. The production dependency
audit confirms that the deployed worker neither imports nor installs
`mitmproxy`; compatibility remains a clean-room facade over Spider's native
inspection API. All **377** direct addon tests still pass. After rebuilding the
embedded worker, the focused selection and packaged-worker tests passed 2/2,
and the complete two-job CTest suite passed **76/76 tests** outside the
restricted outer sandbox in 117.17 seconds.

Public-surface audit checkpoint (2026-10-30): black-box inspection of the
declared content-view module added the exact mutable `ContentviewResult` data
contract. The audit deliberately did not expose `ContentviewRegistry`: a fresh
reference registry contains the built-in `auto` renderer, while Spider's
generation-local registry owns only addon-provided views. All **378** direct
addon tests passed at that point. The same audit added the public
`TransferEncoding` type and both deprecated multipart encoder spellings,
including their 12.3.1 warnings and historical behavior. All **379** direct
addon tests now pass; after rebuilding the embedded worker, the content-view,
HTTP validation, multipart-helper and packaged-worker CTest targets passed 4/4
outside the restricted outer sandbox.

Tagged-netstring public-helper checkpoint (2026-10-30): black-box execution
against mitmproxy 12.3.1 now covers the directly importable `split()` and
`parse()` helpers in addition to saved-flow serialization. All **379** direct
addon tests pass. After rebuilding the embedded worker, the saved-flow and
packaged-worker CTest targets passed 2/2 outside the restricted outer sandbox.

Certificate conversion checkpoint (2026-10-30): the public `Cert` value now
includes the reference's PyOpenSSL conversion boundary. Conversion immediately
returns to the existing `cryptography`-backed value, and the reverse helper
loads PyOpenSSL only when explicitly called. A black-box 12.3.1 corpus fixes the
complete public class surface, converted type, certificate identity and exact
deprecation warning. This does not add certificate issuance, private-key access
or TLS transport authority. All **380** direct addon tests pass; after rebuilding
the embedded worker, the certificate and packaged-worker CTest targets passed
2/2 outside the restricted outer sandbox.

Logging-surface checkpoint (2026-10-30): a black-box 12.3.1 corpus now fixes
the legacy log constants, tiers, entry value and `AddLogHook` data contract.
The public hook registry consequently lists `add_log` rather than `load`, which
belongs to `mitmproxy.addonmanager` and remains fully available to the loader.
This adds no second logging pipeline: `ctx.log` still emits through Python's
standard logging module. All **380** direct addon tests pass; after rebuilding
the embedded worker, the public-surface, logging and packaged-worker CTest
targets passed 3/3 outside the restricted outer sandbox.

DNS helper checkpoint (2026-10-30): `mitmproxy.net.dns.domain_names` now
provides the public uncompressed and compression-aware RFC 1035 name helpers,
offset caching, RDATA decompression and the reference's record-type predicate.
A black-box 12.3.1 corpus covers ASCII and IDNA names, pointer caches, loops,
truncation, invalid labels, RDATA tails and every compressible type below 300.
Canonical `mitmproxy.dns` module aliases are exposed as well. This remains a
data codec and does not claim live DNS transport. All **381** direct addon tests
pass; after rebuilding the embedded worker, the DNS, public-surface and
packaged-worker CTest targets passed 3/3 outside the restricted outer sandbox.
The complete two-job CTest suite then passed **76/76 tests** in 117.11 seconds.

HTTPS-record checkpoint (2026-10-30): the companion public SVCB/HTTPS module
now exposes its record type alias, domain-name module, and `pack()`/`unpack()`
helpers. The differential corpus found and corrected two existing model
differences: `SVCParamKeys` is an `Enum`, not an integer subclass, and unknown
SVC parameter JSON keys remain integers rather than receiving an invented text
prefix. Valid records, IDNA targets, unknown parameters and truncated parameter
errors match 12.3.1. All **382** direct addon tests pass; after rebuilding the
embedded worker, the DNS, public-surface, packaged-worker and worker-bootstrap
CTest targets passed 4/4 outside the restricted outer sandbox.

Encoding checkpoint (2026-10-30): `mitmproxy.net.encoding` now exposes the
complete directly callable codec surface observed in 12.3.1, including mutable
custom codec maps, `CachedDecode`, deterministic encoder helpers and the
historical `deflateraw` aliases. The black-box corpus fixes compressed output,
concatenated and incomplete frame behavior, character-codec policies and exact
error wrapping. HTTP message objects and public helpers share one implementation
rather than carrying a facade-only codec copy. All **383** direct addon tests
passed; after rebuilding the embedded worker, the encoding and packaged-worker
CTest targets passed 2/2 outside the restricted outer sandbox.

Option type-check checkpoint (2026-10-30): the public
`mitmproxy.utils.typecheck` helpers now share their implementation with Spider's
addon option registry. An independent 12.3.1 matrix covers scalar, optional,
union and sequence acceptance, UI labels, nested failures and deliberately
unsupported generic shapes. This also corrects the native option registry's
numeric boundary: a float option accepts integral input, while a boolean option
still rejects plain integers. All **385** direct addon tests pass. After
rebuilding the embedded worker, the type-check, options, public-surface and
packaged-worker CTest targets passed 4/4 outside the restricted outer sandbox.

Signal checkpoint (2026-10-30): `mitmproxy.utils.signals` now provides the
public weak-reference sync and async signal factories plus `make_weak_ref`.
Option change/error notification uses this same implementation, removing the
last private signal copy. The 12.3.1 contract covers duplicate registration,
mutation during delivery, bound-method collection, dead-reference cleanup,
mixed synchronous/asynchronous ordering and coroutine rejection on synchronous
signals. All **386** direct addon tests pass. After rebuilding the embedded
worker, the signal, options and packaged-worker CTest targets passed 3/3 outside
the restricted outer sandbox. The subsequent complete two-job CTest suite
passed **78/78 tests** in 117.67 seconds.

Retirement-queue checkpoint (2026-10-30): generation retirement now has a
deterministic adversarial test with one callback held behind an explicit file
gate and four admitted FIFO waiters. Retirement must wake and reject every
waiter before the active callback is released; that callback may then finish,
run `done()` exactly once and publish one consumable shutdown report. The test
does not infer admission from a request counter and does not make a race pass by
extending its callback timeout. The complete pool test passed once, followed by
ten consecutive `until-fail` repetitions outside the restricted sandbox in
182.83 seconds.

Local-response implementation checkpoint (2026-10-31): `api.message.respond()`
now publishes protocol-owned H1 and H2 responses. H2 atomically updates the
peer HPACK checkpoint and uses the existing reverse queues and flow-control
ledger. H1 stores a bounded data-only origin/local slot queue in the native flow
instance, suppresses the selected request and interleaves queued local responses
after every older origin response. The implementation covers duplicate fields,
reason phrases, 204 bodies, valid complete chunked trailers, informational
responses, multiple pipelined responses, validation/quota rollback and HPACK
continuity. The Parts suite passes **83** cases, the packaged-worker suite passes
**41** cases, the H1 chunked/native transaction suite passes **30** cases and
the C++ deployment test proves checkpoint persistence and state redaction across
the real worker boundary. All **414** direct `addon_*` tests pass. Spider
deliberately emits a complete chunked trailer
response instead of reproducing the reference's recorded incomplete output.
The packaged H1 lifecycle test also matches every hook observation and every
application-owned response field in the checked-in 12.3.1 local-response corpus;
transport-owned framing fields are compared by meaning rather than spelling.
The multiplexed H2 differential test matches all four reference lifecycles and
their ordered fields, bodies, trailers and stream termination. It compares
message semantics rather than DATA-frame segmentation, and retains Spider's
stricter lowercase HTTP/2 trailer validation. A separate boundary test splits
the complete request at every byte, while a multiplexed 150 KiB response test
drains native reverse-output flow control beside a smaller sibling stream.
After rebuilding the embedded
worker and every native target, the complete serial CTest suite passed
**78/78 tests** outside the restricted sandbox in 249.55 seconds.
The subsequent local-response guard matrix rejects response replacement,
streaming and incomplete bodies at every response-hook boundary; the native
length-order regression also preserves the first Content-Length position while
collapsing duplicates. The affected Parts and Translate suites pass 73 and 134
cases respectively. A current branch-coverage audit over all 414 direct addon
tests covers 95% of 5,805 executable statements across `src/addon_*.py`; this
measurement excludes the native Python and C++ transport implementation. The
subsequent registry boundary audit takes `addon_contentviews.py` to 100% branch
coverage. Additional fail-closed tests cover invalid direction, orphan responses,
retry after generation failure and the complete retained-body limit boundary;
the affected content-view and Parts CTest targets pass 2/2.
The concurrent fallback now uses one persistent executor thread and polls its
ordinary future. It therefore preserves script-local state and does not depend
on asyncio's private selector-socket wakeup inside a restricted worker. Its
sync, coroutine and exception paths pass both the direct 11-case suite and the
dedicated CTest target without extending a shutdown timeout.
After regenerating the embedded worker and rebuilding every native target, the
complete serial CTest suite passed **78/78 tests** outside the restricted test
sandbox in 249.28 seconds.
Seven additional binding regressions cover absolute-form HTTP/1 routing,
malformed Host fields, startless groups, illegal trailers, classic HTTP/2
CONNECT, retained HPACK table-size updates and foreign or unresolved Parts.
They raise `addon_parts.py` branch coverage from 89% to 94%; all 83 Parts tests,
the dedicated CTest target and the 414-test direct aggregate pass. The Master
surface addition is also exercised inside the packaged sandboxed worker. After
regenerating that worker, the complete serial CTest suite passed **78/78 tests**
outside the restricted test sandbox in 250.60 seconds.

DNS hardening checkpoint (2026-10-31): five adversarial model cases cover
truncated HTTPS parameters and ALPN values, malformed and cyclic compressed
names, every supported record representation, message-field bounds and
truncation in every wire section. Domain encoding now normalizes IDNA failures
to the facade's public `ValueError` contract instead of leaking a codec-specific
exception. The 20-case DNS suite reaches 97% branch coverage, its dedicated
CTest target passes, and all **419** direct `addon_*` tests pass. The current
aggregate covers 95% of 5,808 executable statements across `src/addon_*.py`.

URL facade checkpoint (2026-10-31): an independently recorded 12.3.1 corpus
now compares the complete URL-helper probe inside the compatibility import
boundary. It exposed and corrected Unicode/byte hostname validation, the
reference's deliberately permissive label characters, unchecked invalid-port
authority handling and byte-oriented parsing error text. The seven-case URL
suite reaches 98% branch coverage, its dedicated CTest target passes, and all
**422** direct `addon_*` tests pass.

Serialization hardening checkpoint (2026-10-31): the HTTP header collection
contract now covers byte keys, every collection view, state restoration and
all public type errors at 100% branch coverage. A separately recorded
tagged-netstring edge corpus covers public dump/load helpers and malformed
scalar, prefix and file inputs. Spider matches the 12.3.1 outcomes except that
it intentionally reports a stable `ValueError` for a truncated file instead of
leaking the reference implementation's `IndexError`. Tagged-netstring branch
coverage is 100%. All **424** direct `addon_*` tests pass, covering 96% of
5,820 executable statements. After regenerating the embedded worker and
rebuilding every native target, the complete serial CTest suite passed
**78/78 tests** outside the restricted sandbox in 250.47 seconds.

Core-model hardening checkpoint (2026-10-31): a direct 12.3.1 multidict
corpus now covers owned values, live views and case-insensitive cookie
attributes. MultiDict, saved-flow I/O and tagged-netstring decoding each reach
100% branch coverage. SerializableDataclass reaches 99%; its only uncovered
branch is the structurally unreachable fall-through after a supported
`T | None` union. Runtime coverage reaches 98% and now proves release guards
during a real concurrent callback, content-view lifecycle guards, explicit
connection identity, and the inline configure/reconfigure order when an option
change is rejected and rolled back. The four affected CTest targets pass and
all **434** direct `addon_*` tests pass, covering 97% of 5,820 executable
statements.

Protocol-model hardening checkpoint (2026-10-31): the H1 event driver reaches
96% branch coverage without forging impossible native parser states. The native
adapter reaches 100%, including real H1 publication, ordinary hook failure and
generation invalidation after a protocol failure. DNS domain-name encoding and
decoding reaches 100%. The target mitmproxy 12 protocol documentation confirms
that HTTP/2 server push is not advertised; a native PUSH_PROMISE regression now
proves that the adapter does not invent a request callback or second HTTPFlow
and does not disturb the parent stream. The Parts suite passes **88** cases and
its dedicated CTest target passes outside the restricted sandbox. All **439**
direct `addon_*` tests pass; the unchanged 5,820-statement production set remains
at 97% aggregate branch coverage.

Flow-filter hardening checkpoint (2026-10-31): a new independently recorded
12.3.1 corpus covers 64 adversarial expressions, including quoted control
escapes, Unicode, implicit conjunction, adjacent operators, nested precedence,
numeric-prefix parsing and malformed expressions. It exposed six observable
parser differences. The clean-room parser now matches the complete corpus,
including the unusual treatment of a second `&` or `|` as a URL regex and of
the suffix in `~c 200x` as an implicit filter. The eight-case flow-filter suite
passes, its dedicated CTest target passes, and module branch coverage reaches
98% without copying the reference parser or adding its parser dependency. All
**440** direct `addon_*` tests pass, covering 97% of 5,854 executable statements.

Command-registration hardening checkpoint (2026-10-31): a new independently
recorded 12.3.1 corpus covers decorator identity and metadata, implicit and
explicit names, duplicate methods, repeated collection, replacement across
owners, valid and invalid direct replacement, invalid collected replacement,
empty names and Unicode paths. It exposed one facade difference: an empty
decorator argument must fall back to the callback name. The corrected adapter
matches the complete corpus, the command CTest target passes, and all **441**
direct `addon_*` tests pass with unchanged aggregate branch coverage of 97% over
5,854 executable statements. After the flow-filter and registration changes,
the complete two-job CTest suite passed **78/78 tests** outside the restricted
outer sandbox in 125.85 seconds. The same suite's socket and worker-IPC targets
fail closed in the restricted sandbox, while all 67 targets not requiring those
capabilities pass there.

Public-surface audit checkpoint (2026-10-31): the declared `__all__` exports of
the principal addon modules were compared with isolated mitmproxy 12.3.1. The
remaining `dir()` differences are predominantly reference implementation
imports and are intentionally not copied into the clean-room facade. The audit
identified one useful new-registry capability: `ContentviewRegistry.on_change`.
An independent corpus proves that registration publishes the new instance
before synchronously notifying listeners, duplicate replacement notifies again,
class registration reports the instantiated view, and disconnect is idempotent.
The content-view CTest target passes and all **442** direct `addon_*` tests pass,
covering 97% of 5,857 executable statements.

Content-view helper checkpoint (2026-10-31): independently observed 12.3.1
contracts now cover `get_data()`, `make_metadata()`, `prettify_message()` and
`reencode_message()` for HTTP request/response, TCP, UDP, WebSocket and DNS
messages. The adapter preserves decoded-content annotations and decode failures,
HTTP content types, optional protobuf definitions, missing content, automatic
view fallback, interactive-view enforcement and unknown-view errors. These
helpers reuse the generation-local registry rather than introducing a global
facade registry. A packaged-worker regression invokes both render and reencode
from a real HTTP request hook, observes the registry signal and verifies the
result in native translated HTTP/2 headers. The content-view and packaged-worker
CTest targets pass. All **444** direct `addon_*` tests pass, covering 97% of
5,914 executable statements.

Addon-tree helper checkpoint (2026-10-31): the public
`mitmproxy.addonmanager.traverse()` helper now exposes the reference's lazy
parent-before-children traversal over lists, tuples and generators. Its
black-box corpus covers absent, tuple and invalid `None` child collections,
non-iterable roots, empty chains, and mutation of a child list after the parent
has been yielded. Registration continues to use Spider's separately bounded,
cycle-safe manager; the public observation helper does not weaken those guards.
The loader CTest target passes and all **445** direct `addon_*` tests pass,
covering 97% of 5,918 executable statements.

Lifecycle-handler and dynamic-update checkpoint (2026-10-31): the public asynchronous
`AddonManager.handle_lifecycle()` entry point now reuses the generation-owned
event dispatcher instead of introducing another callback path. An independently
recorded 12.3.1 corpus fixes callback order, asynchronous callbacks, ordinary
failure continuation, immediate `OptionsError` propagation and rejection of an
event without arguments. A packaged-worker regression exercises the same method
from a deployed request hook and observes its result through native HTTP/2
publication. The exported `update()` lifecycle hook is now a real generation
capability rather than an import-only value. A second reference corpus proves
that add/remove do not synthesize update events, while explicit update events
reach every currently active addon in order, including asynchronous callbacks.
All **449** direct `addon_*` tests pass, covering 97% of 5,925 executable
statements.

Option-helper checkpoint (2026-10-31): `OptManager.update_defer()` now shares
one public pending-value map with deferred text configuration. Typed and textual
values replace each other deterministically, registration remains inert, and an
invalid value stays pending across explicit retries. The independently recorded
12.3.1 corpus also fixes the public `make_parser()` helper for booleans,
scalars, optional values, repeated sequences, short options and metavar text.
The parser is an ordinary caller-owned argparse boundary; it does not introduce
a second Spider CLI. All **452** direct `addon_*` tests pass, covering 97% of
5,961 executable statements.

HTTP-model adversarial checkpoint (2026-10-31): a new independent 12.3.1
corpus exercises invalid constructor content, unknown content codings, an empty
encoded body, text charset fallback, HTTP/2 authority mutation, CONNECT targets,
malformed display hosts and a missing form body. It exposed three observable
facade differences: constructor and encoding error text, plus preservation of a
malformed raw Host value in `pretty_host`. The corrected behavior changes no
wire routing or native publication decision. All **453** direct `addon_*` tests
pass; `addon_http_message.py` branch coverage rises from 95% to 97%, and the
5,961-statement aggregate remains at 97%.

Connection-model adversarial checkpoint (2026-10-31): an independent 12.3.1
corpus now fixes exact required-client-field failures, literal transport
validation, address-state validation, deprecated accessors and warning text,
state flag values, and equality with unrelated objects. The public serializer's
observable address schema accepts an empty, single-item, or extended tuple and
validates its first item as text and every remaining item as an integer. This
remains detached state behavior only; it neither accepts such values as live
endpoints nor fabricates transport metadata. All **454** direct `addon_*` tests
pass; `addon_connection.py` branch coverage rises from 94% to 97%, and the
5,965-statement aggregate remains at 97%.

Clean-room packaging checkpoint (2026-10-31): executable guards now parse both
runtime requirement sets, the complete Spider-owned addon source tree, and the
production worker module manifest. They reject a `mitmproxy` distribution
dependency, any static import of the reference package by runtime code, duplicate
manifest entries, foreign module names, and missing bundled sources. Dynamic
imports performed by user scripts still resolve only through the separately
tested generation-local facade. All **457** direct `addon_*` tests pass, with
97% aggregate branch coverage.

HTTP-header adversarial checkpoint (2026-10-31): a second independent 12.3.1
corpus covers construction failures, case-insensitive membership, missing-key
behavior, pop/setdefault/popitem/clear/update operations, generator replacement,
atomic type failure, insertion boundaries, direct field assignment, surrogate
bytes, and shallow/deep copies. It exposed only exact public error-text and
missing-delete-key differences; ordered fields and every successful mutation
already matched. The correction changes no native header publication logic.
All **458** direct `addon_*` tests pass with 97% aggregate branch coverage.

Service-surface checkpoint (2026-10-31): independently observed public class
inventories now gate `AddonManager`, `CommandManager`, `Loader`, and
`OptManager`, complementing the existing exact flow/message/model inventories.
Every v12.3.1 public method is present. Spider's manager dispatch, shutdown, and
failure-drain helpers are now private implementation details instead of
accidental API extensions. Their lifecycle behavior is unchanged and remains
covered through the public manager methods, generation runtime, and packaged
worker. All **459** direct `addon_*` tests pass with 97% aggregate branch
coverage; the focused loader, public-surface, runtime, and worker CTests pass
4/4.

Master host-boundary checkpoint (2026-10-31): the independent 12.3.1 runtime
probe now records that `master.running` is a zero-argument method and
`master.should_exit` is an `asyncio.Event`, in addition to the synchronous
`None` result and deferred exit observation for `master.shutdown()`. Spider does
not expose worker-local lookalikes for these host-owned controls. The generic,
bounded host-control design and its unresolved shutdown scopes are documented
in `docs/HOST_CONTROL_PROPOSAL.md`; no behavior is implemented without scope
approval. All **459** direct `addon_*` tests pass after this corpus extension,
with 97% aggregate branch coverage.

Detached-flow lifecycle checkpoint (2026-10-31): `master.load_flow(f)` now
matches an independent 12.3.1 corpus across HTTP, TCP, UDP, DNS and WebSocket
models. Tests fix callback ordering, response-plus-error delivery, incremental
message histories, terminal event selection, asynchronous signature, return
value, list replacement and message identity. Adversarial cases additionally fix
the exact empty-flow attribute failures and unknown-flow error. They exposed one
detached-model mismatch: like `HTTPFlow`, a fresh reference `DNSFlow` does not
create its `request` instance attribute before a message is assigned. The local
model now follows that constructor boundary. A real generation also invokes
`load_flow()` from its scoped `running()` hook, proving that callbacks retain the
bundled facade import environment. A failing replay callback is reported through
the ordinary generation diagnostics and does not prevent the following addon
from receiving the event, matching the independent reference observation. All
**462** direct `addon_*` tests pass with 97% aggregate branch coverage; rebuilt
I/O, runtime, DNS and packaged-worker CTests pass, including the updated focused
runtime target.

Registration-failure checkpoint (2026-10-31): a new independent 12.3.1 corpus
fixes four transaction boundaries that ordinary successful registration does
not reveal. It covers a deep child failure after earlier loads, a multi-root
`add()` interrupted in the middle, and independent addons registered as side
effects before a parent or sibling later fails. Spider already matched every
observed lookup, active-chain, callback and cleanup result; no production change
or compensating rollback was needed. All **463** direct `addon_*` tests pass in
the focused runtime suite. The rebuilt full CTest inventory passes **78/78**;
11 socket, fork and IPC tests rejected by the restricted runner were rerun in
the unrestricted local test environment and passed **11/11**.

HTTP/2 flow-control differential checkpoint (2026-10-31): the independent
12.3.1 reference now has a checked corpus for a 150 KiB locally generated body
and a small sibling response multiplexed on the same client connection. The
corpus is stable across three isolated runs and deliberately ignores DATA-frame
segmentation while fixing the complete message fields, length, digest and
END_STREAM result. The existing native sibling-stream regression now compares
its observable output against that corpus in addition to checking native window
drain, reservation cleanup and origin suppression. The focused test passes;
the direct test inventory remains **463** because this strengthens an existing
test rather than adding a duplicate path.

Concurrent-runner shutdown checkpoint (2026-10-31): cancelling the coroutine
that awaits a `@concurrent` lifecycle callback still does not interrupt that
callback. Generation retirement now closes admission atomically, drains any
already running callback on its persistent worker thread, and stops the private
event loop only after its task set becomes empty. This removes a real race where
an immediate retirement could close the loop with a callback still pending; no
timeout was enlarged. A focused regression cancels the await, starts retirement
while the callback is blocked, releases it from another thread, and proves both
completion and post-close admission rejection. All **464** direct addon tests
pass with 97% aggregate branch coverage over 6,024 executable statements. The
rebuilt concurrent, version, Parts and packaged-worker CTest targets pass
**4/4**. The complete rebuilt two-job CTest inventory subsequently passes
**78/78** in 126.86 seconds outside the restricted sandbox.

HTTP/1 body-boundary checkpoint (2026-10-31): addon request and response
lifecycles now run across every two-piece split of representative binary bodies,
including empty first fragments and already complete messages. Each case proves
that header and completed-message hooks run exactly once, hold/resume preserves
the original bytes, body mutation repairs Content-Length, response pairing is
retired after publication, and changing only `status_code` preserves the
original reason phrase. All **466** direct addon tests pass with 97% aggregate
branch coverage; the focused Parts CTest target passes.

Response-side termination reference checkpoint (2026-10-31): new independent
HTTP/1 and multiplexed TLS/H2 black-box probes cover `flow.kill()` from both
`responseheaders` and `response`. HTTP/1 closes without publishing response
bytes. HTTP/2 resets the selected downstream stream with `INTERNAL_ERROR` while
two siblings complete normally; the responseheaders case keeps its upstream
body deliberately incomplete. The per-flow corpus preserves strict lifecycle
order without freezing nondeterministic ordering between streams. Three HTTP/1
runs and repeated H2 runs reproduce the semantic corpora. They also establish
that the terminal response hook has no later `error()` callback, unlike the
other three HTTP lifecycle hooks. The resulting H2 implementation reproduces
this lifecycle and transport result; the HTTP/1 connection-close path remains
unimplemented.

Late-DATA termination checkpoint (2026-10-31): the multiplexed H2 response
probe now has a separately checked corpus with fragmented response bodies and
two valid DATA frames sent after the `responseheaders` hook kills that stream.
The killed stream exposes neither headers nor body downstream, while both
siblings complete normally. No upstream reset was observed. Three isolated
mitmproxy 12.3.1 runs reproduced the corpus exactly. Native H2 termination now
uses this evidence to drop already-in-flight input, refund its flow-control
ownership and avoid a second reset.

Requestheaders termination checkpoint (2026-10-31): a second checked corpus
now sends a valid fragmented request body after `requestheaders` kills the H2
stream but before the client consumes its reset. The reference forwards no part
of the killed request, skips its completed-request hook, delivers exactly one
error hook, and leaves a sibling request operational. Three isolated mitmproxy
12.3.1 runs reproduced the corpus exactly.

Native-binding rejection checkpoint (2026-10-31): three adversarial matrices
now exercise ambiguous and unpublishable drafts before any native staging. They
cover foreign H2 anchors, duplicate pseudo-fields, multiple trailer blocks,
pseudo-fields in replacement trailers, protocol changes, non-byte H2 bodies,
incomplete H1 body replacement and trailers on non-chunked HTTP/1. Failed cases
leave the original Parts or Translate transaction unpublished. All **469**
direct addon tests pass; the focused Parts CTest target passes **1/1**.

Terminal-control rejection checkpoint (2026-10-31): malformed RST_STREAM and
GOAWAY Parts now have an explicit driver matrix covering invalid stream IDs and
payload lengths. Each case fails before a Translate transaction is created and
retires the unsafe addon generation. A second regression coalesces a valid
reset with response HEADERS for the same stream; the reset produces one error,
the response callbacks never run, native output contains only the reset, and
the flow cannot be revived. All **471** direct addon tests pass in 41.23 seconds;
the focused Parts CTest target passes **1/1**.

Full-capacity state checkpoint (2026-10-31): one persistent addon generation
now has a direct regression at its exact 128-flow admission limit. Eight
connections share one addon state, overflow fails without evicting any flow,
releasing one connection frees exactly its 16 flows, and replacement flows
reuse that capacity while the global script sequence and every surviving flow
identity remain intact. Generation shutdown then retires all 128 live flows.
All **472** direct addon tests pass in 41.25 seconds; the focused runtime CTest
target passes **1/1**.

Concurrent-context checkpoint (2026-10-31): an independent 12.3.1 observation
now records context-variable state across three sequential concurrent lifecycle
callbacks. A regular callback's context change remains attached to its executor
thread and is inherited by a following coroutine. Changes made inside that
coroutine remain task-local, so the next regular callback sees the earlier
thread value. Spider's single prepared runner thread now preserves the same
boundary: regular callbacks use one persistent worker context and coroutine
callbacks receive a snapshot. The caller's context still never enters the
runner. Three repeated reference probes reproduce the corpus. Additional local
regressions prove coroutine failure recovery, overlapping coroutine callbacks,
and atomic close admission with draining of accepted work. All **475** direct
addon tests pass in 41.37 seconds; the focused concurrency suite passes
**15/15** in three consecutive runs. After rebuilding the embedded worker, the
concurrent, worker, selection and deployment CTest targets pass **4/4**. The two
subprocess-owning targets were rerun outside the restricted test sandbox after
that sandbox rejected their worker IPC before request delivery.

Nested-configuration abort checkpoint (2026-10-31): an unexpected `BaseException`
raised by a `configure` callback triggered synchronously from another addon hook
now has an explicit regression. The exception reaches the caller, marks the
generation failed, rejects later traffic and still permits one bounded `done`
cleanup; it never resumes with partially changed option state. A closed
concurrent runner is also verified to reject restart. All **476** direct addon
tests pass in 41.25 seconds; the focused runtime and concurrency suites pass
**63/63**. The complete rebuilt two-job CTest inventory subsequently passes
**78/78** in 127.29 seconds outside the restricted sandbox.

Mass-retirement checkpoint (2026-10-31): a generation at its exact 128-flow
capacity now intercepts every flow across eight connections before shutdown.
Even when the addon `done` callback fails, retirement resumes all 128 waiters,
marks every flow non-live, clears every interception flag and releases the
entire flow table. Repeated close remains a no-op and does not deliver cleanup
twice. All **477** direct addon tests pass; the focused regression completes
without extending a synchronization timeout.

Raw-adapter checkpoint (2026-10-31): Spider's packaged worker now accepts the
explicit versioned raw envelope without importing native API modules during
bootstrap. Direct tests cover bidirectional size-changing TCP mutation, empty
UDP datagrams, terminal errors, simultaneous flows, retirement, immutable
transport classification, malformed metadata, unsupported control decisions,
history integrity and byte quotas. Packaged-worker tests additionally publish
TCP mutations and expand an empty UDP datagram through the real JSON worker
protocol. A C++ integration test carries an explicitly classified TCP lifecycle
through `process_webhook()`, the deployed worker and a size-changing webhook
replacement. Direct lifecycle tests match the checked-in mitmproxy 12.3.1 TCP
and UDP hook records and wire bytes. The focused raw and worker CTest targets
pass **2/2**, the native inspection integration target passes, and the rebuilt
complete inventory passes
**80/80**. The inventory now includes a mandatory clean-room import and
dependency boundary test. This does not claim live raw transport:
Smithproxy still does not produce the approved envelope, and no Smithproxy code
was changed.

Raw history accounting has both per-flow and generation-wide limits. The
generation defaults cap retained raw history at 16,384 messages and 32 MiB,
preventing 128 individually valid flows from multiplying the per-flow 16 MiB
allowance into an unbounded worker allocation. Quota regressions cover bytes and
message objects across separate simultaneous flows and verify that retirement
returns both aggregate counters to zero.

Client-lifecycle checkpoint (2026-10-31): an independent loopback probe against
mitmproxy 12.3.1 records the five connection events and their public state
transitions. Spider implements the two events supported by its existing native
connection boundary: `client_connected` precedes protocol hooks and
`client_disconnected` follows protocol terminal/error hooks. Direct regressions
cover two multiplexed H2 flows, TCP transport, repeated stop, fatal startup and
ordinary hook failures. A packaged-worker regression proves descriptor identity
and ordering survive the generated worker bundle. Optional-hook discovery stays
internal, and the public AddonManager surface still matches the reference corpus
exactly. All **510** direct addon tests pass; the production addon modules retain
**98%** aggregate branch coverage. The rebuilt complete inventory passes
**80/80** outside the restricted IPC sandbox, and the affected targets pass
**4/4** after the final negative-path additions. Server lifecycle remains an
explicit producer-integration boundary rather than a fabricated setup event.

Selection-persistence checkpoint (2026-10-31): the first-line `#!mitmproxy`
directive is exercised through validation, isolated preview, deployment,
enablement and real worker warm-up. The end-to-end regression uses a UTF-8 BOM
and CRLF source while the caller explicitly selects the native Spider API. The
worker-resolved mitmproxy mode wins, the backend persists both the effective API
and its `shebang` source, and a later edit that omits `script_api` retains that
effective mode. Export tests also preserve an explicit library selection by
adding the directive when needed. After rebuilding the native target and packed
worker, the complete serial CTest inventory passes **80/80** outside the
restricted IPC sandbox in 294.61 seconds.

Raw fail-closed coverage checkpoint (2026-10-31): strict envelope tests now
cover non-object and malformed endpoint values, invalid directions, units and
sequences, changed terminal identities, bounded terminal messages, duplicate
and orphan lifecycle operations, empty TCP chunks, per-flow history limits,
post-hook aggregate growth, non-byte message mutations, invalid native Part
shapes and empty UDP expansion without a Part factory. A separate passthrough
regression preserves an unmodified empty UDP datagram without requiring a
factory. The focused raw suite passes **22/22**. All **504** direct addon tests
pass under branch instrumentation; `addon_raw_events.py` rises from 87% to 99%
branch coverage and the 6,347-statement production addon set rises from 97% to
98% aggregate branch coverage. The sole uncovered raw statement is a defensive
post-hook aggregate message-count check whose malformed history growth is
rejected earlier by the stronger identity invariant.

Explicit legacy-log checkpoint (2026-10-31): an independent mitmproxy 12.3.1
loopback probe emits ordinary `ctx.log` records, standard Python records and one
public `AddLogHook`. Only the explicitly triggered event reaches `add_log`.
Spider now accepts that passive hook without synthesizing events from either
logging path, avoiding both a second log pipeline and recursive delivery. The
checked corpus, direct generation test and packaged-worker test preserve the
entry value and this negative boundary. The affected logging, public-surface,
clean-room and worker CTest targets pass **4/4**. The complete rebuilt inventory
subsequently passes **80/80** outside the restricted IPC sandbox in 145.28
seconds. A separate instrumented discovery run passes all **513** direct addon
tests and confirms **100%** branch coverage for both `addon_native.py` and
`addon_log.py`, with **98%** aggregate coverage across the 6,404-statement
production addon set.

Dynamic-manager hardening checkpoint (2026-10-31): optional-hook discovery now
has explicit pre-start, active-tree, nested-child, removal and post-close
coverage. Addon trees mutated after registration are verified to retain the
duplicate-identity and 256-object runtime guards. A separate 12.3.1 black-box
corpus records regular callbacks that return native coroutines and custom
awaitables through both targeted invocation APIs. Spider intentionally rejects
either result from the synchronous API instead of reproducing the reference's
discarded asynchronous work; its awaited API matches the reference. All
**516** direct addon tests pass in 50.62 seconds. Aggregate branch coverage
remains **98%**, with six fewer missed statements and three fewer partial
branches than the preceding complete instrumented run.

GOAWAY reference checkpoint (2026-10-31): ten clean-room loopback corpora now
fix the complete addon-hook and client-wire contract for upstream HTTP/2
GOAWAY. They cover response-before, response-pending and response-after timing,
NO_ERROR, PROTOCOL_ERROR, unknown code 123, an incomplete streaming POST,
late request DATA after the synthetic response, and `103 Early Hints` before
termination. Every corpus replays exactly against mitmproxy 12.3.1. The focused
Parts suite passes **102/102** and the complete direct addon inventory passes
**517/517** in 46.79 seconds. Native fallback publication remains behind the
explicit API approval boundary documented in `GOAWAY_FAILURE_API_PROPOSAL.md`.

Command-type hardening checkpoint (2026-10-31): the public extended-type
contract now records string parsing, validation and completion as well as the
reference error raised for an unhashable type lookup. The latter intentionally
propagates mitmproxy 12.3.1's exact `TypeError` instead of silently returning a
default handler. Marker completion returns an isolated list, and path completion
preserves a leading home-directory shorthand. The clean-room reference output
exactly matches the checked corpus, the focused command suite passes **13/13**,
and `addon_types.py` reaches **100%** statement and branch coverage. The complete
direct addon inventory passes **518/518** in 50.18 seconds.

Native GOAWAY failure checkpoint (2026-10-31): the approved additive
`ConnectionHttp2.fail_pending_requests()` API is implemented through the native
Translate ledger. It consumes upstream GOAWAY, selects only requests without a
final response before the anchor, emits bounded local responses through the
existing HPACK and flow-control machinery, and silently credits late DATA.
Tests cover final and informational responses around the anchor, incomplete
uploads, repeated GOAWAY, both RST_STREAM orderings, independent stream windows,
source HPACK continuity, malformed anchors and atomic fan-out quota rollback.
The exact reference set now contains **12** mitmproxy 12.3.1 corpora. An optional
native loopback probe passes between independent TLS/ALPN H2 peers. The focused
native Translate suite passes **162/162**, focused Parts passes **105/105**, and
the relevant rebuilt CTest set passes **9/9**, including packaged-worker and C++
state-boundary coverage. The complete direct and instrumented addon inventory
passes **522/522** in 48.22 and 50.55 seconds respectively; the 6,422-statement
addon implementation remains at **98%** aggregate branch coverage.
The complete rebuilt CTest inventory passes **80/80** after regenerating and
executing the public API example for the new method.

Native stream-failure checkpoint (2026-10-31): the approved additive
`ConnectionHttp2.fail_reset_stream()` API closes the upstream-reset transport
gap without adapter-owned frame construction. The checked eight-code oracle,
reset-before-GOAWAY ordering, one-byte output windows, late request DATA,
multiplexed siblings, source/destination HPACK continuity, quota rollback and
packaged-worker paths pass. A final 200 followed by reset in a later read exposed
one retained-body reservation boundary; the native operation now releases that
reservation atomically with stream failure. Independent mitmproxy 12.3.1 probes
confirm identical hooks and client output for informational, coalesced final and
separately delivered final headers before reset. The native Translate suite
passes **174/174**, Parts **109/109**, packaged worker **50/50**, API **13/13**,
and the rebuilt production C++ state-boundary test passes outside the restricted
sandbox. The complete rebuilt CTest inventory passes **80/80**.

Native informational-response checkpoint (2026-10-31): the approved additive
`ConnectionHttp2.emit_informational_response()` and
`suppress_informational_response()` operations are implemented entirely in
Translate. Reverse responses use the peer HPACK checkpoint and existing output
scheduler; suppression consumes source accounting without advancing the client
encoder. The compatibility driver now matches the checked 12.3.1 matrix for
exact, mixed-case, duplicate, invalid, absent and bodyless `Expect` requests,
and hides upstream `103`/`100` from both hooks and the client. Tests cover every
request and response input split, held request bodies, source and destination
HPACK continuity, multiplexed streams, local-final and termination conflicts,
reset and GOAWAY ordering, invalid anchors, aggregate reverse-output quota
rollback and the production C++ checkpoint boundary. Native Translate passes
**190/190**, Parts **113/113**, packaged worker **50/50**, and public API
**13/13**. The optional independent TLS/ALPN probe verifies local `100`, removed
upstream `Expect`, hidden upstream `103`, final `200` and unchanged bodies over
real loopback sockets. The production C++ test also passes outside the restricted
sandbox; its in-sandbox IPC failure is an environment restriction rather than a
protocol failure.

Final direct branch audit (2026-10-31): all **531** clean-room `addon_*` tests
pass under branch instrumentation in 52.40 seconds. The 6,474-statement
production addon set remains at **98%** aggregate statement/branch coverage.
Every ordinary informational-response path is exercised; the remaining H2
event branches are fail-closed guards for impossible or contract-violating
native states, such as a native operation returning a different stream identity,
an orphan response, or a client-side GOAWAY presented as an upstream failure.
They are intentionally not reached by forging parser objects merely to increase
the percentage. The deterministic deployment-retirement barrier also passes
once in isolation and four times in parallel without increasing a timeout.
The complete CTest inventory initially exposed that the combined Easy and
Expert Translate window matrix had outgrown its original 45-second gate. The
same 190 cases are now two independently named 95-case tests with the original
timeout retained for each mode. Both pass in approximately 32 seconds, and the
reconfigured complete inventory passes **81/81** in 154.46 seconds.

Release-patch behavior audit (2026-10-31): the addon-visible fixes named in the
official 12.3.1 release notes now have explicit local evidence. A dedicated
black-box observation proves that repeated `set_all()` calls on both live query
and request-cookie views neither consume nor mutate the caller's value list;
both assignments produce the same ordered fields. A separate 12.3.1 observation covers response refresh
for an empty-valued cookie, a quoted empty value and an invalid empty cookie
name. It exposed one Spider mismatch: the invalid name's `Expires` attribute was
shifted instead of preserving the original field. The shared cookie helper now
rejects that invalid name and `Response.refresh()` leaves the malformed evidence
unchanged, while valid empty values remain refreshable. The focused model and
helper suites pass **33/33**, followed by all **531/531** direct addon tests in
49.03 seconds.

The same patch-level audit also covers 12.3.1's corrected unsupported-option
diagnostic. An independent public-API probe records `float`, `bytes`,
`Sequence[int]` and `bool | None`. `OptManager.make_parser()` now rejects each
with the exact reference `ValueError` before adding an argparse action; supported
`int`, optional `int`, `str`, optional `str`, `bool` and `Sequence[str]` behavior
is unchanged. The complete 20-case option suite passes, followed by all
**531/531** direct addon tests in 49.32 seconds.

Finally, the 12.3.1 Brotli security floor is enforced rather than merely
documented. Deployment requirements now require Brotli 1.2.1 or newer, CMake
rejects an older imported decoder during addon test configuration, and a
clean-room manifest regression prevents the bound from drifting backwards.
After upgrading the isolated model environment from 1.2.0 to 1.2.1, all
**532/532** direct addon tests pass in 50.84 seconds, including exact content
coding, worker sandbox and native publication coverage.
The final reconfigured CTest inventory passes **81/81** in 161.92 seconds after
all 12.3.1 patch-level behavior and dependency changes.

Fragmentation and capability-revalidation checkpoint (2026-10-31): an explicit
Translate regression now divides a nine-byte HTTP/2 frame header at every one
of its eight internal boundaries in both directions and both safety modes. It
proves that only the bounded partial-header checkpoint changes before the header
is complete, that flow-control credit is debited exactly once, and that release
refunds both stream and connection windows exactly once. HTTP/1 termination now
also has direct-driver and packaged-worker regressions in which a body is held
while `connection-close` is available and resumed after the producer omits that
capability. Both layers revalidate the current callback, reject `flow.kill()`
atomically, and emit neither message bytes nor a close request. All **537**
direct `addon_*` tests pass with **1,895** subtests; the 6,502-statement
production addon set retains **98%** aggregate statement/branch coverage.

Late-stream selection checkpoint (2026-10-31): the official mitmproxy 12
message contract distinguishes a streaming choice made in `requestheaders` or
`responseheaders` from one made after buffering in `request` or `response`.
Spider now preserves the latter assignment on the public message object and
publishes the already buffered H1 or H2 body unchanged, rather than failing the
deployment for a transport decision which is already too late to act on.
Header-hook streaming remains fail-closed until a real incremental publication
contract exists. Direct H1, H2 and local-response regressions plus the packaged
worker boundary verify this distinction; no native API or producer behavior was
changed.

Public-hook inventory checkpoint (2026-10-31): the loader now recognizes every
event name in the official mitmproxy 12 hook inventory. This closes a silent
registration gap for `socks5_auth`: a script declaring that hook now fails
before partial registration because Spider has no SOCKS5 credential observation
or decision producer. It is not accepted and ignored. A fixed inventory test
guards all lifecycle, connection, HTTP, DNS, TCP, UDP, QUIC, TLS, WebSocket,
SOCKS5 and advanced hook names; the existing per-adapter capability matrix still
requires an explicit implementation before any transport hook can load.

SOCKS5 authentication value checkpoint (2026-10-31): an isolated black-box
probe against mitmproxy 12.3.1 fixes the constructor signatures, dataclass
fields, identity, equality, mutability and hook argument contract of
`Socks5AuthData` and `Socks5AuthHook`. The scoped
`mitmproxy.proxy.layers.modes` facade reproduces that corpus both directly and
inside the packaged persistent worker. This is deliberately a data-model
capability only: the loader continues to reject a `socks5_auth` callback until
Smithproxy provides a truthful authentication observation and a synchronous
decision boundary.

TLS value checkpoint (2026-10-31): a separate black-box corpus against
mitmproxy 12.3.1 fixes TLS and DTLS ClientHello parsing, cipher-suite order,
SNI, ALPN, extension bytes, TLS record reconstruction, truncation diagnostics,
proxy-context fork identity and the mutable `ClientHelloData`/`TlsData`
contracts. A companion corpus fixes all seven public TLS hook values. Spider's
implementation is a small clean-room bounded wire parser;
it has no Kaitai, OpenSSL or mitmproxy runtime dependency. The same contract is
verified inside the packaged worker. TLS hooks remain fail-closed because these
detached values do not invent a producer observation or handshake decision
boundary.

QUIC TLS value checkpoint (2026-10-31): the public `QuicTlsSettings`,
`QuicTlsData`, `QuicStartClientHook` and `QuicStartServerHook` contracts now
match an isolated mitmproxy 12.3.1 corpus for field order, defaults, independent
certificate-chain storage, inheritance, endpoint/context identity, hook names,
arguments and blocking semantics. The types are available in the packaged
worker without importing aioquic or a mitmproxy runtime. QUIC hooks remain
fail-closed until a native producer can provide their real handshake boundary.

Connection-hook value checkpoint (2026-10-31): the public
`ServerConnectionHookData` and six client/server lifecycle hook values match a
black-box 12.3.1 corpus for field order, endpoint identity, equality, hook names,
arguments and blocking semantics, directly and in the packaged worker. This
does not synthesize upstream events: only client connect/disconnect callbacks
have a truthful producer today, while all four server callbacks remain
fail-closed pending the ordered Smithproxy observations described above.

HTTP-hook value checkpoint (2026-10-31): all eight public HTTP hook classes in
`mitmproxy.proxy.layers.http` and its `_hooks` child match an isolated 12.3.1
black-box corpus for module identity, dataclass fields, flow identity, equality,
event names, arguments and blocking semantics. The same imports and values are
verified inside the packaged worker. This closes an import-level facade gap;
it does not make HTTP CONNECT events operational. Those callbacks remain
fail-closed until a producer supplies the ordered CONNECT observations and
decisions listed in the TODO.

Protocol-hook value checkpoint (2026-10-31): the public WebSocket, DNS, TCP and
UDP hook classes now match a second isolated 12.3.1 corpus for module identity,
flow identity, fields, equality, event names, arguments and blocking semantics.
They are available in the packaged worker beside the existing flow models.
This adds no synthetic traffic events: TCP and UDP still require the versioned
raw producer envelope, while WebSocket and DNS callbacks remain fail-closed
until their native producers exist. The reconfigured project inventory passes
all **78/78** tests after the hook-facade and registry batches.

Hook-registry checkpoint (2026-10-31): the generation-local
`mitmproxy.hooks.all_hooks` now maps every hook value implemented by the scoped
facade, including `load`, to the same class exported by its public module. This
matches the reference's class-identity contract after those modules are loaded;
Spider builds its safe module set eagerly rather than exposing import-order
changes to user scripts. `next_layer` is intentionally absent from this value
registry even though the loader recognizes and rejects that callback: its
argument is a live host-owned protocol state machine, not a detached event value
that can be represented truthfully without a native producer.

Legacy content-view checkpoint (2026-10-31): the deprecated line-oriented
`mitmproxy.contentviews.View` contract is now supported through a generation-local
`LegacyContentview` wrapper. An isolated 12.3.1 corpus fixes its abstract
constructor, default priority, warning text, metadata projection, styled-line
flattening, module identities, legacy `get()` and `remove()` behavior, and the
five-member `ContentviewMessage` type alias. The historical `remove(original)`
identity quirk is preserved rather than silently improved. The exact corpus and
a packaged persistent-worker test pass; the current `contentviews.__all__`
surface remains unchanged and exact, including the alias's public `_utils`
module identity. The complete remote verification passes all **556/556** direct
addon tests and the rebuilt **79/79** CTest inventory. Branch instrumentation
keeps the 6,915-statement production `addon_*` set at **98%** aggregate coverage;
the newly added hook-value modules are fully covered and omitted from the
coverage report's non-perfect-file list.

WebSocket producer-design checkpoint (2026-10-31):
`WEBSOCKET_PRODUCER_PROPOSAL.md` now separates complete logical-message
observation/mutation/drop from the later active-injection host capability.
Smithproxy remains the sole framing, fragmentation, masking, compression and
control-frame owner. A dormant Spider-side lifecycle adapter validates the
proposed versioned envelope, preserves append-before-callback history, and
returns explicit pass/replace/drop decisions; it is packaged but not connected
to native traffic, and WebSocket hooks therefore remain fail-closed. Its 14-test
suite reaches **100%** statement and branch coverage. The complete Rhino run
passes all **570/570** direct addon tests and the rebuilt **80/80** CTest
inventory. The 7,152-statement production `addon_*` set remains at **98%**
aggregate branch coverage.

DNS producer-design checkpoint (2026-10-31): `DNS_PRODUCER_PROPOSAL.md` fixes a
complete-message boundary for UDP and TCP while leaving sockets, upstream
selection, framing and transport failure in Smithproxy. A dormant Spider-side
adapter now covers forwarded exchanges, local responses, response mutation,
explicit termination, `dns_error`, concurrent identities and connection abort.
It consumes only explicitly classified complete messages through the existing
clean-room DNS model; registration remains fail-closed without the producer.
Raw TCP/UDP, WebSocket and DNS envelope validation share one small internal
validator instead of protocol-specific copies. Both new modules reach **100%**
statement and branch coverage. The complete Rhino run passes all **587/587**
direct addon tests and the rebuilt **82/82** CTest inventory. The 7,370-statement
production `addon_*` set remains at **98%** aggregate branch coverage.

SOCKS5 authentication checkpoint (2026-10-31): a real reference server now
fixes method negotiation and RFC 1929 results for both override directions.
`valid` enters the hook as the built-in policy decision and the addon may either
allow a rejected credential or reject an accepted one. The corpus also proves
that arbitrary credential bytes use reversible escaped text. A dormant
Spider-side adapter validates the bounded observation, reuses the truthful
native `Client`, dispatches one synchronous hook and accepts only a boolean
result; no credential is retained. It reaches **100%** statement and branch
coverage, while registration remains fail-closed without a Smithproxy producer.
The complete Rhino run passes all **592/592** direct addon tests and the rebuilt
**83/83** CTest inventory. The 7,406-statement production `addon_*` set remains
at **98%** aggregate branch coverage.

HTTP CONNECT transport checkpoint (2026-10-31): five real mitmproxy 12.3.1
proxy-mode corpora now fix regular success and target-connection failure, the
distinct lazy upstream-proxy sequence, and ordinary control decisions. Regular
mode emits `http_connect` before target selection and then either
`http_connected` with a 200 response and connected peer or
`http_connect_error` with a 502 response but no `flow.error`. Upstream mode
acknowledges the client first and emits
`http_connect_upstream` only when initial tunneled bytes trigger the upstream
CONNECT exchange; the server descriptor changes from the requested destination
to the connected upstream proxy. The control corpus proves that a local response
prevents target connection but proceeds through `http_connect_error`, kill
closes silently, destination mutation reroutes the native connection, and
success/failure status mutations reach the wire. A lightweight contract test
protects these ordering, identity and control invariants. A dormant Spider-side
adapter now validates a strict versioned envelope, preserves one flow and the
same native `Server`, and returns only the proven request, response and late
upstream-authority decisions. Its 15-test suite reaches **100%** statement and
branch coverage. No live producer was added, so registration remains
fail-closed. The fourth corpus fixes built-in proxy-authentication ordering:
rejected requests still receive
`http_connect` and `http_connect_error` around a local 407, while accepted
credentials are removed before `http_connect` and only the accepted request
reaches the target. The fifth fixes the late upstream hook: its flow is already
non-live, authority mutation changes the serialized upstream CONNECT, kill
raises `ControlException`, local response replacement has no transport effect,
and an upstream 502 closes the tunnel without a new `http_connect_error`.
The complete Rhino verification passes all **612/612** direct addon tests and
the rebuilt **85/85** CTest inventory. Branch instrumentation covers the
7,571-statement production `addon_*` set at **98%** aggregate coverage; the
new CONNECT adapter itself remains at **100%** statement and branch coverage.

Raw transport control checkpoint (2026-10-31): a new real-proxy corpus records
eight control scenarios for both TCP and UDP and reproduces exactly against a
second isolated mitmproxy 12.3.1 run. It proves ordered append-only history,
multiple stream chunks and datagrams, TCP empty-chunk suppression and real
zero-length UDP forwarding. It also corrects an inferred incompatibility:
`flow.kill()`, direct `live` edits and direct `error` edits change only public
flow state in the reference. Current and later traffic continues, and normal
`tcp_end`/`udp_end` preserves that state. Spider now matches that behavior
without inventing a native close command; interception remains fail-closed
pending producer suspension. The five corpus-contract tests and all **26/26**
raw adapter tests pass. The
Smithproxy integration boundary and acceptance gates are recorded in
`RAW_TRANSPORT_PRODUCER_PROPOSAL.md`; no other project was changed. The complete
Rhino verification passes all **619/619** direct addon tests and the rebuilt
**86/86** CTest inventory. Branch instrumentation covers the 7,571-statement
production `addon_*` set at **98%** aggregate coverage; the raw adapter reaches
**99%**, with only a defensive post-hook aggregate-quota branch made
unreachable by the earlier message-history identity guard.

Raw socket-failure checkpoint (2026-10-31): a separate reference corpus fixes
three failure boundaries and reproduces exactly in a second isolated 12.3.1
run. Reverse-TCP connection refusal creates no raw flow. An established TCP
connection reset receives ordinary `tcp_end` with `live=True` and no flow error.
Two UDP datagrams sent to an unreachable loopback target remain normal
`udp_message` events followed by `udp_end`; the ICMP condition does not become
`udp_error`. The proposed producer must therefore classify terminal events
explicitly rather than mapping socket errors mechanically. Three contract tests
guard these observations; no production code or other project changed in this
checkpoint. The complete Rhino verification passes all **622/622** direct addon
tests and the rebuilt **87/87** CTest inventory; production coverage remains
**98%** across 7,571 statements.

WebSocket wire-control checkpoint (2026-10-31): a second real HTTP/1 corpus
now covers the message boundaries that the initial smoke corpus left implicit.
Fragmented text with interleaved ping frames produces one complete addon
message in each direction; ping, pong and close frames do not produce message
callbacks. Bidirectional text, binary and initially empty messages preserve
their logical type, size-changing replacements reach the peer, and explicit
drop consumes exactly one message while retaining it in ordered public
history. A normal close code and reason survive the proxy. The corpus also
corrects the dormant adapter's clean-end ordering: reference
`websocket_end` observes `flow.live=True`, so Spider now retires the flow only
after the callback. The corpus reproduces exactly in two isolated mitmproxy
12.3.1 runs. Five contract tests and all 15 adapter tests pass; the complete
Rhino verification passes all **628/628** direct addon tests and the rebuilt
**88/88** CTest inventory. The 223-statement adapter remains at **100%**
statement and branch coverage across 76 branches. No native producer or other
project was changed.

WebSocket destructive-boundary checkpoint (2026-10-31): a third real HTTP/1
corpus fixes six independent failure/control scenarios and reproduces exactly
in a second isolated mitmproxy 12.3.1 run. Killing the flow at start or in
either directional message callback changes only public live/error state;
messages and the normal close still pass. Abrupt client and origin disconnects
produce code 1006, no flow error and a truthful `closed_by_client` value.
Invalid text from either peer is rejected before a callback for that message,
closes both peers with code 1007, identifies the offending side and retains the
UTF-8 diagnostic as the close reason. Five contract tests guard these
boundaries. The complete direct addon inventory now
passes **632/632**; the newly registered CTest passes and brings the generated
inventory to 89 tests. The prior complete post-production-change CTest run
passed **88/88**; only the new contract target was added afterward. No
production code or other project changed in this checkpoint.

WebSocket shared-state checkpoint (2026-10-31): a fourth real HTTP/1 corpus
keeps two upgraded flows alive simultaneously and reproduces exactly in a
second isolated mitmproxy 12.3.1 run. One addon module maintains a shared
ordinal from one through eight across both flows, while the two independent
message histories each grow through counts one, two, three and four. Mutations
derived from the shared state reach only the correct origin and client in
deterministic order. This fixes the compatibility target as one stable worker
per script generation, not one worker per flow. Three contract tests protect
the observation. The direct addon inventory passes **635/635**; the new CTest
passes and brings the generated inventory to 90 tests. No production code or
other project changed in this checkpoint.

WebSocket compression checkpoint (2026-10-31): a fifth real HTTP/1 corpus
negotiates `permessage-deflate` with no context takeover in both directions.
The addon observes decompressed complete plaintext, applies size-changing
mutations, and both peers receive valid recompressed messages with RSV1 set;
ping/pong remains outside message callbacks. Two additional reproducible
corpora split the same valid compressed stream across a data frame and
continuation with an interleaved ping. Mitmproxy 12.3.1 closes either direction
with code 1007 before publishing that fragmented compressed message, while the
equivalent unfragmented message succeeds. The producer proposal records this
as an explicit compatibility-policy decision rather than silently requiring
Smithproxy to copy a reference protocol limitation. The destructive corpus
also now covers invalid text from the server and confirms the symmetric 1007
close with `closed_by_client=False`. All five compression and five destructive
contract tests pass; the complete direct addon inventory passes **641/641**.
The compression CTest passes and the generated inventory contains 91 tests. No
production code or other project changed in this checkpoint.

DNS forwarded-UDP checkpoint (2026-10-31): a second real DNS-server-mode
corpus now proves both mutation directions against a disposable resolver bound
only to Rhino loopback. The request hook changes the qname before resolution;
the reference resolver then issues separate A and AAAA queries with EDNS and
resolver-owned IDs. It restores the original client ID, publishes one response
on the same public flow, and the response hook's TTL/address mutation reaches
the UDP client. Random resolver IDs are normalized only to the stable facts
that they are distinct and differ from the client ID. The corpus reproduces
exactly in a second isolated 12.3.1 run. Four contract tests pass, followed by
the complete **647/647** direct addon inventory. The new CTest passes and the
generated inventory contains 92 tests. No production code or other project
changed in this checkpoint.

DNS resolver-failure checkpoint (2026-10-31): a third real DNS-server-mode
corpus points the reference at an unreachable selected resolver and reproduces
exactly in a second isolated mitmproxy 12.3.1 run. After its resolver retry
policy, mitmproxy synthesizes SERVFAIL, calls `dns_response` on the still-live
flow, preserves the client message ID and returns the response. It does not call
`dns_error` and does not set `flow.error`. Three contract tests protect that
distinction. The complete Rhino direct inventory passes **650/650**; the new
CTest passes and brings the generated inventory to 93 tests. No production code
or other project changed in this checkpoint.

DNS-over-TCP framing checkpoint (2026-10-31): the reference DNS mode is proven
to listen on TCP as well as UDP. A fourth real corpus splits the first message's
two-byte length prefix and payload across writes, pipelines a second complete
message before reading either response, and reproduces exactly in a second
isolated mitmproxy 12.3.1 run. Each complete message receives its own `DNSFlow`
and ordered request/response hook pair, both flows share the truthful client
connection, and the two independently framed responses retain their original
IDs. Three contract tests protect the boundary. No production code or other
project changed in this checkpoint.

DNS concurrent-identity checkpoint (2026-10-31): a fifth real corpus sends two
simultaneous UDP requests from separate clients with the same 16-bit DNS ID.
The resolver holds both lookups and returns the second lookup first. Repeated
mitmproxy 12.3.1 runs exhibit both legal completion orders, so the corpus
canonicalizes only that scheduler-dependent ordering. Each request and response
still retains its independent flow identity, both responses preserve the shared
client ID, and qname-specific mutations never cross. Eleven canonical reruns
reproduce exactly. Four contract tests guard these invariants and make the
producer-owned opaque exchange identity a tested requirement. No production
code or other project changed in this checkpoint. A direct adapter test now
replays the same shape with exchange ID 1 on two connections, completes the
second response first, proves one shared script ordinal across all four hooks,
and verifies distinct stable flow identities and uncrossed mutations. The full
direct addon inventory passes **661/661**.

DNS malformed-input checkpoint (2026-10-31): a sixth real DNS-server-mode
corpus sends an empty datagram, one byte, an 11-byte header, a declared but
missing question, a compression-pointer loop, and a syntactically complete
query followed by trailing bytes. Mitmproxy 12.3.1 silently drops every case
before addon dispatch and sends no response; a clean baseline immediately
afterward still runs request/response hooks and succeeds. The exact corpus
reproduces in a second isolated run. Three contract tests protect strict whole-
payload consumption and pre-hook rejection. No production code or other project
changed in this checkpoint.

DNS local-error checkpoint (2026-10-31): a seventh real corpus creates NXDOMAIN
in `dns_request`, mutates it to REFUSED in `dns_response` on the same flow, and
delivers the final code with the original client ID and question. A sentinel
resolver bound to the configured upstream address receives no packet, proving
that local error responses bypass resolution rather than merely winning a race.
The corpus reproduces exactly in a second isolated mitmproxy 12.3.1 run. Three
contract tests and a direct dormant-adapter replay protect the lifecycle, wire
result and zero-upstream invariant. The complete Rhino verification passes all
**665/665** direct addon tests and the rebuilt **97/97** CTest inventory. No
production code or other project changed.

DNS complex-message checkpoint (2026-10-31): an eighth real corpus sends a
compressed UDP message with two questions, one answer, one authority and one
additional record. It also sets NOTIFY, AA, TC, RD, RA, every reserved bit and
response code 7. Both hooks receive the complete logical message; response-hook
TTL/address mutations reach the client while every other field survives. The
wire output is fully consumed and deterministically normalizes compressed names
to ordinary record data. The exact corpus reproduces in a second isolated
mitmproxy 12.3.1 run. Four contract tests and a direct dormant-adapter replay
protect flags, sections, compression and mutation. No other project changed.

DNS RDATA-compression checkpoint (2026-10-31): the complex corpus exposed a
clean-room codec defect: compressed NS target data retained a pointer into the
original packet. A new black-box public-model corpus probes 25 standard RR
formats against mitmproxy 12.3.1 and reproduces exactly. The native codec now
normalizes the reference's exact 17-format set, including single-name,
two-name, preference, SOA, PX, SRV and NAPTR layouts, while leaving the eight
reference-opaque formats untouched. Three corpus contracts and a table-driven
codec test prevent stale compression pointers from surviving repacking. Strict
malformed-layout tests cover every new guard, and the complete 567-statement,
158-branch DNS model now has **100%** statement and branch coverage. The full
Rhino verification passes **677/677** direct addon tests and the rebuilt
**99/99** CTest inventory.

DNS control checkpoint (2026-10-31): a ninth real DNS-server-mode corpus fixes
the protocol-specific meaning of `flow.kill()`. Killing in `dns_request`
without a response produces a local SERVFAIL with the original question, skips
`dns_response`, and never contacts upstream. Killing after a local response has
been created still runs `dns_response`; killing in either local or upstream
response hooks preserves the final response and its mutations on the wire. In
all cases the public flow becomes non-live with `Connection killed.`. The
dormant adapter now follows these semantics instead of mapping DNS kill to a
generic transport termination. Four corpus contracts and three direct adapter
paths protect the exact hook, state, upstream and wire distinctions. The
changed 204-statement, 62-branch lifecycle adapter retains **100%** statement
and branch coverage. The complete Rhino Python discovery and rebuilt
**100/100** CTest inventory pass.

Clean-room and coverage audit (2026-10-31): the release check against PyPI still
identifies **12.3.1** as the latest mitmproxy release and therefore confirms the
documented major-12 target. The build-time clean-room guard now parses every
Python module under `src`, rejects any import of the reference distribution,
and rejects a vendored `mitmproxy` package tree under source or conventional
third-party directories. Runtime and test requirements remain independently
guarded against installing the reference product. A complete branch-instrumented
Rhino run covers 7,635 production `addon_*` statements and 2,488 branches at
**98%** aggregate coverage; 31 modules are fully covered. The remaining lines
are predominantly fail-closed invariant checks and OS/thread failure paths,
not evidence for an unimplemented public method. They remain visible rather
than being hidden with coverage exclusions or artificial production branches.

Termination-corpus registration checkpoint (2026-10-31): nine existing
black-box corpora for HTTP/1 close, HTTP/2 stream reset, multiplexed sibling
survival, late request/response DATA and RST_STREAM/GOAWAY ordering are now
loaded by a registered contract suite. Five tests protect the protocol-specific
wire outcomes and hook differences directly from the checked reference data,
instead of relying only on separately encoded native regressions.

Reference-corpus inventory checkpoint (2026-10-31): all 144 checked JSON
corpora are named by direct `*_test.py` contracts, and every such consumer is
registered with CTest. A dedicated inventory test now enforces both invariants
and rejects corpus references from runtime source, so future black-box evidence
cannot silently become an inert fixture or leak into the clean-room adapter.
Every corpus also identifies the audited 12.3.1 patch release. The one older
adversarial connection fixture that lacked that metadata was regenerated in the
isolated reference environment; all 25 observed cases remained byte-for-byte
equivalent and only the release marker changed. The final Rhino checkpoint
passes all 712 direct Python tests and all 107 CTests.

Concurrent-runner saturation checkpoint (2026-10-31): a deterministic stress
test blocks the runner, shrinks its ordinary wakeup pipe to 4096 bytes, queues
more callbacks than the pipe can represent, and then releases the owner. Every
accepted callback runs exactly once and in publication order. This exercises
the real full-pipe path and proves that the in-memory queue, rather than one
wakeup byte per operation, owns delivery. The focused direct and CTest runs
pass without increasing a timeout or adding a retry.

Authentication policy integration (2026-11-02): the earlier dormant SOCKS5 and
CONNECT checkpoints are superseded for the explicitly scoped authentication
deployment. `socks5_auth` and `http_connect` can now veto real Smithproxy AAA
results. No target lifecycle, rerouting or custom wire response is inferred
from this exchange. See [AUTHENTICATION_HOOKS.md](AUTHENTICATION_HOOKS.md) for
the contract and required future `new-AAA` merges into `main` and `master`.

### Multiplexed transport setup boundary

A native `connection-start` with `info.scope = "transport"` represents the
physical QUIC parent, not an HTTP inspection flow. Native scripts may observe
this setup. Content addons do not allocate an instance or emit client lifecycle
hooks for it. The worker also rejects direct transport setup through the HTTP
adapter, including previews.

Logical streams retain their existing independent inspection lifetimes. Their
setup, content and stop metadata carry `scope = "stream"`, `parent_id` (the
parent envelope ID), and the downstream wire `stream_id`. A parent stop must
not retire child inspection instances. Ordinary producers without these fields
retain their existing behavior. Session display labels remain endpoint labels
so existing deployment filters continue to work.

This boundary prevents the newly introduced parent from fabricating an extra
HTTP client lifecycle. It does not implement HTTP/3, QUIC TLS hooks, or a shared
mitmproxy connection identity across H3 streams; those remain producer/adapter
integration work. Subscriptions are deferred.

Validation checkpoint (2026-11-02): companion Smithproxy commit
`92bfb59d18276044fe779932199cfb51bb3ee8e9` passed all 43 standard full P3
sections and 47 native CTest suites. Spider passed all 119 configured CTests;
the final setup-only metadata guard was rebuilt and passed the three affected
host/adapter suites. A real QUIC capture with one parent and ten streams passed
host/packaged-worker replay, and live HTTP CONNECT/SOCKS5/PAM native and addon
veto integration passed with the final production binaries. These checks do
not promote the deferred QUIC/TLS/H3 hook capabilities to supported features.
