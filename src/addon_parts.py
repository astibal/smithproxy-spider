"""Bind addon HTTP objects to Spider's interpreted Parts.

This layer neither parses HTTP/2 frames nor maintains HPACK or flow-control
state. It edits public drafts and leaves publication to message.translate().
Bindings are callback-local: native hold checkpoints own the retained Parts.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
import time
from urllib.parse import urlsplit, urlunsplit

from addon_flow import Error
from addon_http import Headers
from addon_http_message import Request, Response


class AddonMessageError(ValueError):
    """A message cannot be safely exposed or published through the native API."""


@dataclass
class LocalResponseState:
    """Hook delivery for a generated response, independent of its request."""
    headers_delivered: bool = False
    complete: bool = False


@dataclass
class MessageState:
    message: object
    complete: bool = False
    published: bool = False
    local_response: bool = False
    termination_hook: str | None = None
    error_delivered: bool = False
    suspended: bool = False
    local_reply: LocalResponseState | None = None


def _killed(flow):
    return (not flow.intercepted and not flow.live and
            isinstance(flow.error, Error) and
            flow.error.msg == Error.KILLED_MESSAGE)


def check_message_decisions(
        flow,
        kind,
        *,
        allow_termination=False,
        allow_late_stream=False,
        allow_interception=False,
):
    """Reject addon decisions without a corresponding native transport action."""
    if (flow.intercepted and not allow_interception) or ((flow.error is not None or not flow.live) and
                            not (allow_termination and _killed(flow))):
        raise AddonMessageError('Flow interception and termination are not connected to this HTTP driver')
    selected = getattr(flow, kind)
    expected = Request if kind == 'request' else Response
    if not isinstance(selected, expected):
        raise AddonMessageError('The replacement must retain the HTTP message kind')
    if kind == 'request' and flow.response is not None and not isinstance(flow.response, Response):
        raise AddonMessageError('A local response must be an HTTP Response')
    if getattr(selected, 'stream', False) and not allow_late_stream:
        raise AddonMessageError('Streaming callbacks are not connected to this HTTP driver')
    return selected


async def dispatch_local_response(generation, flow, binding):
    """Run response hooks and stage one protocol-owned reverse response."""
    failures = []
    response = flow.response
    if not isinstance(response, Response):
        raise AddonMessageError('A local response must be an HTTP Response')
    if response.stream:
        raise AddonMessageError('Streaming callbacks are not connected to this HTTP driver')

    failures.extend(await generation.dispatch('responseheaders', flow))
    if flow.intercepted:
        raise AddonMessageError('Interception of generated local responses requires a retained response binding')
    response = flow.response
    if not isinstance(response, Response):
        raise AddonMessageError('Response hooks must retain the local HTTP Response')
    if response.stream:
        raise AddonMessageError('Streaming callbacks are not connected to this HTTP driver')
    failures.extend(await generation.dispatch('response', flow))
    if flow.intercepted:
        raise AddonMessageError('Interception of generated local responses requires a retained response binding')
    response = flow.response
    if not isinstance(response, Response):
        raise AddonMessageError('Response hooks must retain the local HTTP Response')
    if not isinstance(response.raw_content, bytes):
        raise AddonMessageError('A local response requires a complete byte body')

    publish_local_response(flow, binding)
    return tuple(failures)


async def advance_local_response(generation, flow, state):
    """Run only the remaining generated-response hooks, without publication.

    A local response already has its body at responseheaders. Retain that
    public object across interception; do not reconstruct it from the request
    Parts or replay a hook when another callback resumes the flow.
    """
    failures = []
    response = flow.response
    if not isinstance(response, Response):
        raise AddonMessageError('Response hooks must retain the local HTTP Response')
    if response.stream and not state.complete:
        raise AddonMessageError('Streaming callbacks are not connected to this HTTP driver')

    if not state.headers_delivered:
        failures.extend(await generation.dispatch('responseheaders', flow))
        state.headers_delivered = True

    if not flow.intercepted and not _killed(flow) and not state.complete:
        response = flow.response
        if not isinstance(response, Response):
            raise AddonMessageError('Response hooks must retain the local HTTP Response')
        if response.stream:
            raise AddonMessageError('Streaming callbacks are not connected to this HTTP driver')
        failures.extend(await generation.dispatch('response', flow))
        state.complete = True

    response = flow.response
    if not isinstance(response, Response):
        raise AddonMessageError('Response hooks must retain the local HTTP Response')
    if response.stream and not state.complete:
        raise AddonMessageError('Streaming callbacks are not connected to this HTTP driver')
    if not isinstance(response.raw_content, bytes):
        raise AddonMessageError('A local response requires a complete byte body')
    return tuple(failures)


def publish_local_response(flow, binding):
    """Serialize the current response through the native request anchor."""
    response = flow.response
    if not isinstance(response, Response):
        raise AddonMessageError('Response hooks must retain the local HTTP Response')
    if not isinstance(response.raw_content, bytes):
        raise AddonMessageError('A local response requires a complete byte body')

    h1_transport = hasattr(binding, 'draft')
    normalize = (lambda name: name) if h1_transport else (lambda name: name.lower())
    headers = [(normalize(name), value) for name, value in response.headers.fields]
    trailers = [] if response.trailers is None else [
        (normalize(name), value) for name, value in response.trailers.fields
    ]
    options = {}
    # A locally constructed compatibility Response defaults to HTTP/1.1 even
    # when it belongs to an H2 flow. The native binding, not that convenience
    # default, owns the transport protocol.
    if h1_transport:
        options['reason'] = (
            response.reason.decode('latin-1')
            if isinstance(response.reason, bytes) else response.reason)
    binding.native.respond(
        status=response.status_code,
        headers=headers,
        body=response.raw_content,
        trailers=trailers,
        request=binding.header,
        **options,
    )


async def dispatch_message(
        generation,
        flow,
        kind,
        binding,
        state,
        *,
        allow_termination=False,
        after_headers=None,
        allow_completed_interception=False,
        allow_header_interception=False,
):
    """Deliver header and completed-message hooks around one native binding."""
    failures = []
    incoming = binding.message
    if state is None:
        # Header hooks see no body even when framing completed in one callback.
        # Keep the selected object so addon identity survives a native hold.
        body = incoming.raw_content
        trailers = incoming.trailers
        finished = incoming.timestamp_end
        incoming.raw_content = None
        incoming.trailers = None
        incoming.timestamp_end = None
        state = MessageState(incoming)
        setattr(flow, kind, incoming)
        failures.extend(await generation.dispatch(kind + 'headers', flow))
        incoming = check_message_decisions(
            flow, kind, allow_termination=allow_termination,
            allow_interception=allow_header_interception)
        state.message = incoming
        if _killed(flow):
            state.termination_hook = kind + 'headers'
            binding.message = state.message
            return state, tuple(failures)
        if after_headers is not None:
            after_headers(flow, state, binding)

        # Retain only the public header draft here. Native Parts own the body
        # until resume; receiving it is not permission to deliver its hook.
        if flow.intercepted:
            binding.message = state.message
            return state, tuple(failures)

        # mitmproxy permits assigning content or trailers in a header hook, but
        # the subsequently received message replaces those provisional values.
        # Header side effects such as its automatically adjusted Content-Length
        # remain. Keeping that slightly surprising behavior is important for
        # existing addons and avoids inventing an early transport mutation.
        if binding.complete:
            incoming.raw_content = body
            incoming.trailers = trailers
            incoming.timestamp_end = finished
    elif state.published:
        raise AddonMessageError('A published HTTP message was delivered again')
    else:
        # Reassembled Parts can revisit a header while its body is still held.
        # Observe decisions made by another callback before exposing new body
        # data or delivering a hook. Reception does not end interception.
        state.message = check_message_decisions(
            flow, kind, allow_termination=allow_termination,
            allow_late_stream=state.complete,
            allow_interception=(allow_header_interception or
                                (state.complete and allow_completed_interception)),
        )
        binding.message = state.message
        if _killed(flow):
            if state.termination_hook is None:
                state.termination_hook = kind if state.complete else kind + 'headers'
            return state, tuple(failures)

        if flow.intercepted:
            return state, tuple(failures)

        if binding.complete and not state.complete:
            state.message.raw_content = incoming.raw_content
            state.message.trailers = incoming.trailers
            state.message.timestamp_end = incoming.timestamp_end

    binding.message = state.message
    if binding.complete and not state.complete:
        failures.extend(await generation.dispatch(kind, flow))
        state.message = check_message_decisions(
            flow,
            kind,
            allow_termination=allow_termination,
            # The completed-message hook runs after buffering. mitmproxy keeps
            # a late .stream assignment on the public object, but it cannot
            # retroactively turn the already buffered body into a stream.
            allow_late_stream=True,
            allow_interception=allow_completed_interception,
        )
        binding.message = state.message
        state.complete = True
        if _killed(flow):
            state.termination_hook = kind
    return state, tuple(failures)


def _h1_headers(draft):
    return Headers([
        (header.name.encode('latin-1'), header.value.encode('latin-1'))
        for header in draft.headers
    ])


def _h1_trailers(group):
    body = group.content_part
    get_trailers = getattr(body, 'get_trailers', None)
    trailers = () if get_trailers is None else get_trailers()
    if not trailers:
        return None
    return Headers([
        (field.name.encode('latin-1'), field.value.encode('latin-1'))
        for field in trailers
    ])


class H1MessageBinding:
    """One native HTTP/1 request or response backed by typed Parts."""

    def __init__(self, native_message, header):
        if header.type != 'http1.header' or header.http1 is None:
            raise AddonMessageError('A typed HTTP/1 header Part is required')
        self.native = native_message
        self.header = header
        self.body_part = header.group.content_part
        self.complete = bool(header.content.complete)
        self.draft = header.http1
        headers = _h1_headers(self.draft)
        body = self.body_part._encoded_bytes() if self.complete else None
        trailers = _h1_trailers(header.group) if self.complete else None
        now = time.time()
        finished = now if self.complete else None

        if self.draft.method is not None:
            target = self.draft.target
            parsed = urlsplit(target)
            absolute = bool(parsed.scheme and parsed.hostname)
            if absolute:
                scheme = parsed.scheme
                host = parsed.hostname
                port = parsed.port or (443 if scheme == 'https' else 80)
                authority = parsed.netloc
                path = urlunsplit(('', '', parsed.path or '/', parsed.query, parsed.fragment))
            else:
                authority = ''
                path = target
                scheme = ''
                host, port = '', 0
                host_header = headers.get('host', '')
                if host_header:
                    try:
                        endpoint = urlsplit('//' + host_header)
                        host = endpoint.hostname or ''
                        port = endpoint.port or 0
                    except ValueError:
                        pass
            self.message = Request(
                host, port, self.draft.method, scheme, authority, path,
                self.draft.http_version, headers, body, trailers, now, finished)
            self.absolute_target = absolute
            self.original_destination = (
                self.message.host, self.message.port, self.message.scheme)
        elif self.draft.status_code is not None:
            self.message = Response(
                self.draft.http_version, self.draft.status_code,
                self.draft.reason, headers, body, trailers, now, finished)
            self.absolute_target = False
            self.original_destination = None
        else:
            raise AddonMessageError('HTTP/1 draft has no request or response start line')

        self.original_body = body
        self.original_trailers = None if trailers is None else trailers.fields

    def apply(self):
        """Copy application changes into native drafts before atomic commit."""
        selected = self.message
        if selected.http_version not in ('HTTP/1.0', 'HTTP/1.1'):
            raise AddonMessageError('Changing HTTP/1 to another protocol requires a new connection')

        if isinstance(selected, Request):
            destination = (selected.host, selected.port, selected.scheme)
            if destination != self.original_destination:
                raise AddonMessageError('Changing the destination requires native upstream routing support')
            self.draft.method = selected.method
            self.draft.target = selected.url if self.absolute_target else selected.path
        elif isinstance(selected, Response):
            self.draft.status_code = selected.status_code
            self.draft.reason = selected.reason
        else:
            raise AddonMessageError('The replacement must retain the HTTP message kind')

        if selected.raw_content != self.original_body:
            if not self.complete or not isinstance(selected.raw_content, bytes):
                raise AddonMessageError('A complete byte body is required for replacement')
            try:
                decoded = selected.content
            except ValueError as error:
                raise AddonMessageError(str(error)) from error
            self.body_part.set_bytes(decoded)

        self.draft.http_version = selected.http_version
        self.draft.replace_headers([
            (name.decode('latin-1'), value.decode('latin-1'))
            for name, value in selected.headers.fields
        ])
        trailer_fields = None if selected.trailers is None else selected.trailers.fields
        if trailer_fields != self.original_trailers:
            replace_trailers = getattr(self.body_part, 'replace_trailers', None)
            if replace_trailers is None:
                raise AddonMessageError('HTTP/1 trailers require chunked framing')
            replace_trailers([
                (name.decode('latin-1'), value.decode('latin-1'))
                for name, value in (trailer_fields or ())
            ])


def _fields(header):
    result = []
    for field in header.headers.entries:
        if field.indexing == "table-size":
            continue
        if not isinstance(field.name, bytes) or not isinstance(field.value, bytes):
            raise AddonMessageError("HTTP/2 fields must be resolved by Translate first")
        result.append((field.name, field.value))
    return tuple(result)


def _group(parts, header):
    selected = []
    found = False
    for part in parts:
        if part is header:
            found = True
        if not found:
            continue
        if part.frame_type is None:
            break
        if part.stream_id != header.stream_id:
            continue
        if part.frame_type == 3:
            break
        if part.frame_type in (0, 1):
            selected.append(part)
            if part.flags & 1:
                break
    if not selected or selected[0] is not header:
        raise AddonMessageError("The header does not belong to this Parts collection")
    return selected


class H2MessageBinding:
    """One request or response, including its body and trailing header block."""

    def __init__(self, native_message, header, http2, *, connection, host="", port=443,
                 parts=None):
        if header.frame_type != 1 or not header.complete or header.headers is None:
            raise AddonMessageError("A complete interpreted HEADERS block is required")
        self.native = native_message
        self.header = header
        self.http2 = http2
        self.connection = connection
        self.stream_id = header.stream_id
        # Refresh native whole-content knowledge. A complete HEADERS or DATA
        # frame by itself does not make a complete request/response body.
        if parts is None:
            native_message.bodies()
            parts = native_message.parts
        self.complete = header.content.complete is True
        group = _group(parts, header)
        self.data_parts = [part for part in group if part.frame_type == 0]
        trailers = [part for part in group[1:] if part.frame_type == 1]
        if len(trailers) > 1:
            raise AddonMessageError("More than one trailing header block")
        self.trailer = trailers[0] if trailers else None
        self.original_fields = _fields(header)
        pseudo = {}
        regular = []
        for name, value in self.original_fields:
            if name.startswith(b":"):
                if name in pseudo:
                    raise AddonMessageError("Duplicate HTTP/2 pseudo-header")
                pseudo[name] = value
            else:
                regular.append((name, value))

        body = None
        if self.complete:
            body = b"".join(part.get_bytes() for part in self.data_parts)
        trailing_fields = None
        if self.trailer is not None and self.trailer.complete:
            trailing_fields = Headers(_fields(self.trailer))
        now = time.time()
        finished = now if self.complete else None
        if b":method" in pseudo and b":status" not in pseudo:
            authority = pseudo.get(b":authority", b"")
            scheme = pseudo.get(b":scheme", b"")
            if authority:
                address = urlsplit("//" + authority.decode("utf-8", "surrogateescape"))
                host = address.hostname or host
                port = address.port or (443 if scheme == b"https" else 80)
            self.message = Request(host, port, pseudo[b":method"], scheme, authority,
                                   pseudo.get(b":path", b""), b"HTTP/2.0", Headers(regular),
                                   body, trailing_fields, now, finished)
        elif b":status" in pseudo and b":method" not in pseudo:
            self.message = Response(b"HTTP/2.0", int(pseudo[b":status"]), b"", Headers(regular),
                                    body, trailing_fields, now, finished)
        else:
            raise AddonMessageError("Expected initial request or response headers")
        self.original_body = body
        self.original_trailers = None if trailing_fields is None else trailing_fields.fields
        self.original_destination = None
        if isinstance(self.message, Request):
            self.original_destination = (self.message.host, self.message.port, self.message.scheme)
        self.pseudo = pseudo

    def _desired_headers(self):
        if not self.message.is_http2:
            raise AddonMessageError("Changing the transport protocol requires a new connection")
        pseudo = self.pseudo.copy()
        if isinstance(self.message, Request):
            # Updating authority is a wire-header edit, but changing these
            # properties asks the proxy to choose a different upstream. Native
            # Translate does not reconnect sockets; never report that as done.
            destination = (self.message.host, self.message.port, self.message.scheme)
            if destination != self.original_destination:
                raise AddonMessageError('Changing the destination requires native upstream routing support')
            changes = {
                b":method": self.message.data.method,
                b":scheme": self.message.data.scheme,
                b":authority": self.message.data.authority,
                b":path": self.message.data.path,
            }
            for name, value in changes.items():
                # Classic CONNECT legitimately has neither scheme nor path.
                if value or name in pseudo:
                    pseudo[name] = value
        else:
            pseudo[b":status"] = str(self.message.status_code).encode("ascii")
        fields = list(pseudo.items())
        for name, value in self.message.headers.fields:
            if name.startswith(b":"):
                raise AddonMessageError("Edit pseudo-headers through the request/response properties")
            fields.append((name.lower(), value))
        return tuple(fields)

    def _entries(self, header, fields):
        """Retain unchanged field representations, including sensitive fields."""
        reusable = defaultdict(deque)
        updates = []
        for entry in header.headers.entries:
            if entry.indexing == "table-size":
                updates.append(entry)
            else:
                reusable[(entry.name, entry.value)].append(entry)
        for name, value in fields:
            available = reusable[(name, value)]
            if available:
                updates.append(available.popleft())
            else:
                updates.append(self.http2.Header(name, value))
        return updates

    def apply(self):
        """Copy changed application data into drafts; do not publish wire bytes."""
        fields = self._desired_headers()
        body = self.message.raw_content
        trailers = self.message.trailers
        trailer_fields = None if trailers is None else trailers.fields
        body_changed = body != self.original_body
        trailers_changed = trailer_fields != self.original_trailers
        if (body_changed or trailers_changed) and not self.complete:
            raise AddonMessageError("Hold the entire message before changing body or trailers")
        if body_changed and not isinstance(body, bytes):
            raise AddonMessageError("A replacement body must be available as bytes")
        if trailer_fields is not None:
            for name, value in trailer_fields:
                if name.startswith(b":"):
                    raise AddonMessageError("Pseudo-headers are not allowed in trailers")

        # Build the changes before mutating Parts. The native translator then
        # validates framing, quotas and flow control atomically at publication.
        header_entries = None
        if fields != self.original_fields:
            header_entries = self._entries(self.header, fields)
        trailer_entries = None
        if trailers_changed and trailer_fields is not None:
            trailer_entries = [self.http2.Header(name.lower(), value) for name, value in trailer_fields]

        # Staging goes through the native connection API. Never insert frames
        # ourselves: Translate owns END_STREAM, flow control and HPACK history.
        if trailers_changed:
            self.connection.http2.replace_trailers(self.header, trailer_entries)
        if body_changed:
            self.connection.http2.replace_body(self.header, body, encoded=True)
        if header_entries is not None:
            self.header.headers.entries[:] = header_entries
