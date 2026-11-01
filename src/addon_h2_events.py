"""Deliver addon HTTP events from interpreted Parts, using native body holds.

This driver owns callback identity and ordering, not HTTP/2 framing, HPACK or
window accounting. The caller publishes the prepared message with Translate.
One instance belongs to one persistent addon generation.
"""

from html import escape

from addon_flow import Error
from addon_http_message import Request
from addon_loader import REFERENCE_RELEASE
from addon_parts import (AddonMessageError, H2MessageBinding, dispatch_local_response,
                         dispatch_message, check_message_decisions, _killed)


class H2AddonEvents:
    HOOKS = frozenset({'requestheaders', 'request', 'responseheaders', 'response', 'error'})
    # HTTP/2 standard error-code names, not a transport implementation.
    RESET_NAMES = (
        'NO_ERROR', 'PROTOCOL_ERROR', 'INTERNAL_ERROR', 'FLOW_CONTROL_ERROR',
        'SETTINGS_TIMEOUT', 'STREAM_CLOSED', 'FRAME_SIZE_ERROR', 'REFUSED_STREAM',
        'CANCEL', 'COMPRESSION_ERROR', 'CONNECT_ERROR', 'ENHANCE_YOUR_CALM',
        'INADEQUATE_SECURITY', 'HTTP_1_1_REQUIRED',
    )
    GOAWAY_THEN_RESET_REASON = (
        'HTTP/2 protocol error: Invalid input '
        'ConnectionInputs.RECV_RST_STREAM in state ConnectionState.CLOSED'
    )

    def __init__(self, generation, *, body_limit=256 * 1024):
        if type(body_limit) is not int or not 1 <= body_limit <= 256 * 1024:
            raise ValueError('The retained body limit must be between 1 and 262144 bytes')
        self.generation = generation
        self.body_limit = body_limit
        self._messages = {}
        self._failed = False

    async def translate(self, connection_id, side, native_message, http2, connection,
                        client_conn, server_conn):
        """Run hooks and publish using one native transaction boundary.

        User callbacks may already have changed arbitrary Python state when
        publication fails. Such a generation cannot safely retry the callback
        or pretend that restoring the native checkpoint restored addon state.
        """
        try:
            failures, keys = await self.prepare(connection_id, side, native_message,
                                                 http2, connection, client_conn, server_conn)
            resumed_failures, resumed_keys = await self._resume_pending(
                connection_id, native_message, http2, connection, keys,
            )
            failures = tuple(failures) + tuple(resumed_failures)
            keys = tuple(keys) + tuple(resumed_keys)
            keys += tuple(self._terminate_pending(connection_id, native_message, keys))
            result = native_message.translate()
            terminated = self.published(keys)
            later_failures = await self._finish_terminations(terminated)
            return result, tuple(failures) + tuple(later_failures)
        except BaseException:
            self._failed = True
            self.generation.invalidate()
            raise

    def _terminate_pending(self, connection_id, native_message, prepared):
        """Settle kills made by later hooks, including the opposite direction.

        Incomplete messages use prefix holds, not logical suspension. Their
        bodies and source compression history remain entirely native-owned.
        """
        terminal = {key[2] for key, outcome in prepared
                    if outcome in ('failed', 'terminated')}
        published = []

        for key, state in self._messages.items():
            if key[0] != connection_id or state.published or key[2] in terminal:
                continue
            flow = self.generation.get_flow(connection_id, key[2])
            if flow is None or not _killed(flow):
                continue

            native_message.terminate_held(
                key[2], key[1], reason=Error.KILLED_MESSAGE, http2_error=2,
            )
            kind = 'request' if key[1] == 'L' else 'response'
            state.termination_hook = kind if state.complete else kind + 'headers'
            published.append((key, 'terminated'))
            terminal.add(key[2])

        return published

    async def _resume_pending(self, connection_id, native_message, http2, connection, prepared):
        """Publish completed intercepted messages without replaying their hooks.

        Another callback may have changed the retained public flow. Only this
        connection can publish it; native resume retains directional ownership
        and performs all encoding, cancellation and window accounting.
        """
        # Cancellation observed in this callback wins over a pending resume.
        # A retained public flow may still exist until publication cleans it up.
        terminal = {key[2] for key, outcome in prepared
                    if outcome in ('failed', 'terminated')}
        streams = []
        for key, state in self._messages.items():
            if key[0] != connection_id or not state.suspended or key[2] in terminal:
                continue
            flow = self.generation.get_flow(connection_id, key[2])
            if flow is not None and not flow.intercepted and key[2] not in streams:
                streams.append(key[2])

        # Resume once per stream: native storage may release both directions.
        # The returned Parts, not the callback's side, identify each message.
        failures, published = [], []
        for stream in streams:
            flow = self.generation.get_flow(connection_id, stream)

            # Run deferred hooks against detached native views first. A hook
            # may intercept again; in that case no resume command is staged
            # and the native queue, deadline and flow-control debt stay put.
            parts = ()
            for direction in ('L', 'R'):
                pending = self._messages.get((connection_id, direction, stream))
                if pending is not None and not pending.complete:
                    parts = native_message.suspended_parts(stream)
                    break

            for header in parts:
                if not self._initial_header(header):
                    continue
                binding = H2MessageBinding(
                    native_message, header, http2, connection=connection, parts=parts,
                )
                kind = 'request' if isinstance(binding.message, Request) else 'response'
                side = 'L' if kind == 'request' else 'R'
                key = (connection_id, side, stream)
                state = self._messages[key]

                # A header interception has not delivered the message hook.
                # Restore its body from native Parts, preserving the public
                # header object and any edits made while it was suspended.
                if not state.complete and not _killed(flow):
                    state.message = check_message_decisions(
                        flow, kind, allow_termination=True,
                    )
                    state, dispatched = await dispatch_message(
                        self.generation, flow, kind, binding, state,
                        allow_termination=True,
                        allow_completed_interception=True,
                    )
                    failures.extend(dispatched)

                if flow.intercepted:
                    break

            if flow.intercepted:
                continue

            # Publication uses the real editable drafts, never the detached
            # copies that were exposed to the deferred message hook above.
            parts = native_message.resume(stream)
            for header in parts:
                if not self._initial_header(header):
                    continue
                binding = H2MessageBinding(
                    native_message, header, http2, connection=connection, parts=parts,
                )
                kind = 'request' if isinstance(binding.message, Request) else 'response'
                side = 'L' if kind == 'request' else 'R'
                key = (connection_id, side, stream)
                state = self._messages[key]

                # Rebind the edited public object without rerunning its hook.
                # Transport guards still apply to mutations made while held.
                binding.message = check_message_decisions(
                    flow, kind, allow_termination=True, allow_late_stream=True,
                )
                outcome = 'normal'
                if _killed(flow):
                    native_message.terminate(header, reason=Error.KILLED_MESSAGE, http2_error=2)
                    if state.termination_hook is None:
                        state.termination_hook = kind if state.complete else kind + 'headers'
                    outcome = 'terminated'
                elif kind == 'request' and flow.response is not None:
                    failures.extend(await dispatch_local_response(self.generation, flow, binding))
                    outcome = 'local'
                else:
                    binding.apply()
                # These are prepared outcomes only. published() retires the
                # suspension after the complete native translation succeeds.
                state.message = binding.message
                published.append((key, outcome))
        return failures, published

    @staticmethod
    def _can_intercept_headers(http2, side, binding):
        """Admit header interception from native header receive evidence.

        Hook delivery and reception are different states: the addon has seen
        only headers. Incomplete bodies stay in the ordinary native prefix hold
        with reserved input credit; logical suspension starts after reception.
        """
        snapshot = http2.state
        if snapshot is None:
            return False

        for stream in snapshot:
            if stream.stream_id != binding.stream_id:
                continue

            message = stream.request if side == 'L' else stream.response
            return not stream.reset and message.headers_complete

        return False

    @staticmethod
    def _initial_header(part):
        if (part.frame_type != 1 or not part.complete or part.headers is None or
                getattr(part, '_translate_cancelled', False)):
            return False
        return any(entry.name in (b':method', b':status') for entry in part.headers.entries)

    @staticmethod
    def _informational_header(part):
        pseudo = [entry for entry in part.headers.entries
                  if isinstance(entry.name, bytes) and entry.name.startswith(b':')]
        if len(pseudo) != 1 or pseudo[0].name != b':status':
            return False
        status = pseudo[0].value
        if not (isinstance(status, bytes) and len(status) == 3 and
                status.isdigit() and 100 <= int(status) < 200):
            return False
        # Do not silently skip an invalid response and leave its flow waiting
        # forever for final headers. HTTP/2 cannot switch protocols with 101,
        # and an informational response cannot terminate the stream.
        if status == b'101':
            raise AddonMessageError('HTTP/2 does not support status 101')
        if part.flags & 1:
            raise AddonMessageError('An informational response cannot carry END_STREAM')
        return True

    @classmethod
    def _reset_reason(cls, part):
        payload = part.get_bytes()
        if part.stream_id == 0 or len(payload) != 4:
            raise AddonMessageError('Invalid HTTP/2 RST_STREAM')
        code = int.from_bytes(payload, 'big')
        name = cls.RESET_NAMES[code] if code < len(cls.RESET_NAMES) else str(code)
        # This wording is observable in the reference even for a reset sent
        # by the upstream peer. Keep it as compatibility text, not endpoint
        # metadata or a conclusion about which socket initiated the reset.
        return f'stream reset by client ({name})'

    @staticmethod
    def _goaway_reason(part):
        payload = part.get_bytes()
        if part.stream_id != 0 or len(payload) < 8:
            raise AddonMessageError('Invalid HTTP/2 GOAWAY')
        last_stream = int.from_bytes(payload[:4], 'big') & 0x7fffffff
        error_code = int.from_bytes(payload[4:8], 'big')
        additional = payload[8:]
        additional_text = 'None' if not additional else repr(additional)
        return (
            'HTTP/2 connection closed: <ConnectionTerminated '
            f'error_code:{error_code}, last_stream_id:{last_stream}, '
            f'additional_data:{additional_text}>'
        )

    @staticmethod
    def _goaway_body(reason):
        safe_reason = escape(reason)
        return (
            '<html>\n'
            '<head>\n'
            '    <title>502 Bad Gateway</title>\n'
            '</head>\n'
            '<body>\n'
            '    <h1>502 Bad Gateway</h1>\n'
            f'    <p>{safe_reason}</p>\n'
            '</body>\n'
            '</html>'
        ).encode('utf-8')

    def _reservation_limit(self, binding):
        """Reserve the observed body size when the source states it exactly.

        The native ledger owns admission and validates the original field again.
        A missing, duplicate or malformed Content-Length is not a trustworthy
        sizing hint, so it retains the configured conservative maximum.
        """
        lengths = [value for name, value in binding.original_fields
                   if name == b'content-length']
        if len(lengths) != 1 or not lengths[0].isdigit():
            return self.body_limit
        declared = int(lengths[0])
        return max(1, min(declared, self.body_limit))

    async def prepare(self, connection_id, side, native_message, http2, connection,
                      client_conn, server_conn):
        """Dispatch each event once and stage only the publishable prefix.

        A completed stream may follow another stream's unfinished body in the
        retained Parts. Its hooks can run now, but its mutations stay in the
        addon object until the prefix can be published. This avoids replaying
        user code or inserting synthetic frames into a held native checkpoint.
        """
        if side not in ('L', 'R'):
            raise ValueError('H2 addon events require an L/R direction')
        if self._failed:
            raise AddonMessageError('The H2 addon generation failed; redeploy before processing more traffic')
        parts = tuple(native_message.parts)
        hold_index = len(parts)
        prepared = []
        reservations = []
        informational = []
        failures = []
        # Several resets may arrive in one native callback. Deduplicate them
        # without reordering observable error hooks by Python set iteration.
        cancelled = {}
        reset_positions = {}
        goaway_staged = False
        complete_goaway = next((index for index, part in enumerate(parts)
                                if part.complete and part.frame_type == 7), None)
        reset_after_goaway = (
            complete_goaway is not None and
            any(index > complete_goaway and part.complete and part.frame_type == 3
                for index, part in enumerate(parts))
        )
        for index, part in enumerate(parts):
            if part.complete and part.frame_type == 3:
                if reset_after_goaway and index > complete_goaway:
                    # mitmproxy's H2 state machine treats a reset after GOAWAY
                    # as the connection failure that owns every pending flow.
                    # Native Translate suppresses this reset after staging the
                    # connection-wide responses below.
                    continue
                reason = self._reset_reason(part)
                cancelled.setdefault(part.stream_id, reason)
                reset_positions.setdefault(part.stream_id, index)
                error_code = int.from_bytes(part.get_bytes(), 'big')
                if side == 'R' and error_code != 8:
                    selected = connection.http2.fail_reset_stream(
                        part,
                        status=502,
                        headers=[
                            (b'server', f'mitmproxy {REFERENCE_RELEASE}'.encode('ascii')),
                            (b'content-type', b'text/html'),
                        ],
                        body=self._goaway_body(reason),
                        include_content_length=False,
                    )
                    if selected != part.stream_id:
                        raise AddonMessageError('Native reset selection changed stream identity')
            elif part.complete and part.frame_type == 7:
                # Parts supplies the complete control payload; no frame
                # boundaries, HPACK or flow-control state are parsed here.
                reason = (self.GOAWAY_THEN_RESET_REASON if reset_after_goaway
                          else self._goaway_reason(part))
                if side != 'R':
                    raise AddonMessageError('A client GOAWAY cannot fail upstream requests')
                if not goaway_staged:
                    selected = connection.http2.fail_pending_requests(
                        part,
                        status=502,
                        headers=[
                            (b'server', f'mitmproxy {REFERENCE_RELEASE}'.encode('ascii')),
                            (b'content-type', b'text/html'),
                        ],
                        body=self._goaway_body(reason),
                        include_content_length=False,
                    )
                    for stream in selected:
                        cancelled.setdefault(stream, reason)
                    goaway_staged = True
        deferred_resets = set()
        for stream, reset_index in reset_positions.items():
            for part in parts[:reset_index]:
                if part.stream_id != stream or not self._initial_header(part):
                    continue
                if side == 'R' and not self._informational_header(part):
                    deferred_resets.add(stream)
                    break

        terminal_releases = []

        async def dispatch_terminal(stream, reason):
            flow = self.generation.get_flow(connection_id, stream)
            if flow is None:
                return
            flow.error = Error(reason)
            failures.extend(await self.generation.dispatch('error', flow))
            terminal_releases.append(
                ((connection_id, side, stream), 'failed')
            )

        for stream, reason in cancelled.items():
            if stream not in deferred_resets:
                await dispatch_terminal(stream, reason)
        for index, part in enumerate(parts):
            if (part.frame_type == 3 and part.stream_id in deferred_resets and
                    reset_positions.get(part.stream_id) == index):
                await dispatch_terminal(part.stream_id, cancelled[part.stream_id])
                continue
            if not part.complete:
                hold_index = min(hold_index, index)
                break
            if not self._initial_header(part):
                continue
            reset_index = reset_positions.get(part.stream_id)
            response_before_reset = (
                side == 'R' and reset_index is not None and index < reset_index
            )
            if part.stream_id in cancelled and not response_before_reset:
                continue
            if side == 'R' and self._informational_header(part):
                # Classify before binding a complete response: later HEADERS
                # on this stream are final headers, not informational trailers.
                # The native suppression operation advances only the source
                # HPACK state when this block reaches the publishable prefix.
                informational.append((index, part))
                continue
            binding = H2MessageBinding(native_message, part, http2, connection=connection)
            kind = 'request' if isinstance(binding.message, Request) else 'response'
            if (kind == 'request') != (side == 'L'):
                raise AddonMessageError('HTTP message direction does not match the connection side')
            flow = self.generation.get_flow(connection_id, part.stream_id)
            if flow is None:
                if kind != 'request':
                    raise AddonMessageError('A response has no observed addon request')
                flow = self.generation.create_flow(connection_id, part.stream_id,
                                                   client_conn, server_conn)
            key = (connection_id, side, part.stream_id)
            state = self._messages.get(key)
            first_delivery = state is None

            def handle_expect_continue(current_flow, current_state, current_binding):
                if (kind != 'request' or not first_delivery or
                        not self._expects_continue(current_binding.original_fields) or
                        current_flow.response is not None):
                    return
                # requestheaders observes the original field. The completed
                # request and upstream peer do not: mitmproxy handles the
                # expectation locally before admitting the retained body.
                current_state.message.headers.set_all('expect', ())
                selected = connection.http2.emit_informational_response(
                    part,
                    status=100,
                )
                if selected != part.stream_id:
                    raise AddonMessageError(
                        'Native informational response changed stream identity'
                    )

            state, dispatched = await dispatch_message(
                self.generation, flow, kind, binding, state,
                allow_termination=True,
                after_headers=handle_expect_continue,
                allow_completed_interception=True,
                allow_header_interception=self._can_intercept_headers(http2, side, binding),
            )
            self._messages[key] = state
            failures.extend(dispatched)
            if response_before_reset:
                # The responseheaders hook is observable, but the later reset
                # owns this stream. Native Translate suppresses the partial
                # response and emits the staged failure response instead.
                continue
            if state.termination_hook is not None:
                native_message.terminate(
                    part,
                    reason=Error.KILLED_MESSAGE,
                    http2_error=2,
                )
                prepared.append((index, binding, state, 'terminated'))
                continue
            if flow.intercepted and binding.complete:
                prepared.append((index, binding, state, 'suspended'))
                continue
            if not binding.complete:
                hold_index = min(hold_index, index)
                reservations.append((part, self._reservation_limit(binding)))
            local = kind == 'request' and flow.response is not None
            if local:
                if not binding.complete:
                    hold_index = min(hold_index, index)
                else:
                    failures.extend(await dispatch_local_response(
                        self.generation, flow, binding))
            prepared.append((index, binding, state, 'local' if local else 'normal'))

        if hold_index < len(parts):
            native_message.parts.hold_from(parts[hold_index])
        for index, part in informational:
            if index < hold_index:
                selected = connection.http2.suppress_informational_response(part)
                if selected != part.stream_id:
                    raise AddonMessageError(
                        'Native informational suppression changed stream identity'
                    )
        for header, limit in reservations:
            connection.http2.reserve_body(header, limit)
        published = terminal_releases
        for index, binding, state, outcome in prepared:
            if outcome == 'terminated':
                published.append(((connection_id, side, binding.stream_id), outcome))
            elif index < hold_index:
                if outcome == 'suspended':
                    binding, outcome, dispatched = await self._settle_interception(
                        connection_id, side, native_message, http2, connection,
                        binding, state,
                    )
                    failures.extend(dispatched)
                    if outcome == 'suspended':
                        continue

                if outcome == 'normal':
                    binding.apply()
                published.append(((connection_id, side, binding.stream_id), outcome))
        return tuple(failures), tuple(published)

    async def _settle_interception(self, connection_id, side, native_message,
                                   http2, connection, binding, state):
        """Resolve callback-local decisions before staging a native command.

        A later stream in the same input batch may resume or kill this flow.
        Do not stage suspend followed by resume: no bytes have been committed
        yet, so the final decision can be published directly.
        """
        flow = self.generation.get_flow(connection_id, binding.stream_id)
        failures = ()
        if not flow.intercepted:
            # The earlier binding exposes the public header-only draft.
            # Recover the received body from Parts, not from that draft.
            binding = H2MessageBinding(
                native_message, binding.header, http2, connection=connection,
            )
            kind = 'request' if side == 'L' else 'response'
            state, failures = await dispatch_message(
                self.generation, flow, kind, binding, state,
                allow_termination=True, allow_completed_interception=True,
            )

        if state.termination_hook is not None:
            native_message.terminate(binding.header, reason=Error.KILLED_MESSAGE, http2_error=2)
            return binding, 'terminated', failures

        if flow.intercepted:
            native_message.suspend(binding.header)
            state.suspended = True
            return binding, 'suspended', failures

        if side == 'L' and flow.response is not None:
            local_failures = await dispatch_local_response(self.generation, flow, binding)
            return binding, 'local', tuple(failures) + tuple(local_failures)

        return binding, 'normal', failures

    @staticmethod
    def _expects_continue(fields):
        values = [
            value for name, value in fields
            if name.lower() == b'expect'
        ]
        return len(values) == 1 and values[0].lower() == b'100-continue'

    def published(self, keys):
        """Acknowledge native publication and return terminated flows for hooks."""
        terminated = []
        for key, outcome in keys:
            connection_id, side, stream = key
            if outcome == 'failed':
                self._release_stream(connection_id, stream)
                continue
            state = self._messages[key]
            state.published = True
            state.suspended = False
            if outcome == 'terminated':
                flow = self.generation.get_flow(connection_id, stream)
                if flow is not None:
                    terminated.append((key, flow, state.termination_hook != 'response'))
                continue
            if outcome == 'local':
                self._release_stream(connection_id, stream)
                continue
            peer = (connection_id, 'R' if side == 'L' else 'L', stream)
            other = self._messages.get(peer)
            if other is not None and other.published:
                self._release_stream(connection_id, stream)
        return tuple(terminated)

    async def _finish_terminations(self, terminated):
        """Deliver compatibility error hooks only after native reset assembly."""
        failures = []
        for key, flow, deliver_error in terminated:
            connection_id, _, stream = key
            state = self._messages.get(key)
            try:
                if deliver_error and state is not None and not state.error_delivered:
                    state.error_delivered = True
                    failures.extend(await self.generation.dispatch('error', flow))
            finally:
                self._release_stream(connection_id, stream)
        return tuple(failures)

    def _release_stream(self, connection_id, stream):
        for side in ('L', 'R'):
            self._messages.pop((connection_id, side, stream), None)
        self.generation.release_flow(connection_id, stream)

    def release_connection(self, connection_id):
        keys = [key for key in self._messages if key[0] == connection_id]
        for key in keys:
            del self._messages[key]
        return self.generation.release_connection(connection_id)
