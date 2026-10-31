"""Deliver addon HTTP events from Spider's typed HTTP/1 Parts.

The native Parts layer owns parsing, framing, content decoding, retained input,
and atomic publication. This driver only associates request and response
messages with a compatibility flow and dispatches addon hooks exactly once.
"""

from collections import defaultdict, deque

from addon_flow import Error
from addon_http_message import Request
from addon_parts import (
    AddonMessageError,
    H1MessageBinding,
    dispatch_local_response,
    dispatch_message,
)


class H1AddonEvents:
    """Dispatch sequential HTTP/1 exchanges for one addon generation."""

    HOOKS = frozenset({
        'requestheaders', 'request', 'responseheaders', 'response', 'error',
    })

    def __init__(self, generation):
        self.generation = generation
        self._messages = {}
        self._active = {}
        self._pending = defaultdict(deque)
        self._next_exchange = defaultdict(int)
        self._failed = False

    @staticmethod
    def _bindings(native_message):
        parts = tuple(native_message.parts)
        bindings = []
        cursor = 0
        while cursor < len(parts):
            header = parts[cursor]
            if (header.type != 'http1.header' or header.http1 is None
                    or cursor + 1 >= len(parts)
                    or parts[cursor + 1] is not header.group.content_part):
                raise AddonMessageError(
                    'Mixed typed and opaque HTTP/1 callbacks are not supported')
            bindings.append(H1MessageBinding(native_message, header))
            cursor += 2

        if not bindings:
            raise AddonMessageError('An HTTP/1 callback has no typed message')
        return tuple(bindings)

    def _new_request(self, connection_id):
        self._next_exchange[connection_id] += 1
        exchange = self._next_exchange[connection_id]
        self._pending[connection_id].append(exchange)
        return exchange

    @staticmethod
    def _informational(binding):
        status = binding.draft.status_code
        return status is not None and 100 <= status < 200

    async def rewrite(self, connection_id, side, native_message,
                      client_conn, server_conn):
        """Run hooks and publish one or more HTTP/1 messages atomically."""
        if side not in ('L', 'R'):
            raise ValueError('H1 addon events require an L/R direction')
        if self._failed:
            raise AddonMessageError(
                'The H1 addon generation failed; redeploy before processing more traffic')

        try:
            bindings = self._bindings(native_message)
            active_key = (connection_id, side)
            active = self._active.get(active_key)
            active_used = False
            response_offset = 0
            failures = []
            published = []
            terminated = None

            for index, binding in enumerate(bindings):
                kind = 'request' if isinstance(binding.message, Request) else 'response'
                if (kind == 'request') != (side == 'L'):
                    raise AddonMessageError(
                        'HTTP message direction does not match the connection side')

                # mitmproxy does not expose interim responses through the
                # regular response hooks. Native publication stays unchanged.
                if kind == 'response' and self._informational(binding):
                    continue

                if active is not None and not active_used:
                    exchange = active
                    active_used = True
                    if kind == 'response':
                        response_offset = 1
                elif kind == 'request':
                    exchange = self._new_request(connection_id)
                else:
                    pending = self._pending[connection_id]
                    if response_offset >= len(pending):
                        raise AddonMessageError(
                            'An HTTP/1 response has no observed addon request')
                    exchange = pending[response_offset]
                    response_offset += 1

                flow = self.generation.get_flow(connection_id, exchange)
                if flow is None:
                    if kind != 'request':
                        raise AddonMessageError(
                            'An HTTP/1 response has no observed addon request')
                    flow = self.generation.create_flow(
                        connection_id, exchange, client_conn, server_conn)

                key = (connection_id, side, exchange)
                state, dispatched = await dispatch_message(
                    self.generation, flow, kind, binding,
                    self._messages.get(key),
                    allow_termination=True)
                self._messages[key] = state
                failures.extend(dispatched)

                if state.termination_hook is not None:
                    native_message.terminate(
                        binding.header,
                        reason=Error.KILLED_MESSAGE,
                    )
                    terminated = (
                        key,
                        flow,
                        state.termination_hook != 'response',
                    )
                    break

                if not binding.complete:
                    if index != len(bindings) - 1:
                        raise AddonMessageError(
                            'An incomplete HTTP/1 message must be the final typed group')
                    self._active[active_key] = exchange
                    native_message.parts.hold_from(binding.header)
                    break

                self._active.pop(active_key, None)
                if kind == 'request' and flow.response is not None:
                    failures.extend(await dispatch_local_response(
                        self.generation, flow, binding))
                    state.local_response = True
                else:
                    binding.apply()
                published.append(key)

            result = native_message.commit()
            for key in published:
                self._published(key)
            if terminated is not None:
                failures.extend(await self._finish_termination(terminated))
            return result, tuple(failures)
        except BaseException:
            self._failed = True
            self.generation.invalidate()
            raise

    def _published(self, key):
        state = self._messages[key]
        state.published = True
        connection_id, side, exchange = key
        active_key = (connection_id, side)
        if self._active.get(active_key) == exchange:
            self._active.pop(active_key, None)

        if state.local_response:
            pending = self._pending[connection_id]
            try:
                pending.remove(exchange)
            except ValueError as error:
                raise AddonMessageError(
                    'HTTP/1 local response lost its request order') from error
            self._release_exchange(connection_id, exchange)
            return

        peer = (connection_id, 'R' if side == 'L' else 'L', exchange)
        other = self._messages.get(peer)
        if other is not None and other.published:
            pending = self._pending[connection_id]
            if not pending or pending[0] != exchange:
                raise AddonMessageError('HTTP/1 response order changed unexpectedly')
            pending.popleft()
            self._release_exchange(connection_id, exchange)

    def _release_exchange(self, connection_id, exchange):
        for side in ('L', 'R'):
            self._messages.pop((connection_id, side, exchange), None)
        self.generation.release_flow(connection_id, exchange)

    async def _finish_termination(self, terminated):
        """Deliver the error hook only after native close publication."""
        key, flow, deliver_error = terminated
        connection_id, _, exchange = key
        state = self._messages.get(key)
        failures = []
        try:
            if deliver_error and state is not None and not state.error_delivered:
                state.error_delivered = True
                failures.extend(await self.generation.dispatch('error', flow))
        finally:
            self._release_exchange(connection_id, exchange)
        return tuple(failures)

    def release_connection(self, connection_id):
        keys = [key for key in self._messages if key[0] == connection_id]
        for key in keys:
            del self._messages[key]
        for side in ('L', 'R'):
            self._active.pop((connection_id, side), None)
        self._pending.pop(connection_id, None)
        self._next_exchange.pop(connection_id, None)
        return self.generation.release_connection(connection_id)
