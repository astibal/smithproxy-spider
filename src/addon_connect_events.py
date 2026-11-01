"""Dispatch producer-owned HTTP CONNECT lifecycle observations.

This adapter owns addon flow identity and hook ordering.  It receives HTTP
objects and connection descriptors produced by Spider's native boundary; it
does not parse CONNECT requests, open sockets, or serialize proxy traffic.
"""

from dataclasses import dataclass

from addon_connection import Client, Server
from addon_flow import Error
from addon_http_message import Request, Response
from addon_runtime import AddonRuntimeError
from addon_transport_envelope import bounded_text, exact_object


class HTTPConnectTransportError(AddonRuntimeError):
    """The producer event cannot preserve HTTP CONNECT semantics."""


@dataclass(frozen=True)
class HTTPConnectEvent:
    connection_id: str
    exchange_id: int
    event: str
    mode: str

    @classmethod
    def parse(cls, value, expected_event):
        envelope = exact_object(
            HTTPConnectTransportError,
            'http_connect',
            value,
            (
                'version', 'delivery', 'connection_id', 'exchange_id',
                'event', 'mode',
            ),
        )
        if type(envelope['version']) is not int or envelope['version'] != 1:
            raise HTTPConnectTransportError('http_connect.version must be 1')
        if envelope['delivery'] != 'http-connect':
            raise HTTPConnectTransportError(
                'http_connect.delivery must be http-connect')
        connection_id = bounded_text(
            HTTPConnectTransportError,
            'http_connect.connection_id',
            envelope['connection_id'],
            1024,
        )
        if not connection_id:
            raise HTTPConnectTransportError(
                'http_connect.connection_id must be bounded text')
        exchange_id = envelope['exchange_id']
        if type(exchange_id) is not int or exchange_id < 1:
            raise HTTPConnectTransportError(
                'http_connect.exchange_id must be a positive integer')
        event = envelope['event']
        if event != expected_event:
            raise HTTPConnectTransportError(
                'http_connect.event must be ' + expected_event)
        mode = envelope['mode']
        if mode not in ('regular', 'upstream'):
            raise HTTPConnectTransportError(
                'http_connect.mode must be regular or upstream')
        return cls(connection_id, exchange_id, event, mode)

    @property
    def key(self):
        return self.connection_id, self.exchange_id


@dataclass(frozen=True)
class HTTPConnectDecision:
    action: str
    request: Request | None = None
    response: Response | None = None


@dataclass
class _HTTPConnectState:
    flow: object
    mode: str
    stage: str


def _killed(flow):
    return (
        not flow.live
        and isinstance(flow.error, Error)
        and flow.error.msg == Error.KILLED_MESSAGE
    )


class HTTPConnectAddonEvents:
    """Maintain one truthful flow across native CONNECT observations."""

    HOOKS = frozenset({
        'http_connect',
        'http_connected',
        'http_connect_error',
        'http_connect_upstream',
    })

    def __init__(self, generation):
        self.generation = generation
        self._states = {}

    @property
    def active_exchanges(self):
        return len(self._states)

    async def request(self, value, request, client, server, response=None):
        event = HTTPConnectEvent.parse(value, 'request')
        if event.key in self._states:
            raise HTTPConnectTransportError(
                'HTTP CONNECT exchange is already active')
        if not isinstance(request, Request) or request.method != 'CONNECT':
            raise HTTPConnectTransportError(
                'HTTP CONNECT request requires a native CONNECT Request')
        if not isinstance(client, Client) or not isinstance(server, Server):
            raise HTTPConnectTransportError(
                'HTTP CONNECT requires native connection descriptors')
        self._validate_response(response, nullable=True)

        flow = self.generation.create_flow(
            event.connection_id,
            event.exchange_id,
            client,
            server,
        )
        flow.request = request
        flow.response = response
        flow._mode = event.mode
        state = _HTTPConnectState(flow, event.mode, 'request')
        self._states[event.key] = state
        try:
            failures = tuple(await self.generation.dispatch(
                'http_connect', flow))
            self._validate_request(flow.request)
            self._validate_response(flow.response, nullable=True)
            if flow.intercepted:
                raise HTTPConnectTransportError(
                    'HTTP CONNECT interception has no native control boundary')

            if _killed(flow):
                decision = HTTPConnectDecision('kill')
                self._release(event.key)
            elif not flow.live or flow.error is not None:
                raise HTTPConnectTransportError(
                    'HTTP CONNECT request entered an unsupported flow state')
            elif flow.response is not None:
                state.stage = 'error'
                decision = HTTPConnectDecision(
                    'local-response',
                    response=flow.response.copy(),
                )
            else:
                state.stage = 'outcome'
                decision = HTTPConnectDecision(
                    'continue',
                    request=flow.request.copy(),
                )
            return decision, failures
        except BaseException:
            self._release(event.key)
            raise

    async def connected(self, value, response):
        event, state = self._event_state(value, 'connected', 'outcome')
        self._validate_response(response)
        flow = state.flow
        flow.response = response
        try:
            failures = tuple(await self.generation.dispatch(
                'http_connected', flow))
            self._validate_response(flow.response)
            if flow.intercepted:
                raise HTTPConnectTransportError(
                    'HTTP CONNECT interception has no native control boundary')
            decision = HTTPConnectDecision(
                'send-response',
                response=flow.response.copy(),
            )
            if state.mode == 'upstream':
                state.stage = 'upstream'
            else:
                self._release(event.key)
            return decision, failures
        except BaseException:
            self._release(event.key)
            raise

    async def error(self, value, response=None):
        event = HTTPConnectEvent.parse(value, 'error')
        state = self._state(event)
        if state.stage not in ('outcome', 'error'):
            raise HTTPConnectTransportError(
                'HTTP CONNECT error arrived out of order')
        if response is not None:
            self._validate_response(response)
            state.flow.response = response
        self._validate_response(state.flow.response)
        try:
            failures = tuple(await self.generation.dispatch(
                'http_connect_error', state.flow))
            self._validate_response(state.flow.response)
            if state.flow.intercepted:
                raise HTTPConnectTransportError(
                    'HTTP CONNECT interception has no native control boundary')
            decision = HTTPConnectDecision(
                'send-response',
                response=state.flow.response.copy(),
            )
            return decision, failures
        finally:
            self._release(event.key)

    async def upstream(self, value):
        event, state = self._event_state(value, 'upstream', 'upstream')
        flow = state.flow
        flow.response = None
        flow.live = False
        try:
            failures = tuple(await self.generation.dispatch(
                'http_connect_upstream', flow))
            self._validate_request(flow.request)
            if flow.intercepted:
                raise HTTPConnectTransportError(
                    'HTTP CONNECT interception has no native control boundary')
            decision = HTTPConnectDecision(
                'upstream-authority',
                request=flow.request.copy(),
            )
            return decision, failures
        finally:
            self._release(event.key)

    def abort_connection(self, connection_id):
        if not isinstance(connection_id, str) or not connection_id:
            raise HTTPConnectTransportError(
                'A non-empty HTTP CONNECT connection identity is required')
        keys = [key for key in self._states if key[0] == connection_id]
        return tuple(self._release(key) for key in keys)

    def _event_state(self, value, event_name, expected_stage):
        event = HTTPConnectEvent.parse(value, event_name)
        state = self._state(event)
        if state.stage != expected_stage:
            raise HTTPConnectTransportError(
                'HTTP CONNECT ' + event_name + ' arrived out of order')
        return event, state

    def _state(self, event):
        state = self._states.get(event.key)
        if state is None:
            raise HTTPConnectTransportError(
                'HTTP CONNECT event arrived without a request')
        if state.mode != event.mode:
            raise HTTPConnectTransportError(
                'HTTP CONNECT mode changed during the exchange')
        return state

    def _release(self, key):
        state = self._states.pop(key)
        self.generation.release_flow(*key)
        return state.flow

    @staticmethod
    def _validate_request(request):
        if not isinstance(request, Request):
            raise HTTPConnectTransportError(
                'HTTP CONNECT hooks must retain an HTTP Request')

    @staticmethod
    def _validate_response(response, *, nullable=False):
        if nullable and response is None:
            return
        if not isinstance(response, Response):
            raise HTTPConnectTransportError(
                'HTTP CONNECT hooks must retain an HTTP Response')
        if not isinstance(response.raw_content, bytes):
            raise HTTPConnectTransportError(
                'HTTP CONNECT response requires a complete byte body')
