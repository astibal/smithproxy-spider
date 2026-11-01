"""Validate and dispatch producer-owned logical WebSocket messages.

This module deliberately owns no RFC 6455 framing.  It consumes complete
logical messages from an explicit producer contract and returns structured
decisions for a future native transport integration.
"""

from dataclasses import dataclass
import time

from wsproto.frame_protocol import Opcode

from addon_flow import Error, HTTPFlow
from addon_runtime import AddonRuntimeError
from addon_transport_envelope import bounded_text, exact_object
from addon_websocket import WebSocketData, WebSocketMessage


class WebSocketTransportError(AddonRuntimeError):
    """The producer event cannot preserve WebSocket addon semantics."""


def _connection_id(value):
    return bounded_text(
        WebSocketTransportError, 'websocket.connection_id', value, 1024)


def _version_and_event(envelope, event):
    if type(envelope['version']) is not int or envelope['version'] != 1:
        raise WebSocketTransportError('websocket.version must be 1')
    if envelope['event'] != event:
        raise WebSocketTransportError(
            'websocket.event must be ' + event)


@dataclass(frozen=True)
class WebSocketSetup:
    connection_id: str
    exchange_id: int
    subprotocol: str | None
    extensions: tuple[str, ...]

    @classmethod
    def parse(cls, value):
        envelope = exact_object(
            WebSocketTransportError, 'websocket', value,
            ('version', 'connection_id', 'exchange_id', 'event',
             'subprotocol', 'extensions'),
        )
        _version_and_event(envelope, 'start')
        connection_id = _connection_id(envelope['connection_id'])
        exchange_id = envelope['exchange_id']
        if type(exchange_id) is not int or exchange_id < 1:
            raise WebSocketTransportError(
                'websocket.exchange_id must be a positive integer')
        subprotocol = bounded_text(
            WebSocketTransportError, 'websocket.subprotocol',
            envelope['subprotocol'], 1024,
            nullable=True,
        )
        raw_extensions = envelope['extensions']
        if not isinstance(raw_extensions, list) or len(raw_extensions) > 64:
            raise WebSocketTransportError(
                'websocket.extensions must be a bounded list')
        extensions = tuple(
            bounded_text(
                WebSocketTransportError, 'websocket extension', extension, 1024)
            for extension in raw_extensions
        )
        return cls(connection_id, exchange_id, subprotocol, extensions)


@dataclass(frozen=True)
class WebSocketObservation:
    sequence: int
    from_client: bool
    opcode: Opcode
    compressed_on_wire: bool

    @classmethod
    def parse(cls, value, setup, previous_sequence):
        envelope = exact_object(
            WebSocketTransportError, 'websocket', value,
            ('version', 'connection_id', 'event', 'sequence', 'direction',
             'opcode', 'compressed_on_wire'),
        )
        _version_and_event(envelope, 'message')
        if _connection_id(envelope['connection_id']) != setup.connection_id:
            raise WebSocketTransportError(
                'websocket connection identity changed')

        sequence = envelope['sequence']
        if type(sequence) is not int or sequence < 0:
            raise WebSocketTransportError(
                'websocket.sequence must be a non-negative integer')
        if previous_sequence is not None and sequence != previous_sequence + 1:
            raise WebSocketTransportError(
                'websocket sequence is not contiguous')

        direction = envelope['direction']
        if direction not in ('client-to-server', 'server-to-client'):
            raise WebSocketTransportError('websocket.direction is invalid')
        opcode = envelope['opcode']
        if type(opcode) is not int or opcode not in (int(Opcode.TEXT), int(Opcode.BINARY)):
            raise WebSocketTransportError(
                'websocket.opcode must identify a text or binary message')
        compressed = envelope['compressed_on_wire']
        if type(compressed) is not bool:
            raise WebSocketTransportError(
                'websocket.compressed_on_wire must be a boolean')
        return cls(
            sequence,
            direction == 'client-to-server',
            Opcode(opcode),
            compressed,
        )


@dataclass(frozen=True)
class WebSocketTerminal:
    close_code: int | None
    close_reason: str | None
    closed_by_client: bool | None
    transport_error: str | None

    @classmethod
    def parse(cls, value, setup):
        envelope = exact_object(
            WebSocketTransportError, 'websocket', value,
            ('version', 'connection_id', 'event', 'close_code',
             'close_reason', 'closed_by_client', 'transport_error'),
        )
        _version_and_event(envelope, 'end')
        if _connection_id(envelope['connection_id']) != setup.connection_id:
            raise WebSocketTransportError(
                'websocket connection identity changed')

        close_code = envelope['close_code']
        if (close_code is not None and
                (type(close_code) is not int or not 0 <= close_code <= 65535)):
            raise WebSocketTransportError(
                'websocket.close_code must be null or an unsigned 16-bit integer')
        close_reason = bounded_text(
            WebSocketTransportError, 'websocket.close_reason',
            envelope['close_reason'], 1024,
            nullable=True,
        )
        closed_by_client = envelope['closed_by_client']
        if closed_by_client is not None and type(closed_by_client) is not bool:
            raise WebSocketTransportError(
                'websocket.closed_by_client must be boolean or null')
        transport_error = bounded_text(
            WebSocketTransportError, 'websocket.transport_error',
            envelope['transport_error'], 1024,
            nullable=True,
        )
        return cls(
            close_code,
            close_reason,
            closed_by_client,
            transport_error,
        )


@dataclass(frozen=True)
class WebSocketDecision:
    action: str
    opcode: int | None = None
    content: bytes | None = None


class WebSocketAddonEvents:
    """Maintain the public flow lifecycle without owning wire framing."""

    HOOKS = frozenset({
        'websocket_start', 'websocket_message', 'websocket_end',
    })
    MAX_MESSAGES = 4096
    MAX_HISTORY_BYTES = 16 * 1024 * 1024
    MAX_GENERATION_MESSAGES = 16384
    MAX_GENERATION_HISTORY_BYTES = 32 * 1024 * 1024

    def __init__(self, generation):
        self.generation = generation
        self._flows = {}
        self._setups = {}
        self._sequences = {}
        self._history_bytes = {}
        self._history_counts = {}
        self._generation_history_bytes = 0
        self._generation_message_count = 0

    async def start(self, setup, flow):
        identity = setup.connection_id
        if identity in self._flows:
            raise WebSocketTransportError(
                'WebSocket addon connection is already active')
        if not isinstance(flow, HTTPFlow) or not flow.live:
            raise WebSocketTransportError(
                'WebSocket setup requires the live upgraded HTTP flow')
        if flow.websocket is not None:
            raise WebSocketTransportError(
                'The HTTP flow already owns WebSocket state')

        websocket = WebSocketData()
        flow.websocket = websocket
        self._flows[identity] = flow
        self._setups[identity] = setup
        self._sequences[identity] = None
        self._history_bytes[identity] = 0
        self._history_counts[identity] = 0
        try:
            failures = tuple(await self.generation.dispatch(
                'websocket_start', flow))
            if flow.websocket is not websocket:
                raise WebSocketTransportError(
                    'WebSocket start hooks must not replace transport state')
            return failures
        except BaseException:
            self._forget(identity)
            flow.websocket = None
            raise

    async def message(self, value, content):
        if not isinstance(content, bytes):
            raise WebSocketTransportError(
                'WebSocket message content must be bytes')
        identity = value.get('connection_id') if isinstance(value, dict) else None
        flow = self._flows.get(identity)
        if flow is None:
            raise WebSocketTransportError(
                'WebSocket message arrived without setup')
        setup = self._setups[identity]
        observation = WebSocketObservation.parse(
            value, setup, self._sequences[identity])
        self._check_admission(identity, flow, len(content))

        message = WebSocketMessage(
            observation.opcode,
            observation.from_client,
            content,
            timestamp=time.time(),
        )
        flow.websocket.messages.append(message)
        history_identity = tuple(
            id(item) for item in flow.websocket.messages)
        failures = await self.generation.dispatch('websocket_message', flow)

        if tuple(id(item) for item in flow.websocket.messages) != history_identity:
            raise WebSocketTransportError(
                'WebSocket hooks must not replace the message history')
        self._validate_message(message)
        history_size = self._measure_history(flow)
        self._commit_accounting(identity, flow, history_size)
        self._sequences[identity] = observation.sequence

        if message.dropped:
            decision = WebSocketDecision('drop')
        elif message.type == observation.opcode and message.content == content:
            decision = WebSocketDecision('pass')
        else:
            decision = WebSocketDecision(
                'replace', int(message.type), message.content)
        return decision, tuple(failures)

    async def stop(self, value):
        identity = value.get('connection_id') if isinstance(value, dict) else None
        flow = self._flows.get(identity)
        if flow is None:
            raise WebSocketTransportError(
                'WebSocket terminal event arrived without setup')
        setup = self._setups[identity]
        terminal = WebSocketTerminal.parse(value, setup)
        try:
            flow.websocket.close_code = terminal.close_code
            flow.websocket.close_reason = terminal.close_reason
            flow.websocket.closed_by_client = terminal.closed_by_client
            flow.websocket.timestamp_end = time.time()
            if terminal.transport_error is not None:
                flow.error = Error(terminal.transport_error)
            failures = tuple(await self.generation.dispatch(
                'websocket_end', flow))
            flow.live = False
            return failures
        finally:
            self._forget(identity)

    async def abort(self, connection_id, reason):
        flow = self._flows.get(connection_id)
        if flow is None:
            return ()
        try:
            flow.live = False
            flow.error = Error(reason)
            flow.websocket.timestamp_end = time.time()
            return tuple(await self.generation.dispatch(
                'websocket_end', flow))
        finally:
            self._forget(connection_id)

    def release_connection(self, connection_id):
        self._forget(connection_id)

    def _check_admission(self, identity, flow, incoming_size):
        messages = flow.websocket.messages
        if len(messages) >= self.MAX_MESSAGES:
            raise WebSocketTransportError(
                'WebSocket message history limit reached')
        if self._generation_message_count >= self.MAX_GENERATION_MESSAGES:
            raise WebSocketTransportError(
                'WebSocket generation message limit reached')
        history_size = self._measure_history(flow)
        if history_size + incoming_size > self.MAX_HISTORY_BYTES:
            raise WebSocketTransportError(
                'WebSocket message history exceeds 16 MiB')
        generation_size = (
            self._generation_history_bytes
            - self._history_bytes[identity]
            + history_size
            + incoming_size
        )
        if generation_size > self.MAX_GENERATION_HISTORY_BYTES:
            raise WebSocketTransportError(
                'WebSocket generation history limit reached')

    def _commit_accounting(self, identity, flow, history_size):
        if history_size > self.MAX_HISTORY_BYTES:
            raise WebSocketTransportError(
                'WebSocket message history exceeds 16 MiB')
        generation_size = (
            self._generation_history_bytes
            - self._history_bytes[identity]
            + history_size
        )
        if generation_size > self.MAX_GENERATION_HISTORY_BYTES:
            raise WebSocketTransportError(
                'WebSocket generation history limit reached')
        message_count = len(flow.websocket.messages)
        generation_count = (
            self._generation_message_count
            - self._history_counts[identity]
            + message_count
        )
        if generation_count > self.MAX_GENERATION_MESSAGES:
            raise WebSocketTransportError(
                'WebSocket generation message limit reached')

        self._generation_history_bytes = generation_size
        self._generation_message_count = generation_count
        self._history_bytes[identity] = history_size
        self._history_counts[identity] = message_count

    @staticmethod
    def _validate_message(message):
        if message.injected:
            raise WebSocketTransportError(
                'Observed messages cannot become injected messages')
        if not isinstance(message.content, bytes):
            raise WebSocketTransportError(
                'WebSocket addon message content must remain bytes')
        if message.type not in (Opcode.TEXT, Opcode.BINARY):
            raise WebSocketTransportError(
                'WebSocket addon message type must remain text or binary')
        if message.is_text:
            try:
                message.content.decode('utf-8')
            except UnicodeDecodeError as error:
                raise WebSocketTransportError(
                    'WebSocket text replacement must be valid UTF-8') from error

    @staticmethod
    def _measure_history(flow):
        size = 0
        for message in flow.websocket.messages:
            if not isinstance(message.content, bytes):
                raise WebSocketTransportError(
                    'WebSocket addon message content must remain bytes')
            size += len(message.content)
        return size

    def _forget(self, identity):
        self._flows.pop(identity, None)
        self._setups.pop(identity, None)
        self._sequences.pop(identity, None)
        self._generation_history_bytes -= self._history_bytes.pop(identity, 0)
        self._generation_message_count -= self._history_counts.pop(identity, 0)
