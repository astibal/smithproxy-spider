"""Deliver explicitly classified raw TCP and UDP addon events.

This module consumes a versioned producer envelope.  It never guesses a
transport from payload bytes, session labels, ports, or application protocol.
Spider's native Opaque Part remains the only byte-rewrite mechanism.
"""

from dataclasses import dataclass
import time

from addon_connection import Client, ConnectionState, Server
from addon_flow import Error, TCPMessage, UDPMessage
from addon_runtime import AddonRuntimeError
from addon_transport_envelope import exact_object, network_address


class RawTransportError(AddonRuntimeError):
    """The producer envelope cannot preserve raw transport semantics."""


@dataclass(frozen=True)
class RawTransportSetup:
    kind: str
    client: Client
    server: Server
    fingerprint: tuple

    @classmethod
    def parse(cls, value):
        envelope = exact_object(
            RawTransportError, 'raw_transport', value,
            ('version', 'kind', 'delivery', 'client', 'server'),
        )
        if envelope['version'] != 1 or type(envelope['version']) is not int:
            raise RawTransportError('raw_transport.version must be 1')
        kind = envelope['kind']
        if kind not in ('tcp', 'udp'):
            raise RawTransportError('raw_transport.kind must be tcp or udp')
        if envelope['delivery'] != 'raw':
            raise RawTransportError('raw_transport.delivery must be raw')

        client_data = exact_object(
            RawTransportError, 'raw_transport.client', envelope['client'],
            ('peername', 'sockname'))
        server_data = exact_object(
            RawTransportError, 'raw_transport.server', envelope['server'],
            ('address', 'peername', 'sockname'))
        client_peer = network_address(
            RawTransportError, 'raw_transport.client.peername', client_data['peername'])
        client_sock = network_address(
            RawTransportError, 'raw_transport.client.sockname', client_data['sockname'])
        server_address = network_address(
            RawTransportError, 'raw_transport.server.address', server_data['address'])
        server_peer = network_address(
            RawTransportError, 'raw_transport.server.peername', server_data['peername'])
        server_sock = network_address(
            RawTransportError, 'raw_transport.server.sockname', server_data['sockname'])

        client = Client(
            peername=client_peer,
            sockname=client_sock,
            transport_protocol=kind,
        )
        server = Server(
            address=server_address,
            peername=server_peer,
            sockname=server_sock,
            transport_protocol=kind,
        )
        client.state = ConnectionState.OPEN
        server.state = ConnectionState.OPEN
        fingerprint = (
            kind, client_peer, client_sock,
            server_address, server_peer, server_sock,
        )
        return cls(kind, client, server, fingerprint)


@dataclass(frozen=True)
class RawTransportContent:
    from_client: bool
    sequence: int

    @classmethod
    def parse(cls, value, setup, side, previous_sequence):
        envelope = exact_object(
            RawTransportError, 'raw_transport', value,
            ('version', 'kind', 'delivery', 'client', 'server',
             'direction', 'sequence', 'unit'),
        )
        core = {key: envelope[key] for key in
                ('version', 'kind', 'delivery', 'client', 'server')}
        observed = RawTransportSetup.parse(core)
        if observed.fingerprint != setup.fingerprint:
            raise RawTransportError('raw transport identity changed during the connection')

        direction = envelope['direction']
        if direction not in ('client-to-server', 'server-to-client'):
            raise RawTransportError('raw_transport.direction is invalid')
        from_client = direction == 'client-to-server'
        expected_side = 'L' if from_client else 'R'
        if side != expected_side:
            raise RawTransportError('raw transport direction does not match callback side')

        unit = envelope['unit']
        expected_unit = 'stream-chunk' if setup.kind == 'tcp' else 'datagram'
        if unit != expected_unit:
            raise RawTransportError('raw transport unit does not match its kind')
        sequence = envelope['sequence']
        if type(sequence) is not int or not 0 <= sequence <= 0x7fffffffffffffff:
            raise RawTransportError('raw_transport.sequence must be a non-negative integer')
        if previous_sequence is not None and sequence != previous_sequence + 1:
            raise RawTransportError('raw transport sequence is not contiguous')
        return cls(from_client, sequence)


@dataclass(frozen=True)
class RawTransportTerminal:
    error: str | None

    @classmethod
    def parse(cls, value, setup):
        envelope = exact_object(
            RawTransportError, 'raw_transport', value,
            ('version', 'kind', 'delivery', 'client', 'server', 'terminal'),
        )
        core = {key: envelope[key] for key in
                ('version', 'kind', 'delivery', 'client', 'server')}
        observed = RawTransportSetup.parse(core)
        if observed.fingerprint != setup.fingerprint:
            raise RawTransportError('raw transport identity changed during the connection')
        terminal = exact_object(
            RawTransportError, 'raw_transport.terminal', envelope['terminal'],
            ('state', 'message'))
        state = terminal['state']
        if state not in ('closed', 'error'):
            raise RawTransportError('raw transport terminal state is invalid')
        message = terminal['message']
        if not isinstance(message, str) or len(message.encode('utf-8')) > 1024:
            raise RawTransportError('raw transport terminal message must be bounded text')
        if any(character in message for character in ('\r', '\n', '\x00')):
            raise RawTransportError('raw transport terminal message contains a control character')
        return cls(message if state == 'error' else None)


class RawAddonEvents:
    HOOKS = frozenset({
        'tcp_start', 'tcp_message', 'tcp_end', 'tcp_error',
        'udp_start', 'udp_message', 'udp_end', 'udp_error',
    })
    MAX_MESSAGES = 4096
    MAX_HISTORY_BYTES = 16 * 1024 * 1024
    MAX_GENERATION_MESSAGES = 16384
    MAX_GENERATION_HISTORY_BYTES = 32 * 1024 * 1024

    def __init__(self, generation, opaque_part_factory=None):
        self.generation = generation
        self._opaque_part_factory = opaque_part_factory
        self._flows = {}
        self._sequence = {}
        self._history_bytes = {}
        self._history_counts = {}
        self._generation_history_bytes = 0
        self._generation_message_count = 0

    async def start(self, connection_id, setup):
        if connection_id in self._flows:
            raise RawTransportError('Raw addon connection is already active')
        flow = self.generation.create_transport_flow(
            connection_id, setup.kind, setup.client, setup.server)
        self._flows[connection_id] = flow
        self._sequence[connection_id] = None
        self._history_bytes[connection_id] = 0
        self._history_counts[connection_id] = 0
        failures = await self.generation.dispatch(setup.kind + '_start', flow)
        self._check_transport_decision(flow)
        return tuple(failures)

    async def content(self, connection_id, side, native_message, setup, envelope):
        flow = self._flows.get(connection_id)
        if flow is None:
            raise RawTransportError('Raw content arrived without setup')
        observation = RawTransportContent.parse(
            envelope, setup, side, self._sequence[connection_id])
        payload = native_message.bytes
        if setup.kind == 'tcp' and not payload:
            raise RawTransportError('A TCP stream chunk must not be empty')
        if len(flow.messages) >= self.MAX_MESSAGES:
            raise RawTransportError('Raw transport message history limit reached')
        if self._generation_message_count >= self.MAX_GENERATION_MESSAGES:
            raise RawTransportError(
                'Raw transport generation message limit reached')
        history_size = self._measure_history(flow)
        if history_size + len(payload) > self.MAX_HISTORY_BYTES:
            raise RawTransportError('Raw transport message history exceeds 16 MiB')
        generation_size = (
            self._generation_history_bytes
            - self._history_bytes[connection_id]
            + history_size
            + len(payload)
        )
        if generation_size > self.MAX_GENERATION_HISTORY_BYTES:
            raise RawTransportError(
                'Raw transport generation history limit reached')

        message_type = TCPMessage if setup.kind == 'tcp' else UDPMessage
        message = message_type(observation.from_client, payload, time.time())
        flow.messages.append(message)
        message_history = tuple(id(observed) for observed in flow.messages)
        failures = await self.generation.dispatch(setup.kind + '_message', flow)
        self._check_transport_decision(flow)
        if tuple(id(observed) for observed in flow.messages) != message_history:
            raise RawTransportError(
                'Raw addon hooks must not replace the transport message history')
        history_size = self._measure_history(flow)
        if history_size > self.MAX_HISTORY_BYTES:
            raise RawTransportError('Raw transport message history exceeds 16 MiB')
        generation_size = (
            self._generation_history_bytes
            - self._history_bytes[connection_id]
            + history_size
        )
        if generation_size > self.MAX_GENERATION_HISTORY_BYTES:
            raise RawTransportError(
                'Raw transport generation history limit reached')
        generation_count = (
            self._generation_message_count
            - self._history_counts[connection_id]
            + len(flow.messages)
        )
        if generation_count > self.MAX_GENERATION_MESSAGES:
            raise RawTransportError(
                'Raw transport generation message limit reached')

        parts = tuple(native_message.parts)
        if parts and (len(parts) != 1 or parts[0].type != 'opaque'):
            raise RawTransportError('Raw callbacks require one Opaque native Part')
        if parts:
            parts[0].set_bytes(message.content)
        elif message.content:
            if self._opaque_part_factory is None:
                raise RawTransportError(
                    'Raw empty-input expansion needs a native Opaque Part factory')
            native_message.parts.append(
                self._opaque_part_factory(message.content, data=message.content))

        result = native_message.commit()
        self._generation_history_bytes = generation_size
        self._generation_message_count = generation_count
        self._history_bytes[connection_id] = history_size
        self._history_counts[connection_id] = len(flow.messages)
        self._sequence[connection_id] = observation.sequence
        return result, tuple(failures)

    async def stop(self, connection_id, setup, envelope):
        flow = self._flows.get(connection_id)
        if flow is None:
            return ()
        failures = []
        try:
            terminal = RawTransportTerminal.parse(envelope, setup)
            flow.client_conn.state = ConnectionState.CLOSED
            flow.server_conn.state = ConnectionState.CLOSED
            flow.client_conn.timestamp_end = time.time()
            flow.server_conn.timestamp_end = flow.client_conn.timestamp_end
            if terminal.error is not None:
                flow.live = False
                flow.error = Error(terminal.error)
                failures.extend(await self.generation.dispatch(
                    setup.kind + '_error', flow))
            else:
                failures.extend(await self.generation.dispatch(
                    setup.kind + '_end', flow))
        finally:
            self._forget_connection(connection_id)
            self.generation.release_flow(connection_id, 1)
        return tuple(failures)

    async def abort(self, connection_id, setup, reason):
        flow = self._flows.get(connection_id)
        if flow is None:
            return ()
        failures = []
        try:
            flow.live = False
            flow.client_conn.state = ConnectionState.CLOSED
            flow.server_conn.state = ConnectionState.CLOSED
            flow.client_conn.timestamp_end = time.time()
            flow.server_conn.timestamp_end = flow.client_conn.timestamp_end
            flow.error = Error(reason)
            failures.extend(await self.generation.dispatch(
                setup.kind + '_error', flow))
        finally:
            self._forget_connection(connection_id)
            self.generation.release_flow(connection_id, 1)
        return tuple(failures)

    def release_connection(self, connection_id):
        self._forget_connection(connection_id)
        return self.generation.release_flow(connection_id, 1)

    def _forget_connection(self, connection_id):
        self._flows.pop(connection_id, None)
        self._sequence.pop(connection_id, None)
        self._generation_history_bytes -= self._history_bytes.pop(
            connection_id, 0)
        self._generation_message_count -= self._history_counts.pop(
            connection_id, 0)

    @staticmethod
    def _measure_history(flow):
        size = 0
        for message in flow.messages:
            if not isinstance(message.content, bytes):
                raise RawTransportError(
                    'Raw addon message content must remain bytes')
            size += len(message.content)
        return size

    @staticmethod
    def _check_transport_decision(flow):
        if flow.intercepted:
            raise RawTransportError(
                'Raw flow interception requires producer suspension support')
