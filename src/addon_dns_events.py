"""Dispatch explicitly classified complete DNS messages to addon hooks."""

from dataclasses import dataclass
import struct

from addon_connection import Client, ConnectionState, Server
from addon_dns import DNSFlow, DNSMessage, response_codes
from addon_flow import Error
from addon_runtime import AddonRuntimeError
from addon_transport_envelope import (
    bounded_text,
    exact_object,
    network_address,
)


class DNSTransportError(AddonRuntimeError):
    """The producer event cannot preserve DNS addon semantics."""


def _version_delivery_transport(envelope, setup=None):
    if type(envelope['version']) is not int or envelope['version'] != 1:
        raise DNSTransportError('dns_transport.version must be 1')
    if envelope['delivery'] != 'dns-message':
        raise DNSTransportError(
            'dns_transport.delivery must be dns-message')
    transport = envelope['transport']
    if transport not in ('udp', 'tcp'):
        raise DNSTransportError(
            'dns_transport.transport must be udp or tcp')
    if setup is not None and transport != setup.transport:
        raise DNSTransportError(
            'DNS transport identity changed during the connection')
    return transport


@dataclass(frozen=True)
class DNSTransportSetup:
    transport: str
    client: Client
    server: Server
    fingerprint: tuple

    @classmethod
    def parse(cls, value):
        envelope = exact_object(
            DNSTransportError,
            'dns_transport',
            value,
            ('version', 'delivery', 'transport', 'client', 'server'),
        )
        transport = _version_delivery_transport(envelope)
        client_data = exact_object(
            DNSTransportError,
            'dns_transport.client',
            envelope['client'],
            ('peername', 'sockname'),
        )
        server_data = exact_object(
            DNSTransportError,
            'dns_transport.server',
            envelope['server'],
            ('address', 'peername', 'sockname'),
        )
        client_peer = network_address(
            DNSTransportError,
            'dns_transport.client.peername',
            client_data['peername'],
        )
        client_sock = network_address(
            DNSTransportError,
            'dns_transport.client.sockname',
            client_data['sockname'],
        )
        server_address = network_address(
            DNSTransportError,
            'dns_transport.server.address',
            server_data['address'],
        )
        server_peer = network_address(
            DNSTransportError,
            'dns_transport.server.peername',
            server_data['peername'],
        )
        server_sock = network_address(
            DNSTransportError,
            'dns_transport.server.sockname',
            server_data['sockname'],
        )

        client = Client(
            peername=client_peer,
            sockname=client_sock,
            transport_protocol=transport,
        )
        server = Server(
            address=server_address,
            peername=server_peer,
            sockname=server_sock,
            transport_protocol=transport,
        )
        client.state = ConnectionState.OPEN
        server.state = ConnectionState.OPEN
        fingerprint = (
            transport,
            client_peer,
            client_sock,
            server_address,
            server_peer,
            server_sock,
        )
        return cls(transport, client, server, fingerprint)


@dataclass(frozen=True)
class DNSExchangeEvent:
    event: str
    exchange_id: int
    error: str | None = None

    @classmethod
    def parse(cls, value, setup, expected_event):
        fields = [
            'version', 'delivery', 'transport', 'event', 'exchange_id',
        ]
        if expected_event == 'error':
            fields.append('message')
        envelope = exact_object(
            DNSTransportError, 'dns_transport', value, fields)
        _version_delivery_transport(envelope, setup)
        if envelope['event'] != expected_event:
            raise DNSTransportError(
                'dns_transport.event must be ' + expected_event)
        exchange_id = envelope['exchange_id']
        if type(exchange_id) is not int or exchange_id < 1:
            raise DNSTransportError(
                'dns_transport.exchange_id must be a positive integer')
        error = None
        if expected_event == 'error':
            error = bounded_text(
                DNSTransportError,
                'dns_transport.message',
                envelope['message'],
                1024,
            )
        return cls(expected_event, exchange_id, error)


@dataclass(frozen=True)
class DNSDecision:
    action: str
    content: bytes | None = None


class DNSAddonEvents:
    """Maintain complete DNS exchanges without owning their transport."""

    HOOKS = frozenset({'dns_request', 'dns_response', 'dns_error'})
    MAX_MESSAGE_BYTES = 65535

    def __init__(self, generation, *, max_connections=128):
        if type(max_connections) is not int or not 1 <= max_connections <= 1024:
            raise ValueError('DNS connection limit must be between 1 and 1024')
        self.generation = generation
        self.max_connections = max_connections
        self._connections = {}
        self._exchanges = set()

    def register_connection(self, connection_id, setup):
        if not isinstance(connection_id, str) or not connection_id:
            raise DNSTransportError(
                'A non-empty DNS connection identity is required')
        if len(connection_id) > 1024:
            raise DNSTransportError(
                'DNS connection identity exceeds 1024 characters')
        if connection_id in self._connections:
            raise DNSTransportError(
                'DNS addon connection is already active')
        if len(self._connections) >= self.max_connections:
            raise DNSTransportError('DNS connection limit reached')
        if not isinstance(setup, DNSTransportSetup):
            raise DNSTransportError(
                'DNS setup must be a validated producer observation')
        self._connections[connection_id] = setup

    async def request(self, connection_id, value, content):
        setup = self._setup(connection_id)
        event = DNSExchangeEvent.parse(value, setup, 'request')
        key = (connection_id, event.exchange_id)
        if key in self._exchanges:
            raise DNSTransportError('DNS exchange is already active')

        request = self._message(content, query=True)
        flow = self.generation.create_dns_flow(
            connection_id,
            event.exchange_id,
            setup.client,
            setup.server,
        )
        self._exchanges.add(key)
        flow.request = request
        try:
            failures = list(await self.generation.dispatch(
                'dns_request', flow))
            self._reject_interception(flow)
            request_content = self._pack(flow.request, query=True)
            if flow.response is None:
                if not flow.live or flow.error is not None:
                    response = flow.request.fail(response_codes.SERVFAIL)
                    response_content = self._pack(response, query=False)
                    return self._finish(
                        key,
                        DNSDecision('local-response', response_content),
                        failures,
                    )
                return DNSDecision('forward', request_content), tuple(failures)

            failures.extend(await self.generation.dispatch(
                'dns_response', flow))
            self._reject_interception(flow)
            response_content = self._pack(flow.response, query=False)
            return self._finish(
                key,
                DNSDecision('local-response', response_content),
                failures,
            )
        except BaseException:
            self._release(key)
            raise

    async def response(self, connection_id, value, content):
        setup = self._setup(connection_id)
        event = DNSExchangeEvent.parse(value, setup, 'response')
        key = (connection_id, event.exchange_id)
        flow = self._flow(key)
        if flow.response is not None:
            raise DNSTransportError('DNS response is already present')
        flow.response = self._message(content, query=False)
        try:
            failures = list(await self.generation.dispatch(
                'dns_response', flow))
            self._reject_interception(flow)
            response_content = self._pack(flow.response, query=False)
            return self._finish(
                key,
                DNSDecision('replace-response', response_content),
                failures,
            )
        except BaseException:
            self._release(key)
            raise

    async def error(self, connection_id, value):
        setup = self._setup(connection_id)
        event = DNSExchangeEvent.parse(value, setup, 'error')
        key = (connection_id, event.exchange_id)
        flow = self._flow(key)
        try:
            flow.error = Error(event.error)
            flow.live = False
            failures = await self.generation.dispatch('dns_error', flow)
            return self._finish(
                key, DNSDecision('error'), failures)
        except BaseException:
            self._release(key)
            raise

    async def abort_connection(self, connection_id, reason):
        keys = tuple(
            key for key in self._exchanges if key[0] == connection_id)
        failures = []
        try:
            for key in keys:
                flow = self._flow(key)
                try:
                    flow.error = Error(reason)
                    flow.live = False
                    failures.extend(await self.generation.dispatch(
                        'dns_error', flow))
                finally:
                    self._release(key)
        finally:
            self._connections.pop(connection_id, None)
        return tuple(failures)

    def release_connection(self, connection_id):
        for key in tuple(self._exchanges):
            if key[0] == connection_id:
                self._release(key)
        self._connections.pop(connection_id, None)

    def _setup(self, connection_id):
        setup = self._connections.get(connection_id)
        if setup is None:
            raise DNSTransportError(
                'DNS event arrived without connection setup')
        return setup

    def _flow(self, key):
        if key not in self._exchanges:
            raise DNSTransportError('DNS event arrived without request')
        flow = self.generation.get_flow(*key)
        if not isinstance(flow, DNSFlow):
            raise DNSTransportError('DNS exchange lost its flow identity')
        return flow

    def _message(self, content, *, query):
        if not isinstance(content, bytes):
            raise DNSTransportError('DNS message content must be bytes')
        if not 1 <= len(content) <= self.MAX_MESSAGE_BYTES:
            raise DNSTransportError('DNS message size is outside producer limits')
        try:
            message = DNSMessage.unpack(content)
        except (ValueError, UnicodeError, struct.error) as error:
            raise DNSTransportError('DNS producer supplied an invalid message') from error
        if message.query is not query:
            expected = 'query' if query else 'response'
            raise DNSTransportError(
                'DNS producer event does not contain a ' + expected)
        return message

    def _pack(self, message, *, query):
        if not isinstance(message, DNSMessage):
            raise DNSTransportError(
                'DNS addon message must remain a DNSMessage')
        if message.query is not query:
            expected = 'query' if query else 'response'
            raise DNSTransportError(
                'DNS addon message must remain a ' + expected)
        try:
            content = message.packed
        except (AttributeError, TypeError, ValueError, UnicodeError,
                struct.error) as error:
            raise DNSTransportError(
                'DNS addon produced an invalid message') from error
        if not 1 <= len(content) <= self.MAX_MESSAGE_BYTES:
            raise DNSTransportError(
                'DNS addon message size is outside producer limits')
        return content

    @staticmethod
    def _reject_interception(flow):
        if flow.intercepted:
            raise DNSTransportError(
                'DNS interception requires producer suspension support')

    def _finish(self, key, decision, failures):
        self._release(key)
        return decision, tuple(failures)

    def _release(self, key):
        self._exchanges.discard(key)
        self.generation.release_flow(*key)
