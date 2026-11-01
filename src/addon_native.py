"""Connect one addon generation to Spider's native per-callback API objects.

The worker supplies observed connection descriptors at setup. This adapter does
not infer endpoints from display strings or acquire any network resources.
"""

from dataclasses import dataclass
import time

from addon_connection import Client, ConnectionState, Server
from addon_flow import Error
from addon_h1_events import H1AddonEvents
from addon_h2_events import H2AddonEvents
from addon_raw_events import RawAddonEvents, RawTransportError, RawTransportSetup
from addon_runtime import AddonRuntimeError


@dataclass(frozen=True)
class _NativeConnection:
    kind: str
    client: object
    server: object
    raw_setup: RawTransportSetup | None = None


class NativeAddonAdapter:
    CONNECTION_HOOKS = frozenset({
        'client_connected',
        'client_disconnected',
    })
    # Passive hooks are available to addon code but are never synthesized from
    # native traffic. In particular, ordinary Python logging must not loop back
    # through the deprecated add_log event. The event is delivered only when an
    # addon explicitly triggers AddLogHook through the public addon manager.
    PASSIVE_HOOKS = frozenset({'add_log'})
    HOOKS = (H2AddonEvents.HOOKS | RawAddonEvents.HOOKS |
             CONNECTION_HOOKS | PASSIVE_HOOKS)

    def __init__(self, generation, *, max_connections=128, body_limit=256 * 1024,
                 opaque_part_factory=None):
        if type(max_connections) is not int or not 1 <= max_connections <= 1024:
            raise ValueError('Connection limit must be between 1 and 1024')
        self.generation = generation
        self.http1 = H1AddonEvents(generation)
        self.http2 = H2AddonEvents(generation, body_limit=body_limit)
        self.raw = RawAddonEvents(generation, opaque_part_factory)
        self.max_connections = max_connections
        self._connections = {}

    @staticmethod
    def _identity(session_id):
        if not isinstance(session_id, str) or not session_id or len(session_id) > 1024:
            raise AddonRuntimeError('A bounded connection identity is required')
        return session_id

    @property
    def active_connections(self):
        return len(self._connections)

    @staticmethod
    def _http_descriptors(client_conn, server_conn):
        """Create one descriptor pair shared by every flow on a connection."""
        if client_conn is None:
            client_conn = Client(peername=None, sockname=None)
        if server_conn is None:
            server_conn = Server(address=None)
        if isinstance(client_conn, Client):
            client_conn.state = ConnectionState.OPEN
            if client_conn.timestamp_start is None:
                client_conn.timestamp_start = time.time()
            client_conn.timestamp_end = None
        return client_conn, server_conn

    @staticmethod
    def _close_descriptors(registered):
        timestamp = time.time()
        if isinstance(registered.client, Client):
            registered.client.state = ConnectionState.CLOSED
            registered.client.timestamp_end = timestamp
        if (registered.raw_setup is not None and
                isinstance(registered.server, Server)):
            registered.server.state = ConnectionState.CLOSED
            if registered.server.timestamp_end is None:
                registered.server.timestamp_end = timestamp

    def setup(self, api, client_conn, server_conn):
        """Reserve native rewrite before any inspected payload arrives."""
        if self.generation.state != 'running':
            raise AddonRuntimeError('The addon generation is not running')
        if api.phase != 'setup':
            raise AddonRuntimeError('Register connections only during native setup')
        identity = self._identity(api.session_id)
        if identity in self._connections:
            raise AddonRuntimeError('The addon connection is already registered')
        if len(self._connections) >= self.max_connections:
            raise AddonRuntimeError('Addon connection limit reached')
        if api.instance.mode != 'flow':
            raise AddonRuntimeError('Addon execution requires native flow instantiation')
        api.connection.request_rewrite()
        raw_value = getattr(api, 'info', {}).get('raw_transport')
        if raw_value is None:
            # Compatibility lifecycle decisions need native reception state,
            # independently of which addon hooks have already been delivered.
            api.connection.track_states()
            client_conn, server_conn = self._http_descriptors(
                client_conn, server_conn)
            self._connections[identity] = _NativeConnection(
                'http', client_conn, server_conn)
            if self.generation.observes('client_connected'):
                return self._start_http(identity, client_conn)
            return None

        setup = RawTransportSetup.parse(raw_value)
        self._connections[identity] = _NativeConnection(
            setup.kind, setup.client, setup.server, setup)
        return self._start_raw(identity, setup)

    async def _start_http(self, identity, client):
        try:
            return await self.generation.dispatch('client_connected', client)
        except BaseException:
            self.http1.release_connection(identity)
            self.http2.release_connection(identity)
            self._connections.pop(identity, None)
            self.generation.invalidate()
            raise

    async def _start_raw(self, identity, setup):
        try:
            failures = []
            if self.generation.observes('client_connected'):
                failures.extend(await self.generation.dispatch(
                    'client_connected', setup.client))
            failures.extend(await self.raw.start(identity, setup))
            return tuple(failures)
        except BaseException:
            self.raw.release_connection(identity)
            self._connections.pop(identity, None)
            self.generation.invalidate()
            raise

    async def content(self, api):
        """Return the actual Translate result for the worker's existing serializer."""
        if self.generation.state != 'running':
            raise AddonRuntimeError('The addon generation is not running')
        identity = self._identity(api.session_id)
        if api.phase != 'content' or api.message is None:
            raise AddonRuntimeError('A native content callback is required')
        if identity not in self._connections:
            raise AddonRuntimeError('Content arrived without addon connection setup')
        registered = self._connections[identity]
        try:
            raw_value = getattr(api, 'info', {}).get('raw_transport')
            if registered.raw_setup is not None:
                if raw_value is None:
                    raise RawTransportError(
                        'Raw content callback is missing raw_transport metadata')
                api.connection.set_mode('rewrite')
                result, failures = await self.raw.content(
                    identity,
                    api.side,
                    api.message,
                    registered.raw_setup,
                    raw_value,
                )
                for failure in failures:
                    api.print(f'Addon {failure.addon} {failure.hook}: '
                              f'{type(failure.exception).__name__}: {failure.exception}')
                return result
            if raw_value is not None:
                raise RawTransportError(
                    'HTTP connection cannot change into a raw transport')

            is_http1 = any(part.type == 'http1.header'
                           for part in api.message.parts)
            if is_http1:
                api.connection.set_mode('rewrite')
                result, failures = await self.http1.rewrite(
                    identity, api.side, api.message,
                    registered.client, registered.server)
            else:
                api.connection.set_mode('translate')
                result, failures = await self.http2.translate(
                    identity, api.side, api.message, api.http2,
                    api.connection, registered.client, registered.server)
        except BaseException:
            self.generation.invalidate()
            raise
        for failure in failures:
            api.print(f'Addon {failure.addon} {failure.hook}: '
                      f'{type(failure.exception).__name__}: {failure.exception}')
        return result

    async def stop(self, session_id, info=None):
        """Finish pending exchanges before releasing their connection descriptors."""
        identity = self._identity(session_id)
        if identity not in self._connections:
            return ()
        failures = []
        registered = self._connections[identity]
        try:
            if self.generation.state == 'running':
                if registered.raw_setup is not None:
                    raw_value = None if info is None else info.get('raw_transport')
                    if raw_value is None:
                        failures.extend(await self.raw.abort(
                            identity,
                            registered.raw_setup,
                            'Raw transport closed without a terminal observation',
                        ))
                    else:
                        failures.extend(await self.raw.stop(
                            identity, registered.raw_setup, raw_value))
                else:
                    for flow in self.generation.connection_flows(identity):
                        flow.error = Error('Connection closed before HTTP exchange completed')
                        failures.extend(await self.generation.dispatch('error', flow))
                self._close_descriptors(registered)
                if self.generation.observes('client_disconnected'):
                    failures.extend(await self.generation.dispatch(
                        'client_disconnected', registered.client))
            else:
                self._close_descriptors(registered)
        except BaseException:
            self.generation.invalidate()
            raise
        finally:
            if registered.raw_setup is None:
                self.http1.release_connection(identity)
                self.http2.release_connection(identity)
            else:
                self.raw.release_connection(identity)
            del self._connections[identity]
        return tuple(failures)

    async def close(self):
        failures = []
        try:
            try:
                for identity in tuple(self._connections):
                    failures.extend(await self.stop(identity))
            except BaseException as stop_error:
                # A fatal error hook poisons the generation, but must not skip
                # its shutdown lifecycle or leave option subscriptions alive.
                # Preserve the original failure if shutdown also aborts.
                try:
                    await self.generation.close()
                except BaseException as shutdown_error:
                    raise stop_error from shutdown_error
                raise
            else:
                failures.extend(await self.generation.close())
        finally:
            # Teardown must release retained bodies even if a user hook aborts.
            for identity in tuple(self._connections):
                self.http1.release_connection(identity)
                self.http2.release_connection(identity)
                self.raw.release_connection(identity)
            self._connections.clear()
        return tuple(failures)
