"""Translate ordered native TCP observations into server lifecycle hooks.

TLS readiness is a separate layer. These observations never imply completion
of a TLS handshake and never create a server from a client setup notification.
"""

from dataclasses import replace
import time

from addon_connection import ConnectionState, Server
from addon_connect_native import address
from addon_runtime import AddonRuntimeError
from addon_server_hooks import ServerConnectionHookData


HOOKS = frozenset({
    'server_connect',
    'server_connected',
    'server_connect_error',
    'server_disconnected',
})


async def dispatch(adapter, observation):
    envelope = observation['envelope']
    identity = adapter._identity(envelope['connection_id'])
    attempt = envelope['attempt']
    event = envelope['event']
    if (
        type(envelope.get('version')) is not int
        or envelope['version'] != 1
        or type(attempt) is not int
        or attempt < 1
        or event not in ('connect', 'connected', 'error', 'disconnected')
    ):
        raise AddonRuntimeError('Invalid server lifecycle envelope')

    registered = adapter._connections.get(identity)
    if registered is None or registered.raw_setup is not None:
        raise AddonRuntimeError('Server observation requires an established addon setup')

    client_closed = observation.get('client_closed', False)
    if type(client_closed) is not bool:
        raise AddonRuntimeError('Client closure observation must be a boolean')
    session_ending = observation.get('session_ending', False)
    if type(session_ending) is not bool:
        raise AddonRuntimeError('Session retirement observation must be a boolean')
    if session_ending and event not in ('error', 'disconnected'):
        raise AddonRuntimeError('Session retirement requires a terminal event')

    # Retirement is a logical close: native teardown follows the hook and still
    # owns the sockets. Do not require native code to close them for observation.
    if client_closed or session_ending:
        registered.client.state = ConnectionState.CLOSED

    target = address(observation['target'])
    previous = adapter._servers.get(identity)
    terminal = ('error', 'disconnected')

    if event == 'connect':
        if previous is not None:
            old_attempt, old_event = previous
            if old_event not in terminal or attempt <= old_attempt:
                raise AddonRuntimeError('Server attempt overlaps an existing attempt')

            # A reconnect is a new Server, while the accepted Client survives.
            registered = replace(registered, server=Server(address=None))
            adapter._connections[identity] = registered

        server = registered.server
        server.address = target
        server.error = None
        server.timestamp_start = None
        server.timestamp_end = None
        server.state = ConnectionState.CLOSED

        client = registered.client
        client.peername = address(observation['client_peername'])
        client.sockname = address(observation.get('client_sockname'), nullable=True)
        hook = 'server_connect'
    else:
        if previous is None or previous[0] != attempt:
            raise AddonRuntimeError('Server outcome has no matching attempt')

        expected = 'connect' if event in ('connected', 'error') else 'connected'
        if previous[1] != expected:
            raise AddonRuntimeError('Server observation is out of order')

        server = registered.server
        if server.address != target:
            raise AddonRuntimeError('Server target changed during an attempt')

        if event == 'connected':
            server.peername = address(observation['peername'])
            server.sockname = address(observation['sockname'])
            server.state = ConnectionState.OPEN
            server.timestamp_tcp_setup = time.time()
            hook = 'server_connected'
        else:
            server.state = ConnectionState.CLOSED
            server.timestamp_end = time.time()
            if event == 'error':
                error = observation.get('error')
                if not isinstance(error, str) or not error or len(error) > 1024:
                    raise AddonRuntimeError('Connect failure requires a bounded error')
                server.error = server.error or error
                hook = 'server_connect_error'
            else:
                hook = 'server_disconnected'

    # Reserve the transition before dispatch. A failed generation cannot replay
    # an administrator callback against the same transport observation.
    adapter._servers[identity] = (attempt, event)
    data = ServerConnectionHookData(server=server, client=registered.client)
    failures = await adapter.generation.dispatch(hook, data)
    if failures:
        raise AddonRuntimeError('Server lifecycle callback failed')

    if server.address != target:
        # A requested reroute must never silently contact the original target.
        # Restore the descriptor and veto until native policy-aware routing is
        # available at this boundary.
        server.address = target
        server.error = 'Server target mutation requires native routing support'
        return {'proceed': False}

    if event == 'connect' and not server.error:
        server.timestamp_start = time.time()

    return {'proceed': not bool(server.error)}
