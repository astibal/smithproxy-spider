"""Ordered native server observations, descriptor reuse and reference parity."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from addon_connection import Client, ConnectionState, Server
from addon_native import NativeAddonAdapter
from addon_runtime import AddonGeneration, AddonRuntimeError


def observation(event, attempt=1):
    return {
        'envelope': {
            'version': 1,
            'connection_id': 'session',
            'attempt': attempt,
            'event': event,
        },
        'target': ['example.test', 443],
        'client_peername': ['192.0.2.1', 40000],
        'client_sockname': ['192.0.2.2', 8080],
        'peername': ['192.0.2.3', 443],
        'sockname': ['192.0.2.2', 40001],
        'client_closed': event == 'disconnected',
        'error': 'Connection refused' if event == 'error' else '',
    }


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, source):
        generation = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await generation.start()
        adapter = NativeAddonAdapter(generation)
        self.addAsyncCleanup(adapter.close)

        api = SimpleNamespace(
            phase='setup',
            session_id='session',
            info={},
            instance=SimpleNamespace(mode='flow'),
            connection=SimpleNamespace(
                request_rewrite=lambda: None,
                track_states=lambda: None,
            ),
        )
        client = Client(peername=('192.0.2.1', 40000), sockname=('192.0.2.2', 8080))
        pending = adapter.setup(api, client, Server(address=None))
        if pending is not None:
            await pending
        return generation, adapter

    async def test_reference_lifecycle(self):
        probe = Path(__file__).parent / 'probes/addon_connection_lifecycle_probe.py'
        source = probe.read_text().split('class _Origin')[0]
        source += '''
events = []
def _record(hook, *values):
    events.append({'hook': hook, 'connections': [_connection(v) for v in values]})
'''
        generation, adapter = await self.start(source)

        for event in ('connect', 'connected', 'disconnected'):
            self.assertTrue((await adapter.server_lifecycle(observation(event)))['proceed'])
        await adapter.stop('session')

        expected = json.loads((Path(__file__).parent / 'corpus/addon_connection_lifecycle_v12.json').read_text())
        self.assertEqual(generation.addon.module.events, expected['events'])

    async def test_session_retirement_without_early_socket_shutdown(self):
        generation, adapter = await self.start('''events = []
def server_disconnected(data):
    events.append((data.client.connected, data.server.connected))
''')
        await adapter.server_lifecycle(observation('connect'))
        await adapter.server_lifecycle(observation('connected'))

        terminal = observation('disconnected')
        terminal['client_closed'] = False
        terminal['session_ending'] = True
        await adapter.server_lifecycle(terminal)

        self.assertEqual(generation.addon.module.events, [(False, False)])

    async def test_invalid_session_retirement_fails(self):
        for value in (True, 'true'):
            with self.subTest(value=value):
                _, adapter = await self.start('def server_connect(data): pass')
                event = observation('connect')
                event['session_ending'] = value

                with self.assertRaises(AddonRuntimeError):
                    await adapter.server_lifecycle(event)

    async def test_error_and_reconnect_use_new_server(self):
        generation, adapter = await self.start('''events = []
def server_connect(data):
    events.append(('connect', data.server, data.client))
def server_connect_error(data):
    assert data.server.error == 'Connection refused'
    events.append(('error', data.server, data.client))
def server_connected(data):
    events.append(('connected', data.server, data.client))
def server_disconnected(data):
    events.append(('disconnected', data.server, data.client))
''')
        for event in ('connect', 'error'):
            await adapter.server_lifecycle(observation(event))
        for event in ('connect', 'connected', 'disconnected'):
            await adapter.server_lifecycle(observation(event, 2))

        events = generation.addon.module.events
        self.assertEqual([entry[0] for entry in events], ['connect', 'error', 'connect', 'connected', 'disconnected'])
        self.assertIs(events[0][1], events[1][1])
        self.assertIsNot(events[1][1], events[2][1])
        self.assertIs(events[2][1], events[4][1])
        self.assertTrue(all(entry[2] is events[0][2] for entry in events))

    async def test_veto(self):
        _, adapter = await self.start('''def server_connect(data):
    data.server.error = 'denied'
''')
        self.assertFalse((await adapter.server_lifecycle(observation('connect')))['proceed'])

    async def test_unsupported_reroute_vetoes_original_target(self):
        _, adapter = await self.start("""def server_connect(data):
    data.server.address = ('other.test', 443)
""")
        decision = await adapter.server_lifecycle(observation('connect'))
        self.assertFalse(decision['proceed'])
        self.assertEqual(adapter._connections['session'].server.address, ('example.test', 443))

    async def test_duplicate_and_unknown_outcomes_fail(self):
        for events in (('connected',), ('connect', 'connect'), ('connect', 'connected', 'connected')):
            with self.subTest(events=events):
                _, adapter = await self.start('def server_connect(data): pass')
                with self.assertRaises(AddonRuntimeError):
                    for event in events:
                        await adapter.server_lifecycle(observation(event))
                self.assertEqual(adapter.generation.state, 'failed')
                await adapter.stop('session')
                self.assertFalse(adapter._servers)


if __name__ == '__main__':
    unittest.main()
