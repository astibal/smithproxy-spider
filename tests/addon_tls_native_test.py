"""TLS outcomes preserve identity, ordering and explicit native limitations."""

import base64
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from addon_connection import Client, Server
from addon_native import NativeAddonAdapter
from addon_runtime import AddonGeneration, AddonRuntimeError


def observation(side='server', event='established', attempt=1):
    return {
        'envelope': {
            'version': 1,
            'connection_id': 'session',
            'side': side,
            'event': event,
            'attempt': attempt,
        },
        'sni': 'probe.invalid',
        'alpn_base64': base64.b64encode(b'http/1.1').decode(),
        'cipher': 'TLS_AES_256_GCM_SHA384',
        'tls_version': 'TLSv1.3',
        'error': 'TLS handshake failed' if event == 'failed' else '',
    }


class TlsTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, source):
        generation = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await generation.start()
        adapter = NativeAddonAdapter(generation)
        self.addAsyncCleanup(adapter.close)

        api = SimpleNamespace(
            phase='setup', session_id='session', info={},
            instance=SimpleNamespace(mode='flow'),
            connection=SimpleNamespace(request_rewrite=lambda: None, track_states=lambda: None),
        )
        client = Client(peername=('192.0.2.1', 40000), sockname=('192.0.2.2', 8080))
        pending = adapter.setup(api, client, Server(address=('probe.invalid', 443)))
        if pending is not None:
            await pending
        return generation, adapter

    async def test_established_metadata_and_shared_descriptors(self):
        generation, adapter = await self.start('''events = []
def tls_established_server(data):
    assert data.conn is data.context.server
    assert data.conn.tls and data.conn.tls_established
    assert data.conn.alpn == b'http/1.1'
    assert data.conn.sni == 'probe.invalid'
    assert data.conn.tls_version == 'TLSv1.3'
    events.append(data)
def tls_established_client(data):
    assert data.conn is data.context.client
    assert data.context.server is events[0].conn
    events.append(data)
''')
        await adapter.tls_lifecycle(observation())
        await adapter.tls_lifecycle(observation('client', attempt=2))

        events = generation.addon.module.events
        self.assertEqual(len(events), 2)
        self.assertIs(events[0].conn, adapter._connections['session'].server)
        self.assertIs(events[1].conn, adapter._connections['session'].client)
        await adapter.stop('session')
        self.assertFalse(adapter._tls)

    async def test_established_metadata_matches_pinned_reference(self):
        generation, adapter = await self.start('''events = []
def record(hook, data):
    conn = data.conn
    events.append({
        'hook': hook, 'connection': type(conn).__name__,
        'transport': conn.transport_protocol, 'sni': conn.sni,
        'tls': conn.tls, 'tls_established': conn.tls_established,
        'tls_version': conn.tls_version,
        'alpn': None if conn.alpn is None else conn.alpn.decode('latin-1'),
    })
def tls_established_server(data):
    record('tls_established_server', data)
def tls_established_client(data):
    record('tls_established_client', data)
''')
        await adapter.tls_lifecycle(observation())
        await adapter.tls_lifecycle(observation('client', attempt=2))

        corpus = Path(__file__).parent / 'corpus/addon_tls_transport_v12.json'
        expected = [entry for entry in json.loads(corpus.read_text())['hooks']
                    if entry['hook'].startswith('tls_established_')]
        self.assertEqual(generation.addon.module.events, expected)

    async def test_completed_handshake_without_alpn_has_empty_selection(self):
        _, adapter = await self.start('''def tls_established_server(data):
    assert data.conn.alpn == b''
''')
        event = observation()
        event['alpn_base64'] = ''
        await adapter.tls_lifecycle(event)

    async def test_live_ssl_replacement_is_rejected(self):
        _, adapter = await self.start('''def tls_established_server(data):
    data.ssl_conn = None
''')
        with self.assertRaises(AddonRuntimeError):
            await adapter.tls_lifecycle(observation())

    async def test_failed_is_not_established(self):
        generation, adapter = await self.start('''events = []
def tls_failed_client(data):
    assert data.conn.tls and not data.conn.tls_established
    assert data.conn.error == 'TLS handshake failed'
    events.append(data)
''')
        result = await adapter.tls_lifecycle(observation('client', 'failed'))
        self.assertTrue(result['proceed'])
        self.assertEqual(len(generation.addon.module.events), 1)

    async def test_duplicate_and_failed_after_success_are_rejected(self):
        for event in ('established', 'failed'):
            with self.subTest(event=event):
                _, adapter = await self.start('def tls_established_server(data): pass')
                await adapter.tls_lifecycle(observation())
                with self.assertRaises(AddonRuntimeError):
                    await adapter.tls_lifecycle(observation(event=event))

    async def test_later_tls_instance_on_same_descriptor(self):
        generation, adapter = await self.start('''events = []
def tls_established_server(data):
    events.append(data.conn)
''')
        await adapter.tls_lifecycle(observation())
        await adapter.tls_lifecycle(observation(attempt=3))
        first, second = generation.addon.module.events
        self.assertIs(first, second)

    async def test_explicit_error_veto(self):
        _, adapter = await self.start('''def tls_established_server(data):
    data.conn.error = 'rejected by addon'
''')
        result = await adapter.tls_lifecycle(observation())
        self.assertFalse(result['proceed'])

    async def test_live_openssl_access_is_not_silently_emulated(self):
        _, adapter = await self.start('''def tls_established_server(data):
    data.ssl_conn.get_peer_certificate()
''')
        with self.assertRaises(AddonRuntimeError):
            await adapter.tls_lifecycle(observation())
        self.assertEqual(adapter.generation.state, 'failed')

    async def test_malformed_metadata_before_dispatch(self):
        for name, value in (('alpn_base64', '%%%'), ('sni', 3), ('tls_version', 'x' * 33)):
            with self.subTest(field=name):
                generation, adapter = await self.start('''events = []
def tls_established_server(data):
    events.append(data)
''')
                event = observation()
                event[name] = value
                with self.assertRaises(Exception):
                    await adapter.tls_lifecycle(event)
                self.assertEqual(generation.addon.module.events, [])


if __name__ == '__main__':
    unittest.main()
