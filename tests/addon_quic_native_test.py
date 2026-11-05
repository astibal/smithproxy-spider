"""QUIC parent registration, mutable offers and explicit native limitations."""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from addon_tls_native_test import observation
from addon_connection import Client, Server
from addon_native import NativeAddonAdapter
from addon_runtime import AddonGeneration, AddonRuntimeError


class QuicTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, source):
        generation = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await generation.start()
        adapter = NativeAddonAdapter(generation)
        self.addAsyncCleanup(adapter.close)

        api = SimpleNamespace(
            phase='setup', session_id='session',
            info={'scope': 'transport', 'protocol': 'quic'},
            instance=SimpleNamespace(mode='flow'),
        )
        client = Client(peername=('192.0.2.1', 40000), sockname=('192.0.2.2', 443))
        server = Server(address=('example.test', 443))
        pending = adapter.setup(api, client, server)
        if pending is not None:
            await pending
        return generation, adapter

    def start_event(self):
        value = observation(event='start')
        value['protocol'] = 'quic'
        value['upstream'] = {'sni': 'example.test', 'alpn': 'h3', 'ciphers': None}
        return value

    async def test_start_and_outcome_identity(self):
        _, adapter = await self.start('''
seen = []
def quic_start_server(data):
    assert data.conn.transport_protocol == 'udp'
    data.settings.cipher_suites = [0x1301]
    data.conn.sni = 'other.test'
    seen.append(data.conn)
def tls_established_server(data):
    assert data.conn is seen[0]
''')

        reply = await adapter.quic_lifecycle(self.start_event())
        self.assertEqual(reply['upstream']['ciphers'], 'TLS_AES_128_GCM_SHA256')
        self.assertEqual(reply['upstream']['sni'], 'other.test')

        value = observation()
        value.update(protocol='quic', alpn='h3')
        self.assertTrue((await adapter.quic_lifecycle(value))['proceed'])
        await adapter.stop('session')
        self.assertFalse(adapter._tls_starts)

    async def test_reject_unsupported_mutations(self):
        for statement in (
            'data.settings.verify_mode = 0',
            "data.settings.ca_file = '/tmp/other.pem'",
            'data.ssl_conn = object()',
            'data.context.client.tls = True',
            "data.conn.alpn_offers = [b'other']",
            "data.settings.alpn_protocols = ['h3', 'other']",
            'data.settings.cipher_suites = [12345]',
        ):
            with self.subTest(statement=statement):
                _, adapter = await self.start('def quic_start_server(data):\n    ' + statement)
                with self.assertRaises(AddonRuntimeError):
                    await adapter.quic_lifecycle(self.start_event())

    async def test_later_addon_preserves_earlier_cipher_choice(self):
        _, adapter = await self.start('def quic_start_server(data):\n    pass')
        event = self.start_event()
        event['upstream']['ciphers'] = 'TLS_AES_128_GCM_SHA256'

        reply = await adapter.quic_lifecycle(event)

        self.assertEqual(reply['upstream']['ciphers'], 'TLS_AES_128_GCM_SHA256')

    async def test_veto(self):
        _, adapter = await self.start("def quic_start_server(data):\n    data.conn.error = 'denied'")
        reply = await adapter.quic_lifecycle(self.start_event())
        self.assertFalse(reply['proceed'])

    async def test_duplicate_start_rejected(self):
        _, adapter = await self.start('def quic_start_server(data):\n    pass')
        await adapter.quic_lifecycle(self.start_event())
        with self.assertRaises(AddonRuntimeError):
            await adapter.quic_lifecycle(self.start_event())

    async def test_empty_cipher_offer_is_not_replaced_by_defaults(self):
        _, adapter = await self.start('def quic_start_server(data):\n    data.settings.cipher_suites = []')
        reply = await adapter.quic_lifecycle(self.start_event())
        self.assertEqual(reply['upstream']['ciphers'], '')


if __name__ == '__main__':
    unittest.main()
