"""TLS outcomes preserve identity, ordering and explicit native limitations."""

import base64
import json
import ssl
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


def client_hello():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.set_alpn_protocols(['http/1.1'])
    outgoing = ssl.MemoryBIO()
    client = context.wrap_bio(ssl.MemoryBIO(), outgoing, server_hostname='probe.invalid')
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass

    message = observation('client', 'client-hello')
    message['client_hello_base64'] = base64.b64encode(outgoing.read()[9:]).decode()
    return message


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

    async def test_start_server_changes_offer_and_preserves_identity(self):
        generation, adapter = await self.start("""
seen = []
def tls_start_server(data):
    assert data.conn is data.context.server
    assert data.conn.tls and data.conn.timestamp_tls_setup is None
    assert not data.conn.connected
    assert data.conn.timestamp_tcp_setup is None
    data.conn.sni = 'other.test'
    data.conn.alpn_offers = [b'http/1.1']
    data.conn.cipher_list = ['ALL', '!aNULL']
    seen.append(data.conn)
def tls_established_server(data):
    assert data.conn is seen[0]
""")
        message = observation('server', 'start')
        message['upstream'] = {
            'sni': 'probe.invalid',
            'alpn_base64': base64.b64encode(b'\x02h2\x08http/1.1').decode(),
            'openssl_cipher_list': 'DEFAULT',
        }

        decision = await adapter.tls_lifecycle(message)

        self.assertTrue(decision['proceed'])
        self.assertEqual(decision['upstream']['sni'], 'other.test')
        self.assertEqual(decision['upstream']['openssl_cipher_list'], 'ALL:!aNULL')
        await adapter.tls_lifecycle(observation())
        await adapter.stop('session')
        self.assertFalse(adapter._tls_starts)

    async def test_start_server_rejects_ssl_operations_and_replacement(self):
        for statement in (
            'data.ssl_conn.get_cipher_name()',
            'data.ssl_conn = None',
            'data.conn = None',
        ):
            with self.subTest(statement=statement):
                _, adapter = await self.start('def tls_start_server(data):\n    ' + statement)
                message = observation('server', 'start')
                message['upstream'] = {
                    'sni': '', 'alpn_base64': '', 'openssl_cipher_list': 'DEFAULT',
                }
                with self.assertRaises(AddonRuntimeError):
                    await adapter.tls_lifecycle(message)

    async def test_start_server_veto_and_duplicate(self):
        _, adapter = await self.start("def tls_start_server(data): data.conn.error = 'denied'")
        message = observation('server', 'start')
        message['upstream'] = {
            'sni': '', 'alpn_base64': '', 'openssl_cipher_list': 'DEFAULT',
        }

        self.assertEqual(await adapter.tls_lifecycle(message), {'proceed': False})
        with self.assertRaisesRegex(AddonRuntimeError, 'Duplicate'):
            await adapter.tls_lifecycle(message)

    async def test_clienthello_dynamic_registration_and_shared_context(self):
        generation, adapter = await self.start('''from mitmproxy import ctx
seen = []
class Dynamic:
    def tls_clienthello(self, data):
        assert data.client_hello.sni == 'probe.invalid'
        assert data.client_hello.alpn_protocols == [b'http/1.1']
        assert data.context.client.sni == 'probe.invalid'
        assert tuple(data.context.client.alpn_offers) == (b'http/1.1',)
        seen.append(data)
def client_connected(client):
    ctx.master.addons.add(Dynamic())
''')
        decision = await adapter.tls_lifecycle(client_hello())

        self.assertEqual(decision, {'proceed': True, 'ignore_connection': False})
        self.assertIs(generation.addon.module.seen[0].context.client,
                      adapter._connections['session'].client)
        await adapter.stop('session')
        self.assertFalse(adapter._tls_hellos)

    async def test_clienthello_bypass_and_termination(self):
        for statement, expected in (
            ('data.ignore_connection = True', {'proceed': True, 'ignore_connection': True}),
            ("data.context.client.error = 'denied'", {'proceed': False, 'ignore_connection': False}),
        ):
            with self.subTest(statement=statement):
                _, adapter = await self.start('def tls_clienthello(data):\n    ' + statement)
                self.assertEqual(await adapter.tls_lifecycle(client_hello()), expected)

    async def test_clienthello_rejects_unsupported_changes(self):
        for statement in (
            'data.establish_server_tls_first = True',
            'data.ignore_connection = 1',
            'data.client_hello = None',
            "data.context.server.address = ('other.invalid', 443)",
        ):
            with self.subTest(statement=statement):
                generation, adapter = await self.start('def tls_clienthello(data):\n    ' + statement)
                with self.assertRaises(AddonRuntimeError):
                    await adapter.tls_lifecycle(client_hello())
                self.assertNotEqual(generation.state, 'running')

    async def test_clienthello_rejects_tls_settings_on_both_sides(self):
        changes = {
            'tls': 'True',
            'sni': "'other.invalid'",
            'alpn': "b'h2'",
            'alpn_offers': "[b'h2']",
            'cipher': "'TEST-CIPHER'",
            'cipher_list': "['TEST-CIPHER']",
            'tls_version': "'TLSv1.2'",
        }
        for side in ('client', 'server'):
            for field, value in changes.items():
                with self.subTest(side=side, field=field):
                    source = f'def tls_clienthello(data):\n    data.context.{side}.{field} = {value}'
                    generation, adapter = await self.start(source)
                    connection = getattr(adapter._connections['session'], side)
                    previous = getattr(connection, field)
                    if side == 'client' and field == 'sni':
                        previous = 'probe.invalid'
                    elif side == 'client' and field == 'alpn_offers':
                        previous = (b'http/1.1',)

                    with self.assertRaisesRegex(AddonRuntimeError, side + r'\.' + field):
                        await adapter.tls_lifecycle(client_hello())

                    self.assertEqual(getattr(connection, field), previous)
                    self.assertNotEqual(generation.state, 'running')

    async def test_clienthello_restores_lists_and_both_sides_after_exception(self):
        _, adapter = await self.start('''def tls_clienthello(data):
    data.context.client.sni = 'changed.invalid'
    data.context.server.cipher_list.append('ADDED')
    raise RuntimeError('callback failure')
''')
        server = adapter._connections['session'].server
        server.cipher_list = ['ORIGINAL']

        with self.assertRaises(AddonRuntimeError):
            await adapter.tls_lifecycle(client_hello())

        self.assertEqual(adapter._connections['session'].client.sni, 'probe.invalid')
        self.assertEqual(tuple(server.cipher_list), ('ORIGINAL',))

    async def test_clienthello_raw_body_and_default_record(self):
        generation, adapter = await self.start('''records = []
def tls_clienthello(data):
    hello = data.client_hello
    records.extend([hello.raw_bytes(), hello.raw_bytes(True),
                    hello.raw_bytes(False), hello.raw_bytes(wrap_in_record=False)])
''')
        message = client_hello()
        body = base64.b64decode(message['client_hello_base64'])
        expected = b'\x16\x03\x03' + (len(body) + 4).to_bytes(2, 'big')
        expected += b'\x01' + len(body).to_bytes(3, 'big') + body

        await adapter.tls_lifecycle(message)

        self.assertEqual(generation.addon.module.records, [expected, expected, body, body])

    async def test_clienthello_upstream_sni_and_alpn(self):
        _, adapter = await self.start('''def tls_clienthello(data):
    assert data.context.server.sni == 'native.invalid'
    assert data.context.server.alpn_offers == (b'h2', b'http/1.1')
    data.context.server.sni = 'upstream.invalid'
    data.context.server.alpn_offers = [b'http/1.1']
''')
        message = client_hello()
        message['upstream'] = {
            'sni': 'native.invalid',
            'alpn_base64': base64.b64encode(bytes([2]) + b'h2' + bytes([8]) + b'http/1.1').decode(),
        }

        decision = await adapter.tls_lifecycle(message)

        self.assertEqual(decision['upstream'], {
            'sni': 'upstream.invalid',
            'alpn_base64': base64.b64encode(bytes([8]) + b'http/1.1').decode(),
        })
        self.assertEqual(adapter._connections['session'].client.sni, 'probe.invalid')

    async def test_clienthello_upstream_rejects_invalid_options(self):
        for change in (
            "sni = '127.0.0.1'",
            "sni = 'bad..name'",
            "sni = '-bad.invalid'",
            "sni = 123",
            "alpn_offers = [b'h2']",
            "alpn_offers = [b'']",
            "alpn_offers = ['http/1.1']",
            "alpn_offers = None",
            "cipher_list = ['OTHER']",
        ):
            with self.subTest(change=change):
                source = 'def tls_clienthello(data):\n    data.context.server.' + change
                _, adapter = await self.start(source)
                message = client_hello()
                message['upstream'] = {
                    'sni': 'native.invalid',
                    'alpn_base64': base64.b64encode(bytes([8]) + b'http/1.1').decode(),
                }

                with self.assertRaises(AddonRuntimeError):
                    await adapter.tls_lifecycle(message)

    async def test_clienthello_upstream_cannot_enable_blocked_alpn(self):
        source = "def tls_clienthello(data):\n    data.context.server.alpn_offers = [b'http/1.1']"
        _, adapter = await self.start(source)
        message = client_hello()
        message['upstream'] = {'sni': 'native.invalid', 'alpn_base64': ''}
        message['upstream_alpn_blocked'] = True

        with self.assertRaisesRegex(AddonRuntimeError, 'native offer'):
            await adapter.tls_lifecycle(message)

    async def test_clienthello_upstream_defaults_and_idna(self):
        for sni, expected in ((None, 'native.invalid'), ('', ''), ('täst.invalid', 'xn--tst-qla.invalid')):
            with self.subTest(sni=sni):
                source = (
                    f'def tls_clienthello(data):\n'
                    f'    data.context.server.sni = {sni!r}\n'
                    f'    data.context.server.alpn_offers = []'
                )
                _, adapter = await self.start(source)
                message = client_hello()
                message['upstream'] = {
                    'sni': 'native.invalid',
                    'alpn_base64': base64.b64encode(bytes([8]) + b'http/1.1').decode(),
                }

                decision = await adapter.tls_lifecycle(message)

                self.assertEqual(decision['upstream']['sni'], expected)
                self.assertEqual(decision['upstream']['alpn_base64'], message['upstream']['alpn_base64'])

    async def test_upstream_cipher_expression_and_defaults(self):
        cases = (
            (['ECDHE-RSA-AES128-GCM-SHA256', '@SECLEVEL=0'],
             'ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0'),
            (['ALL:!aNULL'], 'ALL:!aNULL'),
            (['UNKNOWN-CIPHER'], 'UNKNOWN-CIPHER'),
            (['TLS_AES_256_GCM_SHA384'], 'TLS_AES_256_GCM_SHA384'),
            ([''], ''),
            ([], None),
            (None, None),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                _, adapter = await self.start(
                    f'def tls_clienthello(data):\n'
                    f'    data.context.server.cipher_list = {value!r}'
                )
                message = client_hello()
                message['upstream'] = {
                    'sni': 'probe.invalid', 'alpn_base64': '',
                    'openssl_cipher_list': None,
                }

                decision = await adapter.tls_lifecycle(message)

                self.assertEqual(decision['upstream']['openssl_cipher_list'], expected)

    async def test_absent_upstream_settings_keep_legacy_contract(self):
        _, adapter = await self.start('def tls_clienthello(data): pass')
        message = client_hello()
        message['upstream'] = None

        decision = await adapter.tls_lifecycle(message)

        self.assertEqual(decision, {'proceed': True, 'ignore_connection': False})

    async def test_upstream_cipher_format_errors(self):
        for expression in ("'ALL'", '[3]', r"['ALL\0!aNULL']", "['A' * 65536]"):
            with self.subTest(expression=expression):
                _, adapter = await self.start(
                    f'def tls_clienthello(data):\n'
                    f'    data.context.server.cipher_list = {expression}'
                )
                message = client_hello()
                message['upstream'] = {
                    'sni': 'probe.invalid', 'alpn_base64': '',
                    'openssl_cipher_list': None,
                }

                with self.assertRaises(AddonRuntimeError):
                    await adapter.tls_lifecycle(message)

    async def test_upstream_cipher_settings_from_earlier_deployment(self):
        _, adapter = await self.start('''def tls_clienthello(data):
    assert data.context.server.cipher_list == ['ALL', '!aNULL']
    data.context.server.cipher_list.append('@SECLEVEL=0')
''')
        message = client_hello()
        message['upstream'] = {
            'sni': 'probe.invalid', 'alpn_base64': '',
            'openssl_cipher_list': 'ALL:!aNULL',
        }

        decision = await adapter.tls_lifecycle(message)

        self.assertEqual(decision['upstream']['openssl_cipher_list'], 'ALL:!aNULL:@SECLEVEL=0')

    async def test_clienthello_cannot_replay(self):
        _, adapter = await self.start('def tls_clienthello(data): pass')
        await adapter.tls_lifecycle(client_hello())
        with self.assertRaises(AddonRuntimeError):
            await adapter.tls_lifecycle(client_hello())

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

    async def test_failure_outcomes_match_pinned_reference(self):
        corpus = Path(__file__).parent / 'corpus/addon_tls_failures_v12.json'
        reference = json.loads(corpus.read_text())

        # Compare only outcome callbacks: start callbacks require live SSL
        # control and are deliberately outside this native adapter contract.
        source = '''events = []
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
def tls_failed_server(data):
    record('tls_failed_server', data)
def tls_failed_client(data):
    record('tls_failed_client', data)
'''

        for failed_side in ('server', 'client'):
            with self.subTest(failed_side=failed_side):
                generation, adapter = await self.start(source)

                # A failure on one leg does not invent a failure on the other.
                # Replay both genuine outcomes in upstream-then-client order.
                for attempt, side in enumerate(('server', 'client'), start=1):
                    failed = side == failed_side
                    event = observation(side, 'failed' if failed else 'established', attempt)
                    event.update({
                        'sni': 'localhost',
                        'alpn_base64': None if failed else '',
                        'tls_version': None if failed else 'TLSv1.3',
                        'cipher': None if failed else 'TLS_AES_256_GCM_SHA384',
                    })

                    self.assertEqual(await adapter.tls_lifecycle(event), {'proceed': True})

                expected = [
                    entry for entry in reference['cases'][failed_side]
                    if entry['hook'].startswith(('tls_established_', 'tls_failed_'))
                ]
                self.assertEqual(generation.addon.module.events, expected)

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
