"""Guard raw and TLS transport behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus'


def load(name):
    return json.loads((CORPUS / name).read_text())


class TransportReferenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tcp = load('addon_tcp_v12.json')
        cls.udp = load('addon_udp_v12.json')
        cls.tls = load('addon_tls_transport_v12.json')

    def test_tcp_and_udp_share_directional_message_lifecycle(self):
        for transport, corpus in (('tcp', self.tcp), ('udp', self.udp)):
            hooks = corpus['hooks']
            with self.subTest(transport=transport):
                self.assertEqual(
                    [hook['hook'] for hook in hooks],
                    [
                        transport + '_start',
                        transport + '_message',
                        transport + '_message',
                        transport + '_end',
                    ],
                )
                self.assertEqual(
                    [hook['message_count'] for hook in hooks],
                    [0, 1, 2, 2],
                )
                self.assertEqual(
                    [hook['from_client'] for hook in hooks[1:3]],
                    [True, False],
                )
                self.assertEqual(corpus['origin']['received'], 'HELLO')
                self.assertEqual(
                    corpus['client_received'],
                    'client:echo:HELLO',
                )

    def test_raw_message_mutations_reach_each_opposite_endpoint(self):
        for corpus in (self.tcp, self.udp):
            request, response = corpus['hooks'][1:3]
            self.assertEqual((request['before'], request['after']), (
                'hello',
                'HELLO',
            ))
            self.assertEqual((response['before'], response['after']), (
                'echo:HELLO',
                'client:echo:HELLO',
            ))

    def test_tls_hooks_follow_clienthello_and_both_handshakes(self):
        hooks = self.tls['hooks']
        self.assertEqual(
            [hook['hook'] for hook in hooks],
            [
                'tls_clienthello',
                'tls_start_server',
                'tls_established_server',
                'tls_start_client',
                'tls_established_client',
            ],
        )
        hello = hooks[0]
        self.assertEqual(hello['sni'], 'probe.invalid')
        self.assertEqual(hello['alpn_offers'], ['http/1.1'])
        self.assertFalse(hello['ignore_connection'])

        for hook in (hooks[2], hooks[4]):
            self.assertTrue(hook['tls_established'])
            self.assertEqual(hook['tls_version'], 'TLSv1.3')
            self.assertEqual(hook['alpn'], 'http/1.1')

        self.assertEqual(
            self.tls['origin']['request_line'],
            'GET /tls HTTP/1.1',
        )
        self.assertEqual(self.tls['client']['body'], 'ok')


if __name__ == '__main__':
    unittest.main()
