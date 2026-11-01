"""Guard black-box TCP/UDP control observations from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_raw_control_v12.json'


class RawControlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_corpus_covers_each_control_scenario_for_tcp_and_udp(self):
        expected = {
            'kill-start',
            'kill-client-message',
            'kill-server-message',
            'empty-client-message',
            'empty-server-message',
            'set-live-false',
            'set-custom-error',
            'tag-messages',
        }
        self.assertEqual(set(self.corpus['tcp']), expected)
        self.assertEqual(set(self.corpus['udp']), expected)

    def test_raw_kill_is_state_only_and_does_not_stop_transport(self):
        for protocol in ('tcp', 'udp'):
            for scenario in (
                    'kill-start', 'kill-client-message', 'kill-server-message'):
                with self.subTest(protocol=protocol, scenario=scenario):
                    observation = self.corpus[protocol][scenario]
                    hooks = observation['hooks']
                    self.assertTrue(any(
                        hook['hook'] == protocol + '_message'
                        and not hook['live']
                        and hook['error'] == 'Connection killed.'
                        for hook in hooks
                    ))
                    self.assertEqual(hooks[-1]['hook'], protocol + '_end')
                    self.assertFalse(hooks[-1]['live'])
                    self.assertEqual(
                        hooks[-1]['error'], 'Connection killed.')
                    self.assertTrue(observation['origin']['received'])
                    if protocol == 'tcp':
                        self.assertEqual(
                            observation['client_received'], 'one:hello')
                    else:
                        self.assertEqual(
                            observation['client_received'], ['1:hello'])

    def test_direct_live_and_error_edits_are_state_only(self):
        expected = {
            'set-live-false': (False, None),
            'set-custom-error': (True, 'custom transport error'),
        }
        for protocol in ('tcp', 'udp'):
            for scenario, (live, error) in expected.items():
                with self.subTest(protocol=protocol, scenario=scenario):
                    observation = self.corpus[protocol][scenario]
                    messages = [
                        hook for hook in observation['hooks']
                        if hook['hook'] == protocol + '_message'
                    ]
                    self.assertEqual(len(messages), 2)
                    self.assertEqual(
                        [(hook['live'], hook['error']) for hook in messages],
                        [(live, error), (live, error)],
                    )
                    end = observation['hooks'][-1]
                    self.assertEqual(end['hook'], protocol + '_end')
                    self.assertEqual((end['live'], end['error']), (live, error))
                    self.assertEqual(observation['origin']['received'], ['hello'])

    def test_empty_payload_semantics_distinguish_streams_and_datagrams(self):
        tcp_client = self.corpus['tcp']['empty-client-message']
        self.assertEqual(tcp_client['origin']['received'], [])
        self.assertEqual(tcp_client['client_outcome'], 'timeout')

        tcp_server = self.corpus['tcp']['empty-server-message']
        self.assertEqual(tcp_server['origin']['received'], ['hello'])
        self.assertEqual(tcp_server['client_received'], '')

        udp_client = self.corpus['udp']['empty-client-message']
        self.assertEqual(udp_client['origin']['received'], [''])
        self.assertEqual(udp_client['client_received'], ['1:'])

        udp_server = self.corpus['udp']['empty-server-message']
        self.assertEqual(udp_server['origin']['received'], ['hello'])
        self.assertEqual(udp_server['client_received'], [''])

    def test_message_history_and_udp_boundaries_remain_ordered(self):
        for protocol in ('tcp', 'udp'):
            hooks = self.corpus[protocol]['tag-messages']['hooks']
            messages = [
                hook for hook in hooks
                if hook['hook'] == protocol + '_message'
            ]
            self.assertEqual(
                [message['message_count'] for message in messages],
                [1, 2, 3, 4],
            )
            self.assertEqual(
                [message['from_client'] for message in messages],
                [True, False, True, False],
            )

        udp = self.corpus['udp']['tag-messages']
        self.assertEqual(udp['origin']['received'], ['C:hello', 'C:world'])
        self.assertEqual(
            udp['client_received'],
            ['S:1:C:hello', 'S:2:C:world'],
        )


if __name__ == '__main__':
    unittest.main()
