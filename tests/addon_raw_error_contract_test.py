"""Guard raw socket-failure observations from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_raw_error_v12.json'


class RawErrorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_tcp_connect_refusal_creates_no_raw_flow(self):
        observation = self.corpus['tcp_connect_refused']
        self.assertEqual(observation['client_outcome'], 'eof')
        self.assertEqual(observation['client_received'], '')
        self.assertEqual(observation['hooks'], [])

    def test_established_tcp_reset_is_a_clean_end(self):
        observation = self.corpus['tcp_reset']
        self.assertEqual(
            [hook['hook'] for hook in observation['hooks']],
            ['tcp_start', 'tcp_message', 'tcp_end'],
        )
        self.assertEqual(
            [(hook['live'], hook['error']) for hook in observation['hooks']],
            [(True, None), (True, None), (True, None)],
        )
        self.assertEqual(observation['hooks'][1]['before'], 'hello')

    def test_udp_unreachable_is_not_an_addon_error(self):
        observation = self.corpus['udp_unreachable']
        self.assertEqual(observation['client_outcome'], 'timeout')
        self.assertEqual(
            [hook['hook'] for hook in observation['hooks']],
            ['udp_start', 'udp_message', 'udp_message', 'udp_end'],
        )
        self.assertEqual(
            [hook['before'] for hook in observation['hooks'][1:3]],
            ['hello', 'again'],
        )
        self.assertTrue(all(
            hook['live'] and hook['error'] is None
            for hook in observation['hooks']
        ))


if __name__ == '__main__':
    unittest.main()
