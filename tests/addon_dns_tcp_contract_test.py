"""Guard DNS-over-TCP framing behavior from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_tcp_v12.json'


class DNSTCPContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_pipelined_messages_have_independent_flows(self):
        hooks = self.corpus['hooks']
        self.assertEqual(
            [(hook['hook'], hook['flow']) for hook in hooks],
            [
                ('dns_request', 1),
                ('dns_response', 1),
                ('dns_request', 2),
                ('dns_response', 2),
            ],
        )

    def test_pipelined_messages_share_the_client_connection(self):
        self.assertTrue(all(
            hook['same_client_connection']
            for hook in self.corpus['hooks']
        ))

    def test_both_framed_responses_reach_the_client(self):
        first, second = self.corpus['responses']
        self.assertEqual(first['id'], 0x4567)
        self.assertEqual(first['question'], ['first.invalid', 1, 1])
        self.assertEqual(
            first['answer'],
            ['first.invalid', 1, 1, 30, '192.0.2.91'],
        )
        self.assertEqual(second['id'], 0x89AB)
        self.assertEqual(second['question'], ['second.invalid', 1, 1])
        self.assertEqual(
            second['answer'],
            ['second.invalid', 1, 1, 30, '192.0.2.92'],
        )
        for response in (first, second):
            self.assertFalse(response['query'])
            self.assertEqual(response['response_code'], 0)
            self.assertEqual(response['counts'], [1, 1, 0, 0])


if __name__ == '__main__':
    unittest.main()
