"""Guard malformed DNS boundaries from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_malformed_v12.json'


class DNSMalformedContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_malformed_datagrams_receive_no_response(self):
        malformed = self.corpus['outcomes'][:-1]
        self.assertEqual(
            [item['case'] for item in malformed],
            [
                'empty',
                'one-byte',
                'short-header',
                'missing-question',
                'compression-pointer-loop',
                'trailing-bytes',
            ],
        )
        self.assertTrue(all(item['outcome'] == 'timeout' for item in malformed))

    def test_malformed_datagrams_never_reach_addon_hooks(self):
        self.assertEqual(
            self.corpus['hooks'],
            [
                {
                    'hook': 'dns_request',
                    'message_id': 0x1005,
                    'question': 'baseline.invalid',
                },
                {
                    'hook': 'dns_response',
                    'message_id': 0x1005,
                    'question': 'baseline.invalid',
                },
            ],
        )

    def test_clean_baseline_still_reaches_the_client(self):
        baseline = self.corpus['outcomes'][-1]
        self.assertEqual(baseline['case'], 'baseline')
        self.assertEqual(baseline['outcome'], 'response')
        response = baseline['response']
        self.assertEqual(response['id'], 0x1005)
        self.assertEqual(response['question'], ['baseline.invalid', 1, 1])
        self.assertEqual(
            response['answer'],
            ['baseline.invalid', 1, 1, 30, '192.0.2.77'],
        )


if __name__ == '__main__':
    unittest.main()
