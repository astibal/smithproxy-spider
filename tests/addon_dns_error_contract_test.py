"""Guard unreachable-resolver DNS behavior from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_error_v12.json'


class DNSErrorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_unreachable_resolver_uses_response_not_error_hook(self):
        hooks = self.corpus['hooks']
        self.assertEqual(
            [hook['hook'] for hook in hooks],
            ['dns_request', 'dns_response'],
        )
        self.assertTrue(all(hook['live'] for hook in hooks))
        self.assertTrue(all(hook['error'] is None for hook in hooks))
        self.assertEqual(hooks[1]['response_code'], 2)
        self.assertTrue(hooks[1]['response_present'])

    def test_synthesized_servfail_reaches_the_client(self):
        self.assertEqual(self.corpus['client_outcome'], 'response')
        wire = self.corpus['wire']
        self.assertEqual(wire['id'], 0x3456)
        self.assertFalse(wire['query'])
        self.assertEqual(wire['response_code'], 2)
        self.assertEqual(wire['counts'], [1, 0, 0, 0])
        self.assertEqual(
            wire['question'],
            ['resolver-failure.example.com', 1, 1],
        )

    def test_request_hook_precedes_resolver_policy(self):
        request = self.corpus['hooks'][0]
        self.assertEqual(request['question'], 'resolver-failure.example.com')
        self.assertFalse(request['response_present'])
        self.assertIsNone(request['response_code'])


if __name__ == '__main__':
    unittest.main()
