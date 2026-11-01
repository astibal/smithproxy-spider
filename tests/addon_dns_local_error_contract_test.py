"""Guard local DNS error responses from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_local_error_v12.json'


class DNSLocalErrorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_local_error_uses_request_then_response_hooks(self):
        request, response = self.corpus['hooks']
        self.assertEqual(request, {
            'hook': 'dns_request',
            'question': 'local-error.example.com',
            'response_present': False,
        })
        self.assertEqual(response, {
            'hook': 'dns_response',
            'same_flow': True,
            'before': 3,
            'after': 5,
        })

    def test_local_error_never_contacts_the_resolver(self):
        self.assertFalse(self.corpus['upstream_contact'])

    def test_response_hook_mutation_reaches_the_client(self):
        wire = self.corpus['wire']
        self.assertEqual(wire['id'], 0x5678)
        self.assertFalse(wire['query'])
        self.assertEqual(wire['response_code'], 5)
        self.assertEqual(wire['counts'], [1, 0, 0, 0])
        self.assertEqual(
            wire['question'],
            ['local-error.example.com', 1, 1],
        )


if __name__ == '__main__':
    unittest.main()
