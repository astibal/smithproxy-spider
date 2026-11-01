"""Guard forwarded UDP DNS behavior from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_forward_v12.json'


class DNSForwardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_request_and_response_share_one_flow(self):
        hooks = self.corpus['hooks']
        self.assertEqual(
            [hook['hook'] for hook in hooks],
            ['dns_request', 'dns_response'],
        )
        self.assertTrue(all(hook['same_flow'] for hook in hooks))
        self.assertFalse(hooks[0]['response_present'])

    def test_request_mutation_drives_real_upstream_lookups(self):
        request = self.corpus['hooks'][0]
        self.assertEqual(request['before'], 'probe.example.com')
        self.assertEqual(request['after'], 'mutated.example.com')

        upstream = self.corpus['upstream']
        self.assertTrue(upstream['query_ids_distinct'])
        self.assertTrue(upstream['query_ids_differ_from_client'])
        self.assertEqual(
            [query['question'] for query in upstream['queries']],
            [
                ['mutated.example.com', 1, 1],
                ['mutated.example.com', 28, 1],
            ],
        )
        self.assertTrue(all(
            query['counts'] == [1, 0, 0, 1]
            for query in upstream['queries']))

    def test_response_mutation_reaches_the_client(self):
        response = self.corpus['hooks'][1]
        self.assertEqual(response['question'], 'mutated.example.com')
        self.assertEqual(response['before'], [60, '192.0.2.10'])
        self.assertEqual(response['after'], [90, '192.0.2.99'])

        client = self.corpus['client']
        self.assertEqual(client['id'], 0x2345)
        self.assertEqual(client['question'], ['mutated.example.com', 1, 1])
        self.assertEqual(
            client['answer'],
            ['mutated.example.com', 1, 1, 90, '192.0.2.99'],
        )

    def test_reference_resolver_preserves_dns_response_shape(self):
        client = self.corpus['client']
        self.assertFalse(client['query'])
        self.assertEqual(client['response_code'], 0)
        self.assertTrue(client['recursion_available'])
        self.assertEqual(client['counts'], [1, 1, 0, 0])


if __name__ == '__main__':
    unittest.main()
