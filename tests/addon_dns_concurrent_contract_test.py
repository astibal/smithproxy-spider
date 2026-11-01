"""Guard concurrent same-ID DNS behavior from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_concurrent_v12.json'


class DNSConcurrentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_equal_wire_ids_do_not_merge_flows(self):
        requests = [
            hook for hook in self.corpus['hooks']
            if hook['hook'] == 'dns_request'
        ]
        self.assertEqual([hook['message_id'] for hook in requests], [0xCAFE, 0xCAFE])
        self.assertEqual([hook['flow'] for hook in requests], [1, 2])
        self.assertEqual(
            [hook['question'] for hook in requests],
            ['first.example.com', 'second.example.com'],
        )

    def test_each_response_returns_to_its_request_flow(self):
        hooks_by_question = {}
        for hook in self.corpus['hooks']:
            hooks_by_question.setdefault(hook['question'], []).append(hook)

        for question, hooks in hooks_by_question.items():
            self.assertEqual(
                [hook['hook'] for hook in hooks],
                ['dns_request', 'dns_response'],
            )
            self.assertEqual(hooks[0]['flow'], hooks[1]['flow'])
            self.assertEqual(hooks[0]['message_id'], hooks[1]['message_id'])
            self.assertEqual(hooks[0]['message_id'], 0xCAFE)
            expected_last_octet = 101 if question.startswith('first') else 102
            self.assertEqual(
                hooks[1]['answer'],
                '192.0.2.' + str(expected_last_octet),
            )

    def test_both_lookups_reach_the_resolver_independently(self):
        questions = [
            query['question']
            for query in self.corpus['upstream']['queries']
        ]
        self.assertEqual(questions, [
            ['first.example.com', 1, 1],
            ['first.example.com', 28, 1],
            ['second.example.com', 1, 1],
            ['second.example.com', 28, 1],
        ])

    def test_client_responses_keep_identity_and_mutation(self):
        first, second = self.corpus['responses']
        self.assertEqual(first['id'], 0xCAFE)
        self.assertEqual(second['id'], 0xCAFE)
        self.assertEqual(
            first['answer'],
            ['first.example.com', 1, 1, 60, '192.0.2.101'],
        )
        self.assertEqual(
            second['answer'],
            ['second.example.com', 1, 1, 60, '192.0.2.102'],
        )


if __name__ == '__main__':
    unittest.main()
