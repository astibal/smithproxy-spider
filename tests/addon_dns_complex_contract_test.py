"""Guard complex DNS message behavior from mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_complex_v12.json'


class DNSComplexContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_compressed_input_exposes_complete_logical_sections(self):
        request = self.corpus['hooks'][0]
        self.assertEqual(request['hook'], 'dns_request')
        message = request['message']
        self.assertEqual(message['questions'], [
            ['alpha.example.com', 1, 1],
            ['beta.example.com', 28, 1],
        ])
        self.assertEqual(message['answers'], [
            ['alpha.example.com', 1, 1, 10, 'c000020a'],
        ])
        self.assertEqual(message['authorities'], [
            [
                'example.com',
                2,
                1,
                20,
                '026e73076578616d706c6503636f6d00',
            ],
        ])
        self.assertEqual(message['additionals'], [
            ['ns.example.com', 1, 1, 30, 'c0000214'],
        ])

    def test_all_header_fields_reach_the_request_hook(self):
        message = self.corpus['hooks'][0]['message']
        self.assertEqual(message['id'], 0x6789)
        self.assertTrue(message['query'])
        self.assertEqual(message['op_code'], 4)
        self.assertTrue(message['authoritative_answer'])
        self.assertTrue(message['truncation'])
        self.assertTrue(message['recursion_desired'])
        self.assertTrue(message['recursion_available'])
        self.assertEqual(message['reserved'], 7)
        self.assertEqual(message['response_code'], 7)

    def test_response_mutations_preserve_the_remaining_message(self):
        request = self.corpus['hooks'][0]['message']
        response_hook = self.corpus['hooks'][1]
        self.assertEqual(response_hook['hook'], 'dns_response')
        response = response_hook['message']
        for field in (
            'id',
            'op_code',
            'authoritative_answer',
            'truncation',
            'recursion_desired',
            'recursion_available',
            'reserved',
            'response_code',
            'questions',
            'authorities',
        ):
            self.assertEqual(response[field], request[field])
        self.assertFalse(response['query'])
        self.assertEqual(response['answers'][0][3], 99)
        self.assertEqual(response['additionals'][0][4], 'c0000263')

    def test_wire_output_is_complete_and_canonical(self):
        wire = self.corpus['wire']
        response = self.corpus['hooks'][1]['message']
        self.assertTrue(wire['fully_consumed'])
        self.assertEqual(wire['id'], response['id'])
        self.assertEqual(wire['flags'], 0xA7F7)
        for section in ('questions', 'answers', 'authorities', 'additionals'):
            self.assertEqual(wire[section], response[section])


if __name__ == '__main__':
    unittest.main()
