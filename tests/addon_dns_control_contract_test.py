"""Guard DNS flow-control behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_dns_control_v12.json'


class DNSControlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        corpus = json.loads(CORPUS.read_text())
        cls.cases = {
            case['case']: case
            for case in corpus['cases']
        }

    def test_request_kill_synthesizes_servfail_without_upstream_or_response_hook(self):
        case = self.cases['request-kill']
        self.assertEqual(case['client_outcome'], 'response')
        self.assertEqual(case['upstream_questions'], [])
        self.assertEqual(
            [event['hook'] for event in case['hooks']],
            ['dns_request'],
        )
        self.assertEqual(case['wire']['response_code'], 2)
        self.assertEqual(case['wire']['counts'], [1, 0, 0, 0])

    def test_request_local_response_survives_kill_and_runs_response_hook(self):
        case = self.cases['request-local-kill']
        self.assertEqual(case['upstream_questions'], [])
        self.assertEqual(
            [event['hook'] for event in case['hooks']],
            ['dns_request', 'dns_response'],
        )
        self.assertEqual(case['wire']['response_code'], 0)
        self.assertEqual(
            case['wire']['answer'],
            ['control.example.com', 1, 1, 30, '192.0.2.10'],
        )

    def test_response_hook_kill_does_not_discard_local_or_upstream_response(self):
        local = self.cases['local-response-kill']
        upstream = self.cases['upstream-response-kill']

        self.assertEqual(local['upstream_questions'], [])
        self.assertEqual(
            upstream['upstream_questions'],
            [
                ['control.example.com', 1, 1],
                ['control.example.com', 28, 1],
            ],
        )
        self.assertEqual(local['wire']['answer'][-1], '192.0.2.91')
        self.assertEqual(upstream['wire']['answer'][-1], '192.0.2.92')

    def test_every_kill_updates_flow_state_but_still_returns_a_wire_response(self):
        for name, case in self.cases.items():
            with self.subTest(case=name):
                self.assertEqual(case['client_outcome'], 'response')
                self.assertFalse(case['hooks'][-1]['after']['live'])
                self.assertEqual(
                    case['hooks'][-1]['after']['error'],
                    'Connection killed.',
                )
                self.assertFalse(case['wire']['query'])
                self.assertEqual(case['wire']['id'], 0x789A)
                self.assertEqual(
                    case['wire']['question'],
                    ['control.example.com', 1, 1],
                )


if __name__ == '__main__':
    unittest.main()
