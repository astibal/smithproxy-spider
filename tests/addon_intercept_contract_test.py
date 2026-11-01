"""Guard delayed intercept/resume behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_intercept_v12.json'


class InterceptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_hook_order_and_flow_identity_survive_delayed_resume(self):
        hooks = self.corpus['hooks']
        self.assertEqual(
            [hook['hook'] for hook in hooks],
            [
                'requestheaders',
                'request',
                'after-intercept',
                'before-resume',
                'after-resume',
                'responseheaders',
                'response',
            ],
        )
        self.assertTrue(all(hook['same_flow'] for hook in hooks))
        self.assertTrue(all(hook['live'] for hook in hooks))
        self.assertTrue(all(hook['error'] is None for hook in hooks))
        self.assertTrue(all(
            hook['path'] == '/intercept'
            for hook in hooks
        ))

    def test_intercepted_state_changes_only_at_intercept_and_resume(self):
        self.assertEqual(
            [hook['intercepted'] for hook in self.corpus['hooks']],
            [False, False, True, True, False, False, False],
        )

    def test_origin_receives_nothing_until_background_resume(self):
        origin = self.corpus['origin']
        self.assertTrue(origin['request_seen'])
        self.assertTrue(origin['request_after_resume'])
        self.assertEqual(origin['request_line'], 'GET /intercept HTTP/1.1')

    def test_resumed_exchange_completes_normally(self):
        self.assertEqual(
            self.corpus['client'],
            {
                'status_line': 'HTTP/1.1 200 OK',
                'body': 'resumed',
            },
        )


if __name__ == '__main__':
    unittest.main()
