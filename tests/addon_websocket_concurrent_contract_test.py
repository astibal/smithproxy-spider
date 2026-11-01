"""Guard shared addon state across concurrent WebSocket flows."""

import base64
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_websocket_concurrent_v12.json'


class WebSocketConcurrentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())
        cls.hooks = cls.corpus['hooks']

    def test_two_flows_are_live_before_messages_begin(self):
        starts = self.hooks[:2]
        self.assertEqual(
            [hook['hook'] for hook in starts],
            ['websocket_start', 'websocket_start'],
        )
        self.assertEqual([hook['active'] for hook in starts], [1, 2])
        messages = [
            hook for hook in self.hooks
            if hook['hook'] == 'websocket_message'
        ]
        self.assertTrue(all(hook['active'] == 2 for hook in messages))

    def test_module_state_is_shared_while_histories_remain_per_flow(self):
        messages = [
            hook for hook in self.hooks
            if hook['hook'] == 'websocket_message'
        ]
        self.assertEqual(
            [hook['ordinal'] for hook in messages],
            list(range(1, 9)),
        )
        self.assertEqual(
            [hook['message_count'] for hook in messages],
            [1, 2, 1, 2, 3, 4, 3, 4],
        )
        self.assertEqual(
            [hook['from_client'] for hook in messages],
            [True, False, True, False, True, False, True, False],
        )

    def test_shared_state_mutations_reach_each_peer_in_order(self):
        responses = [
            base64.b64decode(value)
            for value in self.corpus['client']['responses']
        ]
        self.assertEqual(responses, [
            b'2:origin:1:one-a',
            b'4:origin:3:two-a',
            b'6:origin:5:one-b',
            b'8:origin:7:two-b',
        ])
        self.assertEqual(
            [base64.b64decode(value) for value in self.corpus['origin']['one']],
            [b'1:one-a', b'5:one-b'],
        )
        self.assertEqual(
            [base64.b64decode(value) for value in self.corpus['origin']['two']],
            [b'3:two-a', b'7:two-b'],
        )


if __name__ == '__main__':
    unittest.main()
