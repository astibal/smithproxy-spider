"""Guard wire-level WebSocket decisions from mitmproxy 12.3.1."""

import base64
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_websocket_control_v12.json'


def decoded(item):
    opcode, content = item
    return opcode, base64.b64decode(content)


class WebSocketControlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())

    def test_fragmented_messages_are_one_logical_callback(self):
        hooks = [
            item for item in self.corpus['hooks']
            if item['hook'] == 'websocket_message'
        ]
        self.assertEqual(base64.b64decode(hooks[0]['before']), b'fragment')
        self.assertEqual(base64.b64decode(hooks[0]['after']), b'FRAGMENT')
        self.assertEqual(hooks[0]['type'], 1)
        self.assertTrue(hooks[0]['from_client'])
        self.assertEqual(base64.b64decode(hooks[5]['before']), b'server')
        self.assertEqual(
            base64.b64decode(hooks[5]['after']), b'client:server')
        self.assertFalse(hooks[5]['from_client'])

    def test_control_frames_do_not_create_message_callbacks(self):
        hooks = [
            item for item in self.corpus['hooks']
            if item['hook'] == 'websocket_message'
        ]
        self.assertEqual(len(hooks), 10)
        self.assertEqual(
            self.corpus['origin']['controls'][:2],
            [['ping', 'client-ping'], ['ping', 'between-client']],
        )
        self.assertIn(['ping', 'server-ping'], self.corpus['client']['controls'])
        self.assertIn(['ping', 'between-server'], self.corpus['client']['controls'])

    def test_binary_text_and_empty_replacements_reach_the_peer(self):
        origin_messages = [
            decoded(item) for item in self.corpus['origin']['messages']
        ]
        client_messages = [
            decoded(item) for item in self.corpus['client']['messages']
        ]
        self.assertEqual(origin_messages, [
            (1, b'FRAGMENT'),
            (2, b'\x01\xfe'),
            (1, b'after-client'),
            (1, b'filled-client'),
        ])
        self.assertEqual(client_messages, [
            (1, b'client:server'),
            (2, b'\x11\xee'),
            (1, b'after-server'),
            (1, b'filled-server'),
        ])

    def test_drop_is_explicit_and_history_remains_append_only(self):
        hooks = [
            item for item in self.corpus['hooks']
            if item['hook'] == 'websocket_message'
        ]
        self.assertEqual(
            [item['message_count'] for item in hooks],
            list(range(1, 11)),
        )
        dropped = [item for item in hooks if item['dropped']]
        self.assertEqual(
            [base64.b64decode(item['before']) for item in dropped],
            [b'drop-client', b'drop-server'],
        )
        forwarded = (
            self.corpus['origin']['messages']
            + self.corpus['client']['messages']
        )
        forwarded_content = [decoded(item)[1] for item in forwarded]
        self.assertNotIn(b'drop-client', forwarded_content)
        self.assertNotIn(b'drop-server', forwarded_content)

    def test_clean_end_hook_observes_live_flow_and_close_is_preserved(self):
        end = self.corpus['hooks'][-1]
        self.assertEqual(end['hook'], 'websocket_end')
        self.assertTrue(end['live'])
        self.assertIsNone(end['error'])
        self.assertEqual(decoded(self.corpus['client']['close']), (8, b'\x03\xe8done'))
        self.assertEqual(
            self.corpus['origin']['close'],
            [True, 8, base64.b64encode(b'\x03\xe8done').decode('ascii')],
        )


if __name__ == '__main__':
    unittest.main()
