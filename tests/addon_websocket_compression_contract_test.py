"""Guard negotiated permessage-deflate behavior from mitmproxy 12.3.1."""

import base64
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_websocket_compression_v12.json'
FRAGMENTED_CLIENT = (
    ROOT / 'tests' / 'corpus'
    / 'addon_websocket_compression_fragmented_client_v12.json'
)
FRAGMENTED_SERVER = (
    ROOT / 'tests' / 'corpus'
    / 'addon_websocket_compression_fragmented_server_v12.json'
)
EXTENSION = (
    'permessage-deflate; client_no_context_takeover; '
    'server_no_context_takeover'
)


class WebSocketCompressionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS.read_text())
        cls.fragmented_client = json.loads(FRAGMENTED_CLIENT.read_text())
        cls.fragmented_server = json.loads(FRAGMENTED_SERVER.read_text())

    def test_extension_is_negotiated_end_to_end(self):
        self.assertEqual(
            self.corpus['origin']['request_extension'], EXTENSION)
        self.assertEqual(
            self.corpus['client']['response_extension'], EXTENSION)

    def test_addon_observes_plaintext_and_mutations_are_recompressed(self):
        hooks = self.corpus['hooks']
        self.assertEqual(len(hooks), 2)
        self.assertEqual(
            base64.b64decode(hooks[0]['before']),
            b'client-compressed-payload',
        )
        self.assertEqual(
            base64.b64decode(hooks[0]['after']),
            b'client-mutated:client-compressed-payload',
        )
        self.assertEqual(
            base64.b64decode(hooks[1]['before']),
            b'server-compressed-payload',
        )
        self.assertEqual(
            base64.b64decode(hooks[1]['after']),
            b'server-mutated:server-compressed-payload',
        )

        origin_message = self.corpus['origin']['message']
        client_message = self.corpus['client']['message']
        self.assertTrue(origin_message['compressed'])
        self.assertTrue(client_message['compressed'])
        self.assertEqual(
            base64.b64decode(origin_message['content']),
            b'client-mutated:client-compressed-payload',
        )
        self.assertEqual(
            base64.b64decode(client_message['content']),
            b'server-mutated:server-compressed-payload',
        )

    def test_control_frames_remain_outside_message_callbacks(self):
        self.assertEqual(
            [hook['message_count'] for hook in self.corpus['hooks']],
            [1, 2],
        )
        self.assertIn(
            ['ping', 'client-ping'], self.corpus['origin']['controls'])
        self.assertIn(
            ['ping', 'origin-ping'], self.corpus['client']['controls'])
        self.assertEqual(self.corpus['origin']['close_opcode'], 8)
        self.assertEqual(self.corpus['client']['close_opcode'], 8)

    def test_fragmented_compressed_client_message_closes_before_callback(self):
        observation = self.fragmented_client
        self.assertEqual(observation['fragmented_side'], 'client')
        self.assertEqual(observation['hooks'], [])
        self._assert_utf8_close(observation['client']['message'])
        self._assert_utf8_close(observation['origin']['message'])

    def test_fragmented_compressed_server_message_closes_before_callback(self):
        observation = self.fragmented_server
        self.assertEqual(observation['fragmented_side'], 'server')
        self.assertEqual(len(observation['hooks']), 1)
        self.assertTrue(observation['hooks'][0]['from_client'])
        self._assert_utf8_close(observation['client']['message'])
        self.assertEqual(observation['origin']['close_opcode'], 8)

    def _assert_utf8_close(self, message):
        self.assertTrue(message['close'])
        payload = base64.b64decode(message['payload'])
        self.assertEqual(int.from_bytes(payload[:2], 'big'), 1007)
        self.assertIn(b'utf-8', payload[2:])


if __name__ == '__main__':
    unittest.main()
