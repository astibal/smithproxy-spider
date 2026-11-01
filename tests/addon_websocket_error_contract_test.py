"""Guard destructive WebSocket observations from mitmproxy 12.3.1."""

import base64
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus' / 'addon_websocket_error_v12.json'


class WebSocketErrorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scenarios = json.loads(CORPUS.read_text())['scenarios']

    def test_kill_changes_state_without_stopping_transport(self):
        for scenario in (
                'kill-start', 'kill-client-message', 'kill-server-message'):
            with self.subTest(scenario=scenario):
                observation = self.scenarios[scenario]
                hooks = observation['hooks']
                killed = [hook for hook in hooks if not hook['live']]
                self.assertTrue(killed)
                self.assertTrue(all(
                    hook['error'] == 'Connection killed.' for hook in killed))
                self.assertEqual(
                    base64.b64decode(observation['origin']['received'][3]),
                    b'hello',
                )
                self.assertEqual(
                    base64.b64decode(observation['client']['first'][3]),
                    b'echo:hello',
                )
                self.assertEqual(hooks[-1]['hook'], 'websocket_end')
                self.assertEqual(hooks[-1]['close_code'], 1000)
                self.assertEqual(hooks[-1]['close_reason'], 'done')

    def test_abrupt_close_uses_1006_without_flow_error(self):
        expected_owner = {
            'origin-abort': False,
            'client-abort': True,
        }
        for scenario, closed_by_client in expected_owner.items():
            with self.subTest(scenario=scenario):
                end = self.scenarios[scenario]['hooks'][-1]
                self.assertEqual(end['hook'], 'websocket_end')
                self.assertEqual(end['close_code'], 1006)
                self.assertIsNone(end['close_reason'])
                self.assertEqual(end['closed_by_client'], closed_by_client)
                self.assertIsNone(end['error'])
                self.assertTrue(end['live'])

    def test_invalid_text_is_rejected_before_message_callback(self):
        observation = self.scenarios['invalid-client-text']
        hooks = observation['hooks']
        self.assertEqual(
            [hook['hook'] for hook in hooks],
            ['websocket_start', 'websocket_end'],
        )
        end = hooks[-1]
        self.assertEqual(end['close_code'], 1007)
        self.assertTrue(end['closed_by_client'])
        self.assertIn('utf-8', end['close_reason'])
        self.assertIsNone(end['error'])
        self.assertEqual(observation['client']['first'][2], 8)
        self.assertEqual(observation['origin']['received'][2], 8)

    def test_invalid_server_text_is_rejected_before_server_message_callback(self):
        observation = self.scenarios['invalid-server-text']
        hooks = observation['hooks']
        self.assertEqual(
            [hook['hook'] for hook in hooks],
            ['websocket_start', 'websocket_message', 'websocket_end'],
        )
        self.assertTrue(hooks[1]['from_client'])
        end = hooks[-1]
        self.assertEqual(end['close_code'], 1007)
        self.assertFalse(end['closed_by_client'])
        self.assertIn('utf-8', end['close_reason'])
        self.assertIsNone(end['error'])
        self.assertEqual(observation['client']['first'][2], 8)
        self.assertEqual(observation['origin']['close_reply'][2], 8)

    def test_end_liveness_depends_only_on_prior_public_state(self):
        self.assertTrue(self.scenarios['origin-abort']['hooks'][-1]['live'])
        self.assertTrue(self.scenarios['client-abort']['hooks'][-1]['live'])
        self.assertTrue(
            self.scenarios['invalid-client-text']['hooks'][-1]['live'])
        self.assertTrue(
            self.scenarios['invalid-server-text']['hooks'][-1]['live'])
        self.assertFalse(
            self.scenarios['kill-client-message']['hooks'][-1]['live'])


if __name__ == '__main__':
    unittest.main()
