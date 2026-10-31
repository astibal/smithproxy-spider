"""WebSocket data-model parity without reference implementation imports."""

import json
from pathlib import Path
import sys
import typing
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import addon_websocket as websocket
from addon_websocket_contract import collect


class WebSocketTests(unittest.TestCase):
    def test_public_opcode_and_state_alias(self):
        self.assertEqual(
            [(name, int(value)) for name, value in websocket.Opcode.__members__.items()],
            [('CONTINUATION', 0), ('TEXT', 1), ('BINARY', 2),
             ('CLOSE', 8), ('PING', 9), ('PONG', 10)],
        )
        self.assertEqual(typing.get_origin(websocket.WebSocketMessageState), tuple)
        self.assertEqual(typing.get_args(websocket.WebSocketMessageState),
                         (int, bool, bytes, float, bool, bool))

    def test_reference_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_websocket_v12.json').read_text())
        actual = collect(websocket)
        self.assertEqual(actual.keys(), corpus['cases'].keys())
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    def test_zero_timestamp_uses_current_time_and_kill_warns(self):
        with patch.object(websocket.time, 'time', return_value=456):
            message = websocket.WebSocketMessage(1, True, b'x', timestamp=0)
        self.assertEqual(message.timestamp, 456)
        with self.assertWarnsRegex(DeprecationWarning, 'use .drop'):
            message.kill()
        self.assertTrue(message.dropped)


if __name__ == '__main__':
    unittest.main()
