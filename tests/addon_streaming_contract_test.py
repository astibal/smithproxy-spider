"""Guard HTTP streaming behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus'


def load(name):
    return json.loads((CORPUS / name).read_text())


class StreamingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http1 = load('addon_streaming_v12.json')
        cls.http2 = load('addon_streaming_h2_v12.json')

    def test_headers_hook_selects_streaming_before_message_hook(self):
        for corpus in (self.http1, self.http2):
            hooks = corpus['hooks']
            request = hooks[:3]
            response = hooks[3:]

            with self.subTest(protocol=corpus['reference'], side='request'):
                self.assertEqual(
                    [hook['hook'] for hook in request],
                    [
                        'requestheaders-before',
                        'requestheaders-after',
                        'request',
                    ],
                )
                self.assertFalse(request[0]['stream'])
                self.assertTrue(request[1]['stream'])
                self.assertTrue(request[2]['stream'])

            with self.subTest(protocol=corpus['reference'], side='response'):
                self.assertEqual(
                    [hook['hook'] for hook in response],
                    [
                        'responseheaders-before',
                        'responseheaders-after',
                        'response',
                    ],
                )
                self.assertFalse(response[0]['stream'])
                self.assertTrue(response[1]['stream'])
                self.assertTrue(response[2]['stream'])

    def test_streamed_messages_do_not_retain_buffered_content(self):
        for corpus in (self.http1, self.http2):
            for hook in corpus['hooks']:
                with self.subTest(
                        protocol=corpus['reference'], hook=hook['hook']):
                    self.assertIsNone(hook['content'])

    def test_http1_still_delivers_both_streamed_bodies(self):
        self.assertEqual(self.http1['origin'], {
            'request_body': 'request body',
            'request_line': 'POST /stream HTTP/1.1',
        })
        self.assertEqual(self.http1['client'], {
            'body': 'origin result',
            'status_line': 'HTTP/1.1 200 OK',
        })

    def test_http2_preserves_stream_framing_and_wire_bodies(self):
        self.assertEqual(self.http2['origin'], {
            'body': 'request body',
            'path': '/stream',
        })
        self.assertEqual(self.http2['client']['body'], 'origin result')
        self.assertEqual(
            self.http2['client']['events'],
            [
                'ResponseReceived',
                'DataReceived',
                'DataReceived',
                'StreamEnded',
            ],
        )
        self.assertEqual(
            self.http2['client']['headers'],
            [
                [':status', '200'],
                ['content-length', '13'],
            ],
        )


if __name__ == '__main__':
    unittest.main()
