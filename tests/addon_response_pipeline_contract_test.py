"""Guard HTTP/1 response-pipeline behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus'


def load(name):
    return json.loads((CORPUS / name).read_text())


class ResponsePipelineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pipeline = load('addon_local_response_pipeline_v12.json')
        cls.chunked_trailer = load(
            'addon_local_response_chunked_trailer_v12.json')
        cls.live_trailer = load('addon_live_h1_trailers_v12.json')

    def test_pipelined_local_responses_keep_flow_and_wire_order(self):
        paths = [hook['path'] for hook in self.pipeline['hooks']]
        self.assertEqual(paths, [
            '/pipeline-first',
            '/pipeline-first',
            '/pipeline-first',
            '/pipeline-first',
            '/pipeline-second',
            '/pipeline-second',
            '/pipeline-second',
            '/pipeline-second',
        ])

        hook_names = [hook['hook'] for hook in self.pipeline['hooks']]
        self.assertEqual(hook_names[:4], [
            'requestheaders',
            'request',
            'responseheaders',
            'response',
        ])
        self.assertEqual(hook_names[4:], hook_names[:4])

        responses = self.pipeline['responses']
        self.assertEqual([item['status'] for item in responses], [200, 201])
        self.assertEqual(
            [item['body'] for item in responses],
            [
                'first local response | response hook',
                'second local response | response hook',
            ],
        )

    def test_local_response_hooks_can_mutate_body_and_headers(self):
        for response in self.pipeline['responses']:
            headers = dict(response['headers'])
            with self.subTest(status=response['status']):
                self.assertEqual(headers['X-Response-Headers'], 'seen')
                self.assertEqual(headers['X-Response'], 'seen')
                self.assertEqual(
                    int(headers['content-length']),
                    len(response['body'].encode()),
                )

    def test_http1_trailer_reference_limitations_remain_visible(self):
        live = self.live_trailer
        self.assertEqual(live['outcome'], 'proxy-error')
        self.assertFalse(live['request_forwarded'])
        self.assertFalse(live['client_response'])
        self.assertEqual(
            live['error'],
            'NotImplementedError: HTTP trailers are not implemented yet.',
        )

        local = self.chunked_trailer
        self.assertTrue(local['timed_out'])
        self.assertNotIn('0\r\n', local['wire'])
        self.assertTrue(local['wire'].endswith(
            'chunked local response | response hook\r\n'))
        response_hooks = local['hooks'][2:]
        for hook in response_hooks:
            self.assertEqual(hook['trailers'], [
                ['x-local-trailer', 'one'],
                ['x-local-trailer', 'two'],
            ])


if __name__ == '__main__':
    unittest.main()
