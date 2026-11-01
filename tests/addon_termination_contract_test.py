"""Guard HTTP termination behavior observed in mitmproxy 12.3.1."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tests' / 'corpus'


def load(name):
    return json.loads((CORPUS / name).read_text())


class TerminationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.h1_request = load('addon_kill_v12.json')
        cls.h1_response = load('addon_kill_response_v12.json')
        cls.h2_request = load('addon_kill_h2_v12.json')
        cls.h2_multiplex = load('addon_kill_h2_multiplex_v12.json')
        cls.h2_late_request = load(
            'addon_kill_h2_requestheaders_late_data_v12.json')
        cls.h2_response = load('addon_kill_response_h2_v12.json')
        cls.h2_late_response = load(
            'addon_kill_response_h2_late_data_v12.json')
        cls.reset_before = load('addon_goaway_reset_before_v12.json')
        cls.reset_after = load('addon_goaway_reset_after_v12.json')

    def test_http1_kill_closes_without_response_bytes(self):
        for corpus in (self.h1_request, self.h1_response):
            for path, client in corpus['clients'].items():
                with self.subTest(path=path):
                    self.assertEqual(client, {
                        'outcome': 'eof',
                        'wire': '',
                    })

            killed = [
                hook for hook in corpus['hooks']
                if hook['hook'].endswith('after-kill')
            ]
            self.assertTrue(killed)
            for hook in killed:
                self.assertFalse(hook['live'])
                self.assertFalse(hook['killable'])
                self.assertEqual(hook['error'], 'Connection killed.')

    def test_http2_request_kill_resets_only_the_selected_stream(self):
        single = self.h2_request
        self.assertEqual(single['client']['outcome'], 'stream-reset')
        reset = single['client']['events'][-1]
        self.assertEqual(reset, {
            'type': 'StreamReset',
            'stream': 1,
            'error': 2,
        })

        multiplex = self.h2_multiplex
        self.assertEqual(multiplex['origin_paths'], ['/survive'])
        self.assertEqual(multiplex['client_events'][0], reset)
        sibling = multiplex['client_events'][1:]
        self.assertEqual(sibling[0], {
            'type': 'ResponseReceived',
            'stream': 3,
            'status': '200',
        })
        self.assertEqual(sibling[1]['body'], 'survived')
        self.assertEqual(sibling[-1], {
            'type': 'StreamEnded',
            'stream': 3,
        })

    def test_late_request_data_does_not_revive_a_killed_h2_stream(self):
        corpus = self.h2_late_request
        self.assertEqual(
            corpus['client_late_data'],
            [
                {'body': 'late', 'end_stream': False},
                {'body': 'body', 'end_stream': True},
            ],
        )
        self.assertEqual(corpus['origin_paths'], ['/survive'])
        self.assertEqual(corpus['client_events'][0], {
            'type': 'StreamReset',
            'stream': 1,
            'error': 2,
        })
        killed_hooks = [
            hook['hook'] for hook in corpus['hooks']
            if hook['path'] == '/kill-headers'
        ]
        self.assertEqual(
            killed_hooks,
            ['requestheaders', 'requestheaders-after-kill', 'error'],
        )

    def test_response_kill_is_stream_local_even_with_late_origin_data(self):
        for corpus in (self.h2_response, self.h2_late_response):
            streams = corpus['client_streams']
            for stream in ('1', '5'):
                with self.subTest(stream=stream):
                    self.assertIsNone(streams[stream]['status'])
                    self.assertEqual(streams[stream]['body'], '')
                    self.assertEqual(streams[stream]['reset'], 2)
                    self.assertFalse(streams[stream]['ended'])
            for stream in ('3', '7'):
                with self.subTest(stream=stream):
                    self.assertEqual(streams[stream]['status'], '200')
                    self.assertEqual(
                        streams[stream]['body'],
                        'origin-' + stream,
                    )
                    self.assertIsNone(streams[stream]['reset'])
                    self.assertTrue(streams[stream]['ended'])
            self.assertEqual(corpus['origin_resets'], [])

            header_hooks = [
                hook['hook']
                for hook in corpus['hooks']['/kill-response-headers']
            ]
            response_hooks = [
                hook['hook']
                for hook in corpus['hooks']['/kill-response']
            ]
            self.assertEqual(header_hooks[-2:], [
                'responseheaders-after-kill',
                'error',
            ])
            self.assertEqual(response_hooks[-1], 'response-after-kill')
            self.assertNotIn('error', response_hooks)

    def test_reset_and_goaway_order_selects_the_reference_error(self):
        before = self.reset_before
        self.assertEqual(before['reset_goaway_order'], 'before')
        self.assertEqual(before['client_ended'], [3, 1])
        before_errors = {
            hook[1]: hook[2]
            for hook in before['hooks']
            if hook[0] == 'error'
        }
        self.assertEqual(before_errors['/3'], 'stream reset by client (NO_ERROR)')
        self.assertIn('HTTP/2 connection closed', before_errors['/1'])

        after = self.reset_after
        self.assertEqual(after['reset_goaway_order'], 'after')
        self.assertEqual(after['client_ended'], [1, 3])
        after_errors = [
            hook[2]
            for hook in after['hooks']
            if hook[0] == 'error'
        ]
        self.assertEqual(len(after_errors), 2)
        self.assertTrue(all(
            'RECV_RST_STREAM' in error
            for error in after_errors
        ))
        self.assertEqual(after['client_resets'], [])


if __name__ == '__main__':
    unittest.main()
