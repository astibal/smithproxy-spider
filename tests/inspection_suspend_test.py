"""Logical suspension checked against independent HTTP/2 peers."""
import copy
import base64
import unittest
from unittest.mock import patch

import h2.events

from inspection_translate_windows_test import Peers, CommitException
from inspection_api import Connection as NativeConnection, HpackField
from inspection_h2_test import frame


def suspend(stream):
    def edit(message):
        anchor = next(part for part in message.parts
                      if part.stream_id == stream and part.frame_type in (0, 1))
        message.suspend(anchor)
    return edit


class SuspensionTests(unittest.TestCase):
    def request(self, peers, stream):
        peers.peers['L'].send_headers(stream, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/'),
        ])

    def wake(self, peers, stream, side='L'):
        peers.pump(side, frame(b'12345678', 6, 0, 0),
                   lambda message: message.resume(stream))

    def requests(self, peers):
        return [event.stream_id for event in peers.events['R']
                if isinstance(event, h2.events.RequestReceived)]

    def test_initial_headers_resume_once(self):
        peers = Peers()
        self.request(peers, 1)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        self.assertEqual(self.requests(peers), [])
        self.wake(peers, 1)
        self.assertEqual(self.requests(peers), [1])
        with self.assertRaises(CommitException):
            self.wake(peers, 1)
        self.assertEqual(self.requests(peers), [1])

    def test_request_resumes_from_server_callback(self):
        peers = Peers()
        self.request(peers, 1)
        peers.peers['L'].send_data(1, b'request', end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        self.wake(peers, 1, 'R')
        self.assertEqual(self.requests(peers), [1])
        self.assertEqual(peers.received['R'], [b'request'])
        self.assertEqual(peers.received['L'], [])
        self.assertNotIn('suspension', peers.bridge.control)

    def test_response_resumes_from_client_callback(self):
        peers = Peers()
        peers.open()
        peers.peers['R'].send_headers(1, [(':status', '200'), ('content-length', '3')])
        peers.peers['R'].send_data(1, b'old', end_stream=True)
        peers.pump('R', peers.peers['R'].data_to_send(), suspend(1))

        def edit(message):
            for part in message.resume(1):
                if part.frame_type == 0:
                    part.set_bytes(b'replacement')

        peers.pump('L', frame(b'12345678', 6, 0, 0), edit)
        self.assertEqual(peers.received['L'], [b'replacement'])
        response = next(event for event in peers.events['L']
                        if isinstance(event, h2.events.ResponseReceived))
        self.assertIn((b'content-length', b'11'), response.headers)

    def test_resume_releases_both_directions_of_stream(self):
        peers = Peers()
        peers.open()
        peers.peers['R'].send_headers(1, [(':status', '200')])
        peers.pump('R', peers.peers['R'].data_to_send())
        for side in ('L', 'R'):
            peers.peers[side].send_data(1, side.encode())
            peers.pump(side, peers.peers[side].data_to_send(), suspend(1))
        self.wake(peers, 1)
        self.assertEqual(peers.received['R'], [b'L'])
        self.assertEqual(peers.received['L'], [b'R'])
        self.assertNotIn('suspension', peers.bridge.control)

    def test_reverse_resume_failure_is_atomic_and_retryable(self):
        peers = Peers()
        self.request(peers, 1)
        peers.peers['L'].send_data(1, b'private', end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        before = copy.deepcopy(peers.bridge.control)
        message = peers.bridge.message('R', frame(b'12345678', 6, 0, 0))
        restored = message.resume(1)
        body = next(part for part in restored if part.frame_type == 0)
        body.stream_id = 3
        with self.assertRaises(CommitException):
            peers.bridge.publish('R', message)
        self.assertEqual(peers.bridge.control, before)
        self.assertIsNone(message._translation.result)
        body.stream_id = 1
        peers.bridge.publish('R', message)
        events = peers.peers['R'].receive_data(peers.bridge.reverse)
        self.assertEqual([event.data for event in events
                          if isinstance(event, h2.events.DataReceived)], [b'private'])

    def test_reverse_resume_keeps_hpack_valid_for_following_requests(self):
        peers = Peers()
        self.request(peers, 1)
        self.request(peers, 3)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        self.wake(peers, 1, 'R')
        self.request(peers, 5)
        peers.pump('L', peers.peers['L'].data_to_send())
        self.assertEqual(self.requests(peers), [1, 3, 5])

    def test_reverse_resume_preserves_fragmented_triggering_input(self):
        peers = Peers()
        self.request(peers, 1)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        ping = frame(b'12345678', 6, 0, 0)
        peers.pump('R', ping[:5], lambda message: message.resume(1))
        self.assertEqual(self.requests(peers), [1])
        peers.pump('R', ping[5:])
        self.assertIsNone(peers.bridge.held['R'])
        self.assertEqual(self.requests(peers), [1])

    def test_reverse_resume_obeys_updated_peer_stream_window(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'held', end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        import h2.settings
        peers.peers['R'].update_settings({h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 0})
        peers.pump('R', peers.peers['R'].data_to_send(), lambda message: message.resume(1))
        self.assertEqual(peers.received['R'], [])
        peers.peers['R'].increment_flow_control_window(4, stream_id=1)
        peers.pump('R', peers.peers['R'].data_to_send())
        self.assertEqual(peers.received['R'], [b'held'])
        self.assertEqual(peers.ended['R'], [1])

    def test_reverse_headers_obey_new_table_limit(self):
        import h2.settings
        peers = Peers()
        self.request(peers, 1)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        peers.peers['R'].update_settings({h2.settings.SettingCodes.HEADER_TABLE_SIZE: 0})
        peers.pump('R', peers.peers['R'].data_to_send(), lambda message: message.resume(1))
        self.assertEqual(self.requests(peers), [1])
        self.request(peers, 3)
        peers.pump('L', peers.peers['L'].data_to_send())
        self.assertEqual(self.requests(peers), [1, 3])

    def test_reverse_resume_supports_native_body_and_trailer_operations(self):
        peers = Peers()
        peers.peers['L'].send_headers(1, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/'),
        ], end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))

        def edit(message):
            header = message.resume(1)[0]
            connection = NativeConnection(message)
            connection.http2.replace_body(header, b'added body', encoded=True)
            connection.http2.replace_trailers(header, [HpackField(b'x-test', b'yes', 'without', 0, 0)])

        peers.pump('R', frame(b'12345678', 6, 0, 0), edit)
        self.assertEqual(peers.received['R'], [b'added body'])
        trailers = next(event for event in peers.events['R']
                        if isinstance(event, h2.events.TrailersReceived))
        self.assertEqual(trailers.headers, [(b'x-test', b'yes')])

    def test_reverse_resume_can_terminate_without_publishing_request(self):
        peers = Peers()
        self.request(peers, 1)
        peers.peers['L'].send_data(1, b'private', end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))

        def terminate(message):
            message.terminate(message.resume(1)[0])

        peers.pump('R', frame(b'12345678', 6, 0, 0), terminate)
        self.assertEqual(self.requests(peers), [])
        self.assertEqual(peers.received['R'], [])
        self.assertTrue(any(isinstance(event, h2.events.StreamReset)
                            for event in peers.events['L']))

    def test_reverse_resume_can_generate_local_response(self):
        peers = Peers()
        peers.peers['L'].send_headers(1, [
            (':method', 'GET'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/'),
        ], end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))

        def respond(message):
            message.respond(200, body=b'local', request=message.resume(1)[0])

        peers.pump('R', frame(b'12345678', 6, 0, 0), respond)
        self.assertEqual(self.requests(peers), [])
        self.assertEqual(peers.received['L'], [b'local'])

    def test_reverse_callback_cancellation_never_releases_cancelled_data(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'must-not-escape')
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        peers.peers['R'].reset_stream(1)
        peers.pump('R', peers.peers['R'].data_to_send(), lambda message: message.resume(1))
        self.assertEqual(peers.received['R'], [])
        self.assertEqual(peers.bridge.control['flow']['L']['input']['owned'], 0)
        self.assertNotIn('suspension', peers.bridge.control)

    def test_reverse_resume_worker_publishes_reverse_field_and_checkpoint(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event
        peers = Peers()
        self.request(peers, 1)
        peers.peers['L'].send_data(1, b'worker-reverse', end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        request_event = event(frame(b'12345678', 6, 0, 0), 'R')
        request_event['details']['info']['webhook_control'] = {'content-reverse': True}
        result = run(
            'api.message.resume(1)\nreturn api.message.translate()',
            request_event, instance={'mode': 'flow'}, translate_active=True,
            translate_state=peers.bridge.tables['R'],
            peer_translate_state=peers.bridge.tables['L'],
            translate_control=peers.bridge.control, hold_allowed=True,
            hold_credit_available=True, hold_credit_reserved=peers.bridge.reserved,
        )
        self.assertTrue(result['ok'], result)
        self.assertIn('peer_translate_state', result)
        events = peers.peers['R'].receive_data(base64.b64decode(result['replacement_reverse']))
        self.assertEqual([event.data for event in events
                          if isinstance(event, h2.events.DataReceived)], [b'worker-reverse'])
        self.assertNotIn('suspension', result['translate_control'])

    def test_younger_opening_waits_for_initial_headers(self):
        peers = Peers()
        self.request(peers, 1)
        self.request(peers, 3)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        self.assertEqual(self.requests(peers), [])
        self.wake(peers, 1)
        self.assertEqual(self.requests(peers), [1, 3])

    def test_cancelled_opening_releases_younger_stream(self):
        peers = Peers()
        self.request(peers, 1)
        self.request(peers, 3)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        peers.peers['L'].reset_stream(1)
        peers.pump('L', peers.peers['L'].data_to_send())
        self.assertEqual(self.requests(peers), [3])
        self.assertNotIn('suspension', peers.bridge.control)

    def test_already_open_sibling_keeps_flowing(self):
        peers = Peers()
        peers.open(stream=1)
        peers.open(stream=3)
        peers.peers['L'].send_data(1, b'held')
        peers.peers['L'].send_data(3, b'passing')
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        self.assertEqual(peers.received['R'], [b'passing'])
        self.wake(peers, 1)
        self.assertEqual(peers.received['R'], [b'passing', b'held'])

    def test_response_data_is_independent_of_other_streams(self):
        peers = Peers()
        peers.open(stream=1, reverse=True)
        peers.open(stream=3, reverse=True)
        peers.peers['R'].send_data(1, b'held-response')
        peers.peers['R'].send_data(3, b'other-response')
        peers.pump('R', peers.peers['R'].data_to_send(), suspend(1))
        self.assertEqual(peers.received['L'], [b'other-response'])
        self.wake(peers, 1, 'R')
        self.assertEqual(peers.received['L'], [b'other-response', b'held-response'])

    def test_response_headers_use_current_output_hpack(self):
        peers = Peers()
        peers.open(stream=1)
        peers.open(stream=3)
        server = peers.peers['R']
        fields = [(':status', '200'), ('x-shared', 'dynamic-table-entry')]
        server.send_headers(1, fields)
        peers.pump('R', server.data_to_send(), suspend(1))
        # The second source block references entries introduced by the held
        # first block. Its output must be independently decodable.
        server.send_headers(3, fields)
        peers.pump('R', server.data_to_send())
        self.wake(peers, 1, 'R')
        responses = [event.stream_id for event in peers.events['L']
                     if isinstance(event, h2.events.ResponseReceived)]
        self.assertEqual(responses, [3, 1])

    def test_fragmented_data_retains_fifo_order(self):
        peers = Peers()
        peers.open()
        client = peers.peers['L']
        client.send_data(1, b'first')
        peers.pump('L', client.data_to_send(), suspend(1))
        client.send_data(1, b'second', end_stream=True)
        for byte in client.data_to_send():
            peers.pump('L', bytes([byte]))
        self.assertEqual(peers.received['R'], [])
        self.wake(peers, 1)
        self.assertEqual(peers.received['R'], [b'first', b'second'])
        self.assertEqual(peers.ended['R'], [1])

    def test_resumed_draft_can_be_modified(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'original')
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))

        def edit(message):
            restored = message.resume(1)
            self.assertEqual(len(restored), 1)
            restored[0].set_bytes(b'replacement')

        peers.pump('L', frame(b'12345678', 6, 0, 0), edit)
        self.assertEqual(peers.received['R'], [b'replacement'])

    def test_resumed_headers_and_body_repair_content_length(self):
        peers = Peers()
        client = peers.peers['L']
        client.send_headers(1, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/'), ('content-length', '3'),
        ])
        client.send_data(1, b'old', end_stream=True)
        peers.pump('L', client.data_to_send(), suspend(1))

        def edit(message):
            for part in message.resume(1):
                if part.frame_type == 0:
                    part.set_bytes(b'new body')

        peers.pump('L', frame(b'12345678', 6, 0, 0), edit)
        self.assertEqual(peers.received['R'], [b'new body'])
        request = next(event for event in peers.events['R']
                       if isinstance(event, h2.events.RequestReceived))
        self.assertIn((b'content-length', b'8'), request.headers)

    def test_terminate_resumed_header_drops_held_body(self):
        peers = Peers()
        self.request(peers, 1)
        peers.peers['L'].send_data(1, b'private', end_stream=True)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))

        def terminate(message):
            header = next(part for part in message.resume(1) if part.frame_type == 1)
            message.terminate(header)

        peers.pump('L', frame(b'12345678', 6, 0, 0), terminate)
        self.assertEqual(self.requests(peers), [])
        self.assertEqual(peers.received['R'], [])
        self.assertTrue(any(isinstance(event, h2.events.StreamReset)
                            for event in peers.events['L']))

    def test_suspended_stream_receives_no_stream_window_refund(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'x' * 16000)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        updates = [event for event in peers.events['L']
                   if isinstance(event, h2.events.WindowUpdated)]
        self.assertFalse(any(event.stream_id == 1 for event in updates))
        self.assertTrue(any(event.stream_id == 0 for event in updates))

    def test_cancelled_data_does_not_escape(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'private')
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        peers.peers['L'].reset_stream(1)
        peers.pump('L', peers.peers['L'].data_to_send())
        self.assertEqual(peers.received['R'], [])
        self.assertNotIn('suspension', peers.bridge.control)
        self.assertEqual(peers.bridge.control['flow']['L']['input']['owned'], 0)

    def test_failed_publication_can_retry_without_duplicate_release(self):
        peers = Peers()
        self.request(peers, 1)
        self.request(peers, 3)
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        before = copy.deepcopy(peers.bridge.control)
        peers.peers['L'].reset_stream(1)
        message = peers.bridge.message('L', peers.peers['L'].data_to_send())
        # Fail after cancellation has released the younger stream into the
        # private publication plan, not before restoration is attempted.
        with patch('inspection_api._TranslationSuspension.checkpoint',
                   side_effect=CommitException('checkpoint failure')):
            with self.assertRaisesRegex(CommitException, 'checkpoint failure'):
                peers.bridge.publish('L', message)
        self.assertEqual(peers.bridge.control, before)
        self.assertIsNone(message._translation.result)
        wire = peers.bridge.publish('L', message)
        events = peers.peers['R'].receive_data(wire)
        self.assertEqual([event.stream_id for event in events
                          if isinstance(event, h2.events.RequestReceived)], [3])

    def test_admission_failure_keeps_existing_queue(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'existing')
        peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        before = copy.deepcopy(peers.bridge.control)
        peers.peers['L'].send_data(1, b'new')
        message = peers.bridge.message('L', peers.peers['L'].data_to_send())
        store = message._translation.suspension.buffers['L']
        store._limits = (store._limits[0], store._limits[1], 1, store._limits[3])
        with self.assertRaises(CommitException):
            peers.bridge.publish('L', message)
        self.assertEqual(peers.bridge.control, before)

    def test_checkpoint_survives_fresh_sandboxed_workers(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event

        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'worker-owned-draft')

        def invoke(script, wire):
            request_event = event(wire)
            request_event['details']['info']['webhook_control'] = {'content-reverse': True}
            result = run(
                script, request_event, instance={'mode': 'flow'},
                translate_active=True, translate_state=peers.bridge.tables['L'],
                peer_translate_state=peers.bridge.tables['R'],
                translate_control=peers.bridge.control, hold_allowed=True,
                hold_credit_available=True, hold_credit_reserved=peers.bridge.reserved,
            )
            self.assertTrue(result['ok'], result)
            peers.bridge.tables['L'] = result['translate_state']
            peers.bridge.control = result['translate_control']
            peers.bridge.reserved = peers.bridge.control['flow'].get('hold_reserved', False)
            return base64.b64decode(result['replacement'])

        wire = invoke('api.message.suspend(api.message.parts[0])\n'
                      'return api.message.translate()', peers.peers['L'].data_to_send())
        self.assertEqual(wire, b'')
        wire = invoke('api.message.resume(1)\nreturn api.message.translate()',
                      frame(b'12345678', 6, 0, 0))
        events = peers.peers['R'].receive_data(wire)
        self.assertEqual([event.data for event in events
                          if isinstance(event, h2.events.DataReceived)], [b'worker-owned-draft'])

    def test_worker_rejects_suspension_without_explicit_translate(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event

        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'must-not-leak')
        request_event = event(peers.peers['L'].data_to_send())
        request_event['details']['info']['webhook_control'] = {'content-reverse': True}
        result = run(
            'api.message.suspend(api.message.parts[0])\nreturn None',
            request_event, instance={'mode': 'flow'}, translate_active=True,
            translate_state=peers.bridge.tables['L'],
            peer_translate_state=peers.bridge.tables['R'],
            translate_control=peers.bridge.control,
            hold_allowed=True, hold_credit_available=True,
        )
        self.assertFalse(result['ok'], result)
        self.assertIsNone(result['replacement'])
        self.assertNotIn('translate_control', result)

    def test_deadline_fails_without_changing_host_state(self):
        peers = Peers()
        peers.open()
        peers.peers['L'].send_data(1, b'private')
        with patch('inspection_api._suspension_now_ms', return_value=100):
            peers.pump('L', peers.peers['L'].data_to_send(), suspend(1))
        before = copy.deepcopy(peers.bridge.control)
        with patch('inspection_api._suspension_now_ms', return_value=60100):
            with self.assertRaisesRegex(CommitException, 'timed out'):
                peers.bridge.feed('L', frame(b'12345678', 6, 0, 0))
        self.assertEqual(peers.bridge.control, before)
        self.assertEqual(peers.received['R'], [])


if __name__ == '__main__':
    unittest.main()
