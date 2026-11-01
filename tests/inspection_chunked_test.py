"""Chunked Parts: independent HTTP peer oracle, hold boundaries and draft edits."""
import http.client
import base64
import io
import json
import pathlib
import random
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import (
    Message, PartType, Safety, CommitException, Header,
    _prepare_h1_responses,
)
from inspection_hold_test import checkpoint, resume, header_fragment_info

HEAD = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
WIRE = b'03;hello="world"\r\nabc\r\n2\r\nde\r\n0\r\n\r\n'


def message(data=WIRE, head=HEAD):
    end = head.index(b'\r\n') + 2
    return Message(head + data, len(head + data), {'content_annotations': [
        [0, end, 'http1.start_line'], [end, len(head), 'http1.headers']]})


def peer_body(wire):
    class Socket:
        def makefile(self, *args):
            return io.BytesIO(wire)

    response = http.client.HTTPResponse(Socket())
    response.begin()
    return response.read()


def h1_messages(*items):
    wire = b''.join(items)
    annotations = []
    offset = 0
    for item in items:
        line_end = item.index(b'\r\n') + 2
        head_end = item.index(b'\r\n\r\n') + 4
        annotations.extend((
            [offset, offset + line_end, 'http1.start_line'],
            [offset + line_end, offset + head_end, 'http1.headers'],
        ))
        offset += len(item)
    return Message(wire, len(wire), {'content_annotations': annotations})


def h1_flow(side, *items, state=None, reverse=True):
    result = h1_messages(*items)
    _prepare_h1_responses(result, {
        'instance': {'mode': 'flow'},
        'h1_response_state': state,
        'event': {'details': {'info': {
            'side': side,
            'webhook_control': {'content-reverse': reverse},
        }}},
    })
    return result


class H1SuspensionTests(unittest.TestCase):
    request = b'GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n'
    later = b'GET /later HTTP/1.1\r\nHost: example.test\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody'

    def callback(self, side, *items, state=None, held=None, peer=None,
                 allow_hold=True, reverse=True, info=None):
        data = b''.join(items)
        annotations = []
        offset = 0
        for item in items:
            if b'\r\n\r\n' in item:
                line_end = item.index(b'\r\n') + 2
                head_end = item.index(b'\r\n\r\n') + 4
                annotations.extend((
                    [offset, offset + line_end, 'http1.start_line'],
                    [offset + line_end, offset + head_end, 'http1.headers'],
                ))
            offset += len(item)

        if info is None:
            info = {'content_annotations': annotations}
        if held is not None:
            message = resume(held, data, info)
        else:
            message = Message(data, len(data), info)

        _prepare_h1_responses(message, {
            'instance': {'mode': 'flow'},
            'hold_allowed': allow_hold,
            'held_parts': held,
            'peer_held_parts': peer,
            'h1_response_state': state,
            'event': {'details': {'info': {
                'side': side,
                'webhook_control': {
                    'content-reverse': reverse,
                    'connection-close': True,
                },
            }}},
        })
        return message

    def pause(self, side='L', state=None, wire=None):
        message = self.callback(side, wire or self.request, state=state)
        self.assertEqual(message.suspend(message.parts[0]), 0)
        held = message.commit()
        self.assertEqual(held.prefix, b'')
        return held.checkpoint, message._h1_response.checkpoint

    def test_pause_survives_fresh_callbacks_and_keeps_younger_requests(self):
        held, state = self.pause()
        next_message = self.callback('L', self.later, held=held, state=state)

        still_held = next_message.commit()

        self.assertEqual(still_held.prefix, b'')
        self.assertEqual(next_message._h1_response.checkpoint, state)

        released = self.callback('L', held=still_held.checkpoint, state=state)
        parts = released.resume(0, side='L')
        parts[0].http1.target = '/edited'

        self.assertEqual(released.commit(), self.request.replace(b'/first', b'/edited') + self.later)
        self.assertEqual(released._h1_response.checkpoint, {
            'version': 1, 'slots': ['origin', 'origin'],
        })

    def test_peer_resume_uses_reverse_output_and_native_edits(self):
        held, state = self.pause()
        callback = self.callback('R', state=state, peer=held)
        detached = callback.suspended_parts(0, side='L')
        detached[0].http1.target = '/discarded'
        parts = callback.resume(0, side='L')
        parts[0].http1.target = '/edited'

        self.assertEqual(callback.commit(), b'')
        self.assertEqual(callback._h1_response.reverse_output,
                         self.request.replace(b'/first', b'/edited'))
        self.assertEqual(callback._h1_response.checkpoint['slots'], ['origin'])
        self.assertTrue(callback._h1_response.suspension.peer_hold_changed)
        self.assertIsNone(callback._h1_response.suspension.peer_hold_result)

    def test_peer_response_resume_follows_current_request_publication(self):
        request = self.callback('L', self.request)
        request.commit()
        held, state = self.pause('R', request._h1_response.checkpoint, self.response)
        callback = self.callback('L', self.later, peer=held, state=state)
        parts = callback.resume(0, side='R')
        parts[1].set_bytes(b'changed body')

        self.assertEqual(callback.commit(), self.later)
        self.assertEqual(peer_body(callback._h1_response.reverse_output), b'changed body')
        self.assertEqual(callback._h1_response.checkpoint['slots'], ['origin'])

    def test_resume_can_pause_younger_pipeline_message_atomically(self):
        for side in ('L', 'R'):
            with self.subTest(callback_side=side):
                initial = self.callback('L', self.request, self.later)
                initial.suspend(initial.parts[0])
                held = initial.commit().checkpoint
                state = initial._h1_response.checkpoint

                if side == 'L':
                    callback = self.callback(side, state=state, held=held)
                else:
                    callback = self.callback(side, state=state, peer=held)
                parts = callback.resume(0, side='L')
                callback.suspend(parts[2])
                result = callback.commit()

                if side == 'L':
                    self.assertEqual(result.prefix, self.request)
                    remaining = result.checkpoint
                else:
                    self.assertEqual(result, b'')
                    self.assertEqual(callback._h1_response.reverse_output, self.request)
                    remaining = callback._h1_response.suspension.peer_hold_result
                self.assertEqual(callback._h1_response.checkpoint['slots'], ['origin'])

                final = self.callback('L', held=remaining,
                                      state=callback._h1_response.checkpoint)
                final.resume(0, side='L')
                self.assertEqual(final.commit(), self.later)
                self.assertEqual(final._h1_response.checkpoint['slots'], ['origin', 'origin'])

    def test_resumed_peer_request_can_generate_local_response(self):
        held, state = self.pause()
        callback = self.callback('R', state=state, peer=held)
        parts = callback.resume(0, side='L')
        callback.respond(201, body=b'local', request=parts[0])

        self.assertEqual(peer_body(callback.commit()), b'local')
        self.assertEqual(callback._h1_response.reverse_output, b'')
        self.assertEqual(callback._h1_response.checkpoint['slots'], [])

    def test_incomplete_peer_resume_preserves_reassembly_hold(self):
        head = b'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\n'
        held, state = self.pause(wire=head + b'ab')
        callback = self.callback('R', state=state, peer=held)
        callback.resume(0, side='L')

        self.assertEqual(callback.commit(), b'')
        self.assertEqual(callback._h1_response.reverse_output, b'')
        next_hold = callback._h1_response.suspension.peer_hold_result
        self.assertIsNotNone(next_hold)
        self.assertNotIn('paused', callback._h1_response.checkpoint)

        completed = self.callback('L', b'cd', held=next_hold,
                                  state=callback._h1_response.checkpoint)
        self.assertEqual(completed.commit(), head + b'abcd')
        self.assertEqual(completed._h1_response.checkpoint['slots'], ['origin'])

    def test_peer_resume_publishes_prefix_and_keeps_partial_younger_header(self):
        message = self.callback('L', self.request)
        pending = Message(b'GE', 2, header_fragment_info(self.later, 0, 2))
        message.parts.extend(pending.parts)

        # Prepare again after constructing the full callback so native identity
        # checks cover both the complete request and its incomplete successor.
        _prepare_h1_responses(message, {
            'instance': {'mode': 'flow'}, 'hold_allowed': True,
            'event': {'details': {'info': {
                'side': 'L', 'webhook_control': {'content-reverse': True},
            }}},
        })
        message.suspend(message.parts[0])
        held = message.commit()

        callback = self.callback('R', state=message._h1_response.checkpoint,
                                 peer=held.checkpoint)
        callback.resume(0, side='L')
        self.assertEqual(callback.commit(), b'')
        self.assertEqual(callback._h1_response.reverse_output, self.request)
        next_hold = callback._h1_response.suspension.peer_hold_result
        self.assertIsNotNone(next_hold)

        completed = self.callback(
            'L', self.later[2:], held=next_hold,
            state=callback._h1_response.checkpoint,
            info=header_fragment_info(self.later, 2, len(self.later)))
        self.assertEqual(completed.commit(), self.later)
        self.assertEqual(completed._h1_response.checkpoint['slots'], ['origin', 'origin'])

    def test_resume_can_pause_again_before_a_pending_header(self):
        message = self.callback('L', self.request)
        pending = Message(b'GE', 2, header_fragment_info(self.later, 0, 2))
        message.parts.extend(pending.parts)
        _prepare_h1_responses(message, {
            'instance': {'mode': 'flow'}, 'hold_allowed': True,
            'event': {'details': {'info': {
                'side': 'L', 'webhook_control': {'content-reverse': True},
            }}},
        })
        message.suspend(message.parts[0])
        held = message.commit()

        callback = self.callback('R', state=message._h1_response.checkpoint,
                                 peer=held.checkpoint)
        parts = callback.resume(0, side='L')
        callback.suspend(parts[0])
        self.assertEqual(callback.commit(), b'')
        self.assertEqual(callback._h1_response.reverse_output, b'')
        self.assertIn('L', callback._h1_response.checkpoint['paused'])

    def test_peer_termination_discards_both_lanes(self):
        held, state = self.pause()
        callback = self.callback('R', state=state, peer=held)
        parts = callback.resume(0, side='L')
        callback.terminate(parts[0])

        self.assertEqual(callback.commit(), b'')
        self.assertEqual(callback._h1_response.reverse_output, b'')
        self.assertEqual(callback._h1_response.checkpoint, {'version': 1, 'slots': []})
        self.assertTrue(callback._h1_response.suspension.peer_hold_changed)
        self.assertIsNone(callback._h1_response.suspension.peer_hold_result)

    def test_capabilities_and_explicit_side_are_required(self):
        for options in ({'allow_hold': False}, {'reverse': False}):
            with self.subTest(options=options):
                message = self.callback('L', self.request, **options)
                with self.assertRaisesRegex(CommitException, 'support'):
                    message.suspend(message.parts[0])

        held, state = self.pause()
        callback = self.callback('R', state=state, peer=held)
        with self.assertRaisesRegex(CommitException, 'L/R side'):
            callback.resume(0)
        with self.assertRaisesRegex(CommitException, 'id zero'):
            callback.resume(1, side='L')
        self.assertIsNone(callback._h1_response.result)

    def test_failed_peer_assembly_does_not_consume_host_checkpoint(self):
        held, state = self.pause()
        before = json.dumps([held, state], sort_keys=True)
        callback = self.callback('R', state=state, peer=held)
        parts = callback.resume(0, side='L')
        parts[0].http1.set_header('Host', 'invalid\r\ninjected: header')

        with self.assertRaises(CommitException):
            callback.commit()

        self.assertIsNone(callback._h1_response.result)
        self.assertEqual(callback._h1_response.checkpoint, state)
        self.assertEqual(callback._h1_response.reverse_output, b'')
        self.assertFalse(callback._h1_response.suspension.peer_hold_changed)
        self.assertEqual(json.dumps([held, state], sort_keys=True), before)

        # Retry from the unchanged host-owned data, not the failed draft.
        retry = self.callback('R', state=state, peer=held)
        retry.resume(0, side='L')
        retry.commit()
        self.assertEqual(retry._h1_response.reverse_output, self.request)

    def test_suspension_deadline_is_checked_on_callback_not_extended(self):
        with patch('inspection_api._suspension_now_ms', return_value=1000):
            held, state = self.pause()

        with patch('inspection_api._suspension_now_ms', return_value=61000):
            callback = self.callback('R', state=state, peer=held)
            with self.assertRaisesRegex(CommitException, 'deadline expired'):
                callback.resume(0, side='L')
            self.assertIsNone(callback._h1_response.result)

    def test_suspend_cannot_be_bypassed_by_changing_hold_boundary(self):
        message = self.callback('L', self.request, self.later)
        message.suspend(message.parts[0])
        message.parts.hold_from(message.parts[2])

        with self.assertRaisesRegex(CommitException, 'boundary was changed'):
            message.commit()

        self.assertIsNone(message._h1_response.result)
        self.assertEqual(message._h1_response.reverse_output, b'')

    def test_missing_checkpoint_and_duplicate_command_are_rejected(self):
        held, state = self.pause()
        with self.assertRaisesRegex(CommitException, 'lost its retained Parts'):
            self.callback('R', state=state)

        callback = self.callback('R', state=state, peer=held)
        callback.resume(0, side='L')
        with self.assertRaisesRegex(CommitException, 'out-of-order'):
            callback.resume(0, side='L')

    def test_suspended_response_keeps_queued_local_reply_behind_it(self):
        requests = self.callback('L', self.request, self.later)
        requests.respond(201, body=b'local', request=requests.parts[2])
        requests.commit()
        held, state = self.pause('R', requests._h1_response.checkpoint, self.response)

        callback = self.callback('L', state=state, peer=held)
        callback.resume(0, side='R')
        self.assertEqual(callback.commit(), b'')
        wire = callback._h1_response.reverse_output

        self.assertTrue(wire.startswith(self.response))
        self.assertEqual(wire.count(b'HTTP/1.1 201'), 1)
        self.assertTrue(wire.endswith(b'local'))
        self.assertEqual(callback._h1_response.checkpoint['slots'], [])

    def test_fresh_workers_publish_peer_hold_and_checkpoint_together(self):
        from inspection_cookbook_test import WORKER
        from worker_bootstrap import packed_arguments

        command = [sys.executable, '-I', '-c', *packed_arguments(WORKER)]

        def invoke(script, side, items, *, state=None, held=None, peer=None):
            annotations = []
            offset = 0
            for item in items:
                line_end = item.index(b'\r\n') + 2
                head_end = item.index(b'\r\n\r\n') + 4
                annotations.extend((
                    [offset, offset + line_end, 'http1.start_line'],
                    [offset + line_end, offset + head_end, 'http1.headers'],
                ))
                offset += len(item)

            request = {
                'script': script,
                'hold_allowed': True,
                'held_parts': held,
                'peer_held_parts': peer,
                'h1_response_state': state,
                'instance': {'mode': 'flow'},
                'event': {'id': 'h1-native-suspension', 'details': {'info': {
                    'side': side,
                    'content': base64.b64encode(b''.join(items)).decode(),
                    'content_annotations': annotations,
                    'webhook_control': {'content-reverse': True},
                }}},
            }
            process = subprocess.run(command, input=json.dumps(request),
                                     capture_output=True, text=True, check=True, timeout=10)
            result = json.loads(process.stdout)
            self.assertTrue(result['ok'], result)
            return result

        # The first request has reached the origin. Its response supplies a
        # real opposite-direction callback which releases the second request.
        pause = 'api.message.suspend(api.message.parts[2])\nreturn api.message.commit()'
        first = invoke(pause, 'L', [self.request, self.later])
        self.assertEqual(base64.b64decode(first['replacement']), self.request)
        release = ('parts = api.message.resume(0, side="L")\n'
                   'parts[0].http1.target = "/edited"\n'
                   'return api.message.commit()')
        result = invoke(release, 'R', [self.response],
                        state=first['h1_response_state'], peer=first['held_parts'])

        self.assertEqual(base64.b64decode(result['replacement']), self.response)
        self.assertEqual(base64.b64decode(result['replacement_reverse']),
                         self.later.replace(b'/later', b'/edited'))
        self.assertIsNone(result['peer_held_parts'])
        self.assertEqual(result['h1_response_state'], {'version': 1, 'slots': ['origin']})

        # Reverse the roles: a later client request releases a held response.
        seed = invoke('return api.message.commit()', 'L', [self.request])
        pause = 'api.message.suspend(api.message.parts[0])\nreturn api.message.commit()'
        first = invoke(pause, 'R', [self.response], state=seed['h1_response_state'])
        release = ('parts = api.message.resume(0, side="R")\n'
                   'parts[1].set_bytes(b"edited response")\n'
                   'return api.message.commit()')
        result = invoke(release, 'L', [self.later],
                        state=first['h1_response_state'], peer=first['held_parts'])

        self.assertEqual(base64.b64decode(result['replacement']), self.later)
        self.assertEqual(peer_body(base64.b64decode(result['replacement_reverse'])), b'edited response')
        self.assertIsNone(result['peer_held_parts'])
        self.assertEqual(result['h1_response_state'], {'version': 1, 'slots': ['origin']})


class H1LocalResponseTests(unittest.TestCase):
    first = b'GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n'
    second = b'GET /second HTTP/1.1\r\nHost: example.test\r\n\r\n'
    third = b'GET /third HTTP/1.1\r\nHost: example.test\r\n\r\n'

    def test_held_requests_do_not_allocate_origin_slots(self):
        requests = h1_flow('L', self.first, self.second, self.third)
        requests.parts.hold_from(requests.parts[2])

        held = requests.commit()

        self.assertEqual(held.prefix, self.first)
        self.assertEqual(requests._h1_response.checkpoint['slots'], ['origin'])
        self.assertEqual(requests._h1_response.reverse_output, b'')

        released = resume(held.checkpoint, b'')
        _prepare_h1_responses(released, {
            'instance': {'mode': 'flow'},
            'h1_response_state': requests._h1_response.checkpoint,
            'event': {'details': {'info': {
                'side': 'L',
                'webhook_control': {'content-reverse': True},
            }}},
        })

        self.assertEqual(released.commit(), self.second + self.third)
        self.assertEqual(
            released._h1_response.checkpoint['slots'],
            ['origin', 'origin', 'origin'],
        )

    def test_response_prefix_advances_only_published_slots(self):
        requests = h1_flow('L', self.first, self.second, self.third)
        requests.respond(201, body=b'local', request=requests.parts[4])
        requests.commit()
        state = requests._h1_response.checkpoint
        first = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none'
        second = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo'
        responses = h1_flow('R', first, second, state=state)
        responses.parts.hold_from(responses.parts[2])

        held = responses.commit()

        self.assertEqual(held.prefix, first)
        self.assertEqual(responses._h1_response.checkpoint['slots'], state['slots'][1:])
        self.assertEqual(responses._h1_response.reverse_output, b'')

    def test_local_response_before_hold_remains_publishable(self):
        requests = h1_flow('L', self.first, self.second)
        requests.respond(201, body=b'local', request=requests.parts[0])
        requests.parts.hold_from(requests.parts[2])

        held = requests.commit()

        self.assertEqual(held.prefix, b'')
        self.assertEqual(requests._h1_response.checkpoint['slots'], [])
        self.assertEqual(peer_body(requests._h1_response.reverse_output), b'local')

    def test_held_response_does_not_release_queued_local_response(self):
        requests = h1_flow('L', self.first, self.second)
        requests.respond(201, body=b'local', request=requests.parts[2])
        requests.commit()
        state = requests._h1_response.checkpoint
        origin = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin'
        response = h1_flow('R', origin, state=state)
        response.parts.hold_from(response.parts[0])

        held = response.commit()

        self.assertEqual(held.prefix, b'')
        self.assertEqual(response._h1_response.checkpoint, state)
        self.assertEqual(response._h1_response.reverse_output, b'')

        # Release the native checkpoint in a fresh callback. The local reply
        # must be inserted once, after its preceding origin response.
        released = resume(held.checkpoint, b'')
        _prepare_h1_responses(released, {
            'instance': {'mode': 'flow'},
            'h1_response_state': response._h1_response.checkpoint,
            'event': {'details': {'info': {
                'side': 'R',
                'webhook_control': {'content-reverse': True},
            }}},
        })
        wire = released.commit()

        self.assertTrue(wire.startswith(origin))
        self.assertEqual(wire.count(b'HTTP/1.1 201'), 1)
        self.assertTrue(wire.endswith(b'local'))
        self.assertEqual(released._h1_response.checkpoint['slots'], [])

    def test_local_response_cannot_bypass_held_request_suffix(self):
        requests = h1_flow('L', self.first, self.second, self.third)
        requests.respond(201, body=b'local', request=requests.parts[4])
        requests.parts.hold_from(requests.parts[2])

        with self.assertRaisesRegex(CommitException, 'held request'):
            requests.commit()

        self.assertIsNone(requests._h1_response.result)
        self.assertIsNone(requests._h1_response.checkpoint)
        self.assertEqual(requests._h1_response.reverse_output, b'')

    def test_immediate_and_queued_responses_keep_pipeline_order(self):
        requests = h1_flow('L', self.first, self.second, self.third)
        requests.respond(210, body=b'first-local', request=requests.parts[0])
        requests.respond(211, body=b'third-local', request=requests.parts[4])
        self.assertEqual(requests.commit(), self.second)
        self.assertIn(b'210 ', requests._h1_response.reverse_output)
        self.assertNotIn(b'211 ', requests._h1_response.reverse_output)

        state = requests._h1_response.checkpoint
        self.assertEqual(state['slots'][0], 'origin')
        self.assertIn('response', state['slots'][1])
        origin = b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin'
        response = h1_flow('R', origin, state=state)
        wire = response.commit()
        self.assertTrue(wire.startswith(origin))
        self.assertIn(b'HTTP/1.1 211 ', wire[len(origin):])
        self.assertEqual(response._h1_response.checkpoint['slots'], [])

    def test_multiple_origin_responses_interleave_queued_local_response(self):
        requests = h1_flow('L', self.first, self.second, self.third)
        requests.respond(299, body=b'local', request=requests.parts[2])
        self.assertEqual(requests.commit(), self.first + self.third)
        state = requests._h1_response.checkpoint

        one = b'HTTP/1.1 201 One\r\nContent-Length: 1\r\n\r\n1'
        two = b'HTTP/1.1 202 Two\r\nContent-Length: 1\r\n\r\n2'
        responses = h1_flow('R', one, two, state=state)
        wire = responses.commit()
        first_end = len(one)
        local_end = wire.index(two)
        self.assertEqual(wire[:first_end], one)
        self.assertIn(b'HTTP/1.1 299 ', wire[first_end:local_end])
        self.assertEqual(wire[local_end:], two)

    def test_informational_response_does_not_consume_request_slot(self):
        request = h1_flow('L', self.first)
        self.assertEqual(request.commit(), self.first)
        interim = b'HTTP/1.1 103 Early Hints\r\n\r\n'
        message = h1_flow('R', interim, state=request._h1_response.checkpoint)
        self.assertEqual(message.commit(), interim)
        self.assertEqual(message._h1_response.checkpoint['slots'], ['origin'])

    def test_chunked_local_response_has_complete_valid_trailers(self):
        request = h1_flow('L', self.first)
        request.respond(
            204,
            headers=[(b'X-A', b'one'), (b'X-A', b'two')],
            body=b'body',
            trailers=[(b'X-Finished', b'yes')],
            reason='No Content',
        )
        self.assertEqual(request.commit(), b'')
        wire = request._h1_response.reverse_output
        self.assertEqual(wire.count(b'X-A:'), 2)
        self.assertIn(b'Transfer-Encoding: chunked\r\n', wire)
        self.assertTrue(wire.endswith(
            b'4\r\nbody\r\n0\r\nX-Finished: yes\r\n\r\n'))

    def test_http10_fixed_and_empty_responses_use_request_version(self):
        for body in (b'', b'fixed body'):
            with self.subTest(body=body):
                request = h1_flow('L', b'GET / HTTP/1.0\r\n\r\n')
                request.respond(200, body=body)
                self.assertEqual(request.commit(), b'')
                wire = request._h1_response.reverse_output
                self.assertTrue(wire.startswith(b'HTTP/1.0 200 OK\r\n'))
                self.assertIn(
                    b'Content-Length: ' + str(len(body)).encode() + b'\r\n',
                    wire,
                )
                self.assertTrue(wire.endswith(b'\r\n\r\n' + body))

    def test_validation_is_atomic_and_bounded(self):
        invalid = (
            {'status': 199},
            {'headers': [(b'Connection', b'close')]},
            {'headers': [(b'X-Test', b'bad\x01value')]},
            {'reason': 'bad\rreason'},
        )
        for options in invalid:
            with self.subTest(options=options):
                request = h1_flow('L', self.first)
                with self.assertRaises(CommitException):
                    request.respond(**options)
                self.assertIsNone(request._h1_response.result)
                self.assertEqual(request._h1_response.slots, [])

        requests = h1_flow('L', self.first, self.second)
        requests.respond(200, body=b'x' * (512 * 1024 + 1), request=requests.parts[2])
        with self.assertRaisesRegex(CommitException, '512 KiB'):
            requests.commit()
        self.assertIsNone(requests._h1_response.result)

    def test_capability_version_and_checkpoint_guards(self):
        request = h1_flow('L', self.first, reverse=False)
        with self.assertRaisesRegex(CommitException, 'content-reverse'):
            request.respond(200)

        h10 = b'GET / HTTP/1.0\r\n\r\n'
        request = h1_flow('L', h10)
        with self.assertRaisesRegex(CommitException, 'HTTP/1.1'):
            request.respond(200, trailers=[(b'X-End', b'yes')])

        with self.assertRaisesRegex(CommitException, 'checkpoint'):
            h1_flow('L', self.first, state={'version': 2, 'slots': []})


class ChunkedTests(unittest.TestCase):
    def test_noop_and_two_views(self):
        msg = message()
        self.assertEqual([p.type for p in msg.parts], [PartType.Http1.Header, PartType.Http1.Body])
        body = msg.parts[1]
        self.assertEqual(body.get_bytes(), b'abcde')
        self.assertEqual([p.get_bytes() for p in body.chunks], [b'abc', b'de'])
        self.assertEqual(msg.commit(), HEAD + WIRE)

    def test_body_replacements(self):
        for mode in (Safety.Easy, Safety.Expert):
            for data in (b'', b'x', b'longer body', bytes(range(256)) * 200):
                with self.subTest(mode=mode, size=len(data)):
                    msg = message()
                    msg.parts[1].set_bytes(data)
                    result = msg.commit(safety=mode)
                    self.assertEqual(peer_body(result), data)
                    self.assertNotIn(b'Content-Length:', result)
                    self.assertEqual(msg.commit(safety=mode), result)

    def test_chunk_edits_and_no_duplicate_emission(self):
        msg = message()
        body = msg.parts[1]
        body.chunks[1].set_bytes(b'longer')
        self.assertEqual(body.get_bytes(), b'abclonger')
        self.assertIn(b'03;hello="world"\r\nabc', msg.commit())
        self.assertEqual(peer_body(msg.commit()), b'abclonger')
        body.chunks[0].set_bytes(b'')
        self.assertEqual(peer_body(msg.commit()), b'longer')
        msg.parts.append(body.chunks[0])
        with self.assertRaises(CommitException):
            msg.commit()

    def test_conflicting_views(self):
        msg = message()
        msg.parts[1].chunks[0].set_bytes(b'x')
        msg.parts[1].set_bytes(b'y')
        with self.assertRaisesRegex(CommitException, 'combine'):
            msg.commit()

    def test_same_content_with_changed_chunk_boundaries(self):
        msg = message()
        msg.parts[1].chunks[0].set_bytes(b'a')
        msg.parts[1].chunks[1].set_bytes(b'bcde')
        wire = msg.commit()
        self.assertEqual(peer_body(wire), b'abcde')
        self.assertTrue(wire.endswith(b'1\r\na\r\n4\r\nbcde\r\n0\r\n\r\n'))

    def test_header_only_edit_preserves_chunk_extensions_and_trailers(self):
        head = HEAD[:-2] + b'Trailer: X-Test\r\n\r\n'
        wire = WIRE[:-2] + b'X-Test: original\r\n\r\n'
        msg = message(wire, head)
        msg.parts[0].http1.set_header('X-New', 'yes')
        result = msg.commit()
        self.assertIn(b'Trailer: X-Test\r\n', result)
        self.assertTrue(result.endswith(wire))

    def test_trailer_helper_replaces_duplicates_and_repairs_declaration(self):
        head = HEAD[:-2] + b'Trailer: X-Old\r\n\r\n'
        wire = WIRE[:-2] + b'X-Old: original\r\n\r\n'
        msg = message(wire, head)
        body = msg.parts[1]
        self.assertEqual(body.trailers, (Header('X-Old', 'original'),))
        body.replace_trailers([
            ('X-New', 'one'),
            ('X-New', 'two'),
            ('X-End', 'done'),
        ])
        result = msg.commit()
        self.assertIn(b'Trailer: X-New, X-End\r\n', result)
        self.assertTrue(result.endswith(
            b'0\r\nX-New: one\r\nX-New: two\r\nX-End: done\r\n\r\n'))

        body.replace_trailers([])
        body.set_bytes(b'changed after trailer removal')
        result = msg.commit()
        self.assertNotIn(b'Trailer:', result)
        self.assertTrue(result.endswith(b'0\r\n\r\n'))
        self.assertEqual(peer_body(result), b'changed after trailer removal')

    def test_trailer_helper_rejects_incomplete_invalid_and_unsafe_fields(self):
        incomplete = message(b'1\r\nx\r\n0\r\nX-Later:')
        with self.assertRaisesRegex(CommitException, 'until the message is complete'):
            incomplete.parts[1].replace_trailers([])

        msg = message()
        for fields, reason in (
                ([('bad name', 'value')], 'Invalid'),
                ([('X-Test', 'bad\rvalue')], 'Invalid'),
                ([('Content-Length', '3')], 'required before message completion')):
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(CommitException, reason):
                    msg.parts[1].replace_trailers(fields)

    def test_ambiguous_or_unsupported_heads_are_opaque(self):
        for extra in (b'Content-Length: 5\r\n', b'Transfer-Encoding: chunked\r\n',
                      b'Trailer: bad name\r\n'):
            msg = message(head=HEAD[:-2] + extra + b'\r\n')
            self.assertEqual(msg.parts[0].type, PartType.Opaque)

    def test_chunk_structure_cannot_be_silently_replaced(self):
        msg = message()
        msg.parts[1].chunks = ()
        with self.assertRaisesRegex(CommitException, 'reordered'):
            msg.commit()

    def test_terminal_extensions_and_empty_body(self):
        wire = b'000;done=yes\r\n\r\n'
        msg = message(wire)
        self.assertEqual(msg.parts[1].get_bytes(), b'')
        self.assertEqual(msg.commit(), HEAD + wire)
        msg.parts[1].set_bytes(b'new')
        self.assertEqual(peer_body(msg.commit()), b'new')
        self.assertTrue(msg.commit().endswith(wire))

    def test_malformed_extensions_and_continuations(self):
        for line in (b'1;=bad', b'1;x="unterminated', b'1;x="\x7f"', b'+1', b' 1'):
            msg = message(line + b'\r\nx\r\n0\r\n\r\n')
            self.assertEqual(msg.parts[0].type, PartType.Opaque)
        msg = message(b'1\r\nx')
        with self.assertRaisesRegex(CommitException, 'CRLF'):
            resume(checkpoint(msg), b'!!')

    def test_easy_and_expert_integrity_metadata(self):
        head = HEAD[:-2] + b'Digest: old\r\n\r\n'
        msg = message(head=head)
        msg.parts[1].set_bytes(b'changed')
        with self.assertRaises(CommitException):
            msg.commit()
        self.assertEqual(peer_body(msg.commit(safety=Safety.Expert)), b'changed')

    def test_output_quota_includes_framing(self):
        msg = message()
        msg.parts[1].set_bytes(b'x' * (1024 * 1024))
        for mode in (Safety.Easy, Safety.Expert):
            with self.assertRaises(CommitException):
                msg.commit(safety=mode)

    def test_every_split_and_trailing_bytes(self):
        for cut in range(len(WIRE)):
            with self.subTest(cut=cut):
                msg = message(WIRE[:cut])
                self.assertFalse(msg.parts[1].content.complete)
                msg = resume(checkpoint(msg), WIRE[cut:] + b'NEXT')
                self.assertTrue(msg.parts[1].content.complete)
                self.assertEqual(msg.parts[1].get_bytes(), b'abcde')
                self.assertEqual(msg.commit(), HEAD + WIRE + b'NEXT')

    def test_bytewise_hold_retains_header_and_chunk_edits(self):
        msg = message(b'')
        msg.parts[0].http1.set_header('X-Held', 'yes')
        for byte in WIRE:
            msg = resume(checkpoint(msg), bytes([byte]))
        msg.parts[1].set_bytes(b'rewritten')
        self.assertIn(b'X-Held: yes', msg.commit())
        self.assertEqual(peer_body(msg.commit()), b'rewritten')

    def test_trailers_complete_only_after_final_crlf(self):
        wire = b'1\r\nx\r\n0\r\nX-Checksum: old\r\n\r\n'
        for cut in range(len(wire)):
            msg = resume(checkpoint(message(wire[:cut])), wire[cut:])
            self.assertEqual(msg.commit(), HEAD + wire)
        msg.parts[1].set_bytes(b'new')
        with self.assertRaisesRegex(CommitException, 'trailers'):
            msg.commit()
        self.assertEqual(peer_body(msg.commit(safety=Safety.Expert)), b'new')
        self.assertIn(b'X-Checksum: old', msg.commit(safety=Safety.Expert))

    def test_incomplete_edits_cannot_emit(self):
        msg = message(b'5\r\nab')
        msg.parts[1].set_bytes(b'replacement')
        with self.assertRaisesRegex(CommitException, 'Incomplete'):
            msg.commit()
        with self.assertRaisesRegex(CommitException, 'already edited'):
            resume(checkpoint(msg), b'cde\r\n0\r\n\r\n')

    def test_bad_framing_stays_opaque(self):
        for wire in (b'z\r\nx\r\n', b'1\r\nx!!', b'0\r\nbad trailer\r\n\r\n', b'ffffffff\r\n'):
            msg = message(wire)
            self.assertEqual(msg.parts[0].type, PartType.Opaque)
            self.assertEqual(msg.commit(), HEAD + wire)

    def test_framing_change_rejected_both_modes(self):
        for mode in (Safety.Easy, Safety.Expert):
            msg = message()
            msg.parts[0].http1.set_header('Content-Length', '5')
            with self.assertRaises(CommitException):
                msg.commit(safety=mode)

    def test_random_fragmentation_and_binary_payloads(self):
        rng = random.Random(9112)
        for case in range(100):
            pieces = [rng.randbytes(rng.randint(1, 128)) for _ in range(rng.randint(1, 8))]
            wire = b''.join(f'{len(p):X}\r\n'.encode() + p + b'\r\n' for p in pieces) + b'0\r\n\r\n'
            msg, offset = message(b''), 0
            while offset < len(wire):
                count = rng.randint(1, 33)
                msg = resume(checkpoint(msg), wire[offset:offset + count])
                offset += count
            self.assertEqual(msg.parts[1].get_bytes(), b''.join(pieces))
            self.assertEqual(msg.commit(), HEAD + wire)
            msg.parts[1].set_bytes(b'changed' * case)
            self.assertEqual(peer_body(msg.commit()), b'changed' * case)

    def test_chunk_edit_survives_hold(self):
        msg = message(b'3\r\nabc\r\n')
        msg.parts[1].chunks[0].set_bytes(b'longer')
        msg = resume(checkpoint(msg), b'2\r\nde\r\n0\r\n\r\n')
        self.assertEqual(peer_body(msg.commit()), b'longerde')

    def test_fresh_workers_hold_then_release_to_peer(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        sources = ('inspection_api.py', 'inspection_h2.py', 'inspection_hold.py',
                   'inspection_chunked.py', 'inspection_translate.py', 'inspection_language.py',
                   'inspection_sandbox.py', 'inspection_worker.py')
        from worker_bootstrap import packed
        worker = packed('\n'.join((root / 'src' / name).read_text() for name in sources))
        script = ('body = api.message.parts[1]\n'
                  'if not body.content.complete:\n'
                  '    api.message.parts.hold_from(api.message.parts[0])\n'
                  '    return api.message.commit()\n'
                  'body.set_bytes(b"changed body")\n'
                  'return api.message.commit()')
        held = None
        for index, data in enumerate((HEAD + WIRE[:6], WIRE[6:-1], WIRE[-1:])):
            info = {'side': 'R', 'content': base64.b64encode(data).decode()}
            if index == 0:
                info['content_annotations'] = [[0, 17, 'http1.start_line'],
                                               [17, len(HEAD), 'http1.headers']]
            request = {'script': script, 'hold_allowed': True, 'held_parts': held,
                       'instance': {'mode': 'flow'}, 'event': {'id': 'chunked', 'details': {'info': info}}}
            run = subprocess.run([sys.executable, '-I', '-c', worker], input=json.dumps(request),
                                 capture_output=True, text=True, check=True, timeout=10)
            result = json.loads(run.stdout)
            self.assertTrue(result['ok'], result)
            held = result['held_parts']
            if index < 2:
                self.assertTrue(result['need_more'])
                self.assertEqual(result['replacement'], '')
        self.assertIsNone(held)
        self.assertEqual(peer_body(base64.b64decode(result['replacement'])), b'changed body')


if __name__ == '__main__':
    unittest.main()
