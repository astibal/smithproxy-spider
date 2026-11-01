"""Completed addon interception uses native Parts in either callback direction."""
from collections import deque
from dataclasses import replace
import unittest
import base64
import subprocess
import json
from pathlib import Path

import hpack
import h2.events

from addon_parts_test import H2, ApiConnection, AddonGeneration, H2AddonEvents, Peers, AddonMessageError
from inspection_h2_test import frame
from inspection_protocol_state import H2StateTable
from inspection_api import CommitException


SCRIPT = '''
saved = None
events = []

def request(flow):
    global saved
    events.append(('request', flow.request.path))
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()
    elif flow.request.path == '/release':
        saved.request.content = b'changed after intercept'
        saved.resume()
    elif flow.request.path == '/kill':
        saved.kill()
    elif flow.request.path == '/release-response':
        saved.response.content = b'edited response'
        saved.resume()

def response(flow):
    global saved
    events.append(('response', flow.request.path))
    if flow.request.path == '/wait-response':
        saved = flow
        flow.intercept()
        return
    saved.request.content = b'changed from response'
    saved.resume()

def error(flow):
    events.append(('error', flow.request.path))
'''


class AddonSuspensionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.addon = AddonGeneration(SCRIPT, H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        self.peers = Peers()

    async def asyncTearDown(self):
        self.driver.release_connection('test')
        await self.addon.close()

    async def pump(self, side, wire, *, peers=None, connection_id='test'):
        if peers is None:
            peers = self.peers
        queue = deque([(side, wire, None)])
        while queue:
            source, data, _ = queue.popleft()
            message = peers.bridge.message(source, data)
            result, failures = await self.driver.translate(
                connection_id, source, message, self.http2_view(source, message),
                ApiConnection(message), None, None,
            )
            self.assertEqual(failures, ())
            forward = peers.bridge.accept(source, message, result)
            peers.deliver('R' if source == 'L' else 'L', forward, queue)
            peers.deliver(source, peers.bridge.reverse, queue)

    def http2_view(self, side, message):
        return H2

    async def request(self, stream, path):
        client = self.peers.peers['L']
        client.send_headers(stream, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', path),
        ], end_stream=True)
        await self.pump('L', client.data_to_send())

    def events(self):
        return self.addon.addon.module.events

    async def test_later_request_resumes_and_edits_without_replaying_hook(self):
        await self.request(1, '/wait')
        self.assertEqual(self.peers.received['R'], [])
        await self.request(3, '/release')
        self.assertEqual(self.peers.received['R'], [b'changed after intercept'])
        self.assertEqual(self.events(), [('request', '/wait'), ('request', '/release')])
        self.assertNotIn('suspension', self.peers.bridge.control)

    async def test_response_callback_resumes_request_through_reverse_output(self):
        await self.request(1, '/trigger')
        await self.request(3, '/wait')
        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '204')], end_stream=True)
        await self.pump('R', server.data_to_send())
        self.assertEqual(self.peers.received['R'], [b'changed from response'])
        self.assertEqual(self.events(), [
            ('request', '/trigger'), ('request', '/wait'), ('response', '/trigger'),
        ])
        self.assertNotIn('suspension', self.peers.bridge.control)

    async def test_kill_discards_intercepted_request_and_delivers_error_once(self):
        await self.request(1, '/wait')
        await self.request(3, '/kill')
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.events(), [
            ('request', '/wait'), ('request', '/kill'), ('error', '/wait'),
        ])
        self.assertIsNone(self.addon.get_flow('test', 1))

    async def test_request_callback_resumes_intercepted_response(self):
        await self.request(1, '/wait-response')
        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '200')], end_stream=True)
        await self.pump('R', server.data_to_send())
        self.assertEqual(self.peers.received['L'], [])
        await self.request(3, '/release-response')
        self.assertEqual(self.peers.received['L'], [b'edited response'])
        self.assertEqual(self.events(), [
            ('request', '/wait-response'), ('response', '/wait-response'),
            ('request', '/release-response'),
        ])
        self.assertIsNone(self.addon.get_flow('test', 1))

    async def test_peer_reset_discards_intercepted_request(self):
        await self.request(1, '/wait')
        self.peers.peers['L'].reset_stream(1)
        await self.pump('L', self.peers.peers['L'].data_to_send())
        self.assertEqual(self.peers.received['R'], [])
        self.assertIsNone(self.addon.get_flow('test', 1))
        self.assertNotIn('suspension', self.peers.bridge.control)
        self.assertEqual(self.events(), [('request', '/wait'), ('error', '/wait')])

    async def test_other_connection_can_request_resume_but_cannot_publish_it(self):
        await self.request(1, '/wait')
        other = Peers()
        other.peers['L'].send_headers(1, [
            (':method', 'GET'), (':scheme', 'https'),
            (':authority', 'other.test'), (':path', '/release'),
        ], end_stream=True)
        try:
            # The script state is shared, but each connection owns its output
            # context. Matching stream IDs must not cross that boundary.
            await self.pump('L', other.peers['L'].data_to_send(),
                            peers=other, connection_id='other')
            self.assertFalse(self.addon.addon.module.saved.intercepted)
            self.assertEqual(self.peers.ended['R'], [])
            self.assertEqual(other.received['R'], [])
            self.assertEqual(other.ended['R'], [1])

            # An ordinary control frame on the owning connection is enough;
            # the request hook must not be invoked a second time.
            self.peers.peers['L'].ping(b'wake-own')
            await self.pump('L', self.peers.peers['L'].data_to_send())
            self.assertEqual(self.peers.received['R'], [b'changed after intercept'])
            self.assertEqual(self.peers.ended['R'], [1])
            self.assertEqual(self.events(), [('request', '/wait'), ('request', '/release')])
        finally:
            self.driver.release_connection('other')

    async def test_repeated_resume_does_not_publish_the_message_twice(self):
        await self.request(1, '/wait')
        await self.request(3, '/release')
        saved = self.addon.addon.module.saved
        saved.resume()
        saved.resume()
        self.peers.peers['L'].ping(b'no-retry')
        await self.pump('L', self.peers.peers['L'].data_to_send())
        self.assertEqual(self.peers.received['R'], [b'changed after intercept'])
        self.assertEqual(self.peers.ended['R'].count(1), 1)
        self.assertEqual(self.events(), [('request', '/wait'), ('request', '/release')])

    async def test_retired_flow_cannot_publish_into_a_reused_connection_id(self):
        await self.request(1, '/wait')
        retired = self.addon.addon.module.saved
        self.driver.release_connection('test')
        self.assertIsNone(self.addon.get_flow('test', 1))

        # A script can retain the old public object. Resuming it must not
        # resurrect its binding when the transport starts a fresh connection.
        retired.resume()
        self.peers = Peers()
        await self.request(1, '/trigger')
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.peers.ended['R'], [1])
        current = self.addon.get_flow('test', 1)
        self.assertIsNot(current, retired)
        self.assertEqual(current.request.path, '/trigger')
        self.assertEqual(self.events(), [('request', '/wait'), ('request', '/trigger')])

    async def test_intercepted_generated_response_is_not_silently_published(self):
        await self.addon.close()
        source = '''
from mitmproxy import http
saved = None
def request(flow):
    global saved
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()
    else:
        saved.response = http.Response.make(200, b'private')
        saved.resume()
def response(flow):
    flow.intercept()
'''
        self.addon = AddonGeneration(source, H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        await self.request(1, '/wait')
        await self.request(3, '/release')
        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.addon.state, 'running')
        self.assertTrue(self.addon.addon.module.saved.intercepted)

        # Resume a second time: response() must not be replayed and intercept
        # again. A real callback of the owning connection drives publication.
        self.addon.addon.module.saved.resume()
        await self.pump('L', frame(b'12345678', 6, 0, 0))
        self.assertEqual(self.peers.received['L'], [b'private'])


class PackagedSuspensionTests(unittest.TestCase):
    def test_persistent_worker_returns_then_resumes_without_replaying_hook(self):
        self.check_worker(SCRIPT, fragmented=False)

    def test_persistent_worker_retains_partial_header_interception(self):
        self.check_worker(HEADER_SCRIPT, fragmented=True)

    def test_persistent_worker_resumes_generated_response(self):
        self.check_worker(LOCAL_RESPONSE_SCRIPT, fragmented=False, local=True)

    def check_worker(self, script, *, fragmented, local=False):
        import addon_worker_test as worker_tools

        process = subprocess.Popen(
            worker_tools.worker_command('--persistent'), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        peers = Peers()
        encoder = hpack.Encoder()
        calls = iter(range(100))

        def exchange(request):
            if 'script' not in request:
                request['_request_id'] = next(calls)
            return worker_tools.AddonWorkerTests.exchange(self, process, request)

        try:
            ready = exchange({'script': '#!mitmproxy\n' + script})
            self.assertTrue(ready['ready'])
            setup = exchange(worker_tools.callback('test', 'connection-start'))
            self.assertTrue(setup['ok'], setup)
            protocol_state = setup['protocol_state']
            tables = peers.bridge.tables.copy()
            control = peers.bridge.control
            reserved = False
            held = None
            output = b''
            reverse_output = b''
            inputs = []
            first_path = b'/headers/resume' if local else b'/wait'
            for stream, path in ((1, first_path), (3, b'/release')):
                flags = 4 if fragmented and stream == 1 else 5
                fields = [
                    (b':method', b'POST'), (b':scheme', b'https'),
                    (b':authority', b'example.test'), (b':path', path),
                ]
                if local:
                    peers.peers['L'].send_headers(stream, fields, end_stream=True)
                    peers.peers['L'].data_to_send()
                wire = frame(encoder.encode(fields), 1, flags, stream)
                inputs.append((stream, wire))
                if fragmented and stream == 1:
                    inputs.append((stream, frame(b'private', 0, 1, stream)))

            for stream, wire in inputs:
                request = worker_tools.callback('test', 'connection-content', wire)
                request.update(
                    translate_allowed=False, translate_active=True,
                    translate_state=tables['L'], peer_translate_state=tables['R'],
                    translate_control=control, hold_credit_reserved=reserved,
                    protocol_state=protocol_state, held_parts=held,
                )
                result = exchange(request)
                self.assertTrue(result['ok'], result)
                tables['L'] = result['translate_state']
                if 'peer_translate_state' in result:
                    tables['R'] = result['peer_translate_state']
                control = result['translate_control']
                reserved = result.get('hold_credit_reservation', False)
                protocol_state = result['protocol_state']
                held = result.get('held_parts')
                current = base64.b64decode(result['replacement'] or '')
                reverse_output += base64.b64decode(result.get('replacement_reverse') or '')
                if stream == 1:
                    self.assertEqual(current, b'')
                    if held is None:
                        self.assertIn('suspension', control)
                    if local:
                        self.assertEqual(reverse_output, b'')
                output += current
            events = peers.peers['R'].receive_data(output)
            self.assertEqual([event.stream_id for event in events
                              if isinstance(event, h2.events.RequestReceived)],
                             [3] if local else [1, 3])
            expected = b'private' if fragmented else b'changed after intercept'
            self.assertEqual([event.data for event in events
                              if isinstance(event, h2.events.DataReceived)], [] if local else [expected])
            if local:
                response_events = peers.peers['L'].receive_data(reverse_output)
                self.assertEqual([event.data for event in response_events
                                  if isinstance(event, h2.events.DataReceived)],
                                 [b'edited while held'])
            self.assertNotIn('suspension', control)
        finally:
            if process.stdin is not None:
                process.stdin.close()
                process.stdin = None
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


HEADER_SCRIPT = '''
saved = None
events = []

def requestheaders(flow):
    global saved
    events.append(('headers', flow.request.path, flow.request.raw_content))
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()

def request(flow):
    events.append(('request', flow.request.path, flow.request.raw_content))
    if flow.request.path == '/release':
        saved.request.headers['x-resumed'] = 'yes'
        saved.resume()
    elif flow.request.path == '/kill':
        saved.kill()

def response(flow):
    events.append(('response', flow.request.path))
    saved.resume()

def error(flow):
    events.append(('error', flow.request.path))
'''


class HeaderSuspensionTests(unittest.IsolatedAsyncioTestCase):
    pump = AddonSuspensionTests.pump
    request = AddonSuspensionTests.request
    asyncTearDown = AddonSuspensionTests.asyncTearDown

    async def asyncSetUp(self):
        self.addon = AddonGeneration(HEADER_SCRIPT, H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        self.peers = Peers()
        self.states = H2StateTable()

    def http2_view(self, side, message):
        self.states.observe(side, message.parts, restored=True)
        return replace(H2, state=self.states.snapshot())

    async def test_resume_delivers_message_hook_once_after_headers(self):
        await self.request(1, '/wait')

        saved = self.addon.addon.module.saved
        self.assertIsNone(saved.request.raw_content)
        self.assertEqual(self.peers.ended['R'], [])
        self.assertEqual(self.addon.addon.module.events, [('headers', '/wait', None)])

        await self.request(3, '/release')

        self.assertIs(self.addon.get_flow('test', 1), saved)
        self.assertEqual(saved.request.headers['x-resumed'], 'yes')
        self.assertEqual(self.peers.ended['R'].count(1), 1)
        headers = [
            event.headers for event in self.peers.events['R']
            if isinstance(event, h2.events.RequestReceived) and event.stream_id == 1
        ]
        self.assertEqual(len(headers), 1)
        self.assertIn((b'x-resumed', b'yes'), headers[0])

        self.assertEqual(self.addon.addon.module.events, [
            ('headers', '/wait', None),
            ('headers', '/release', None),
            ('request', '/release', b''),
            ('request', '/wait', b''),
        ])

        self.peers.peers['L'].ping(b'no-retry')
        await self.pump('L', self.peers.peers['L'].data_to_send())
        self.assertEqual(len(self.addon.addon.module.events), 4)

    async def test_reverse_callback_resumes_header_interception(self):
        await self.request(1, '/trigger')
        await self.request(3, '/wait')

        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '204')], end_stream=True)
        await self.pump('R', server.data_to_send())

        self.assertEqual(self.peers.ended['R'].count(3), 1)
        self.assertEqual(self.addon.addon.module.events[-2:], [
            ('response', '/trigger'), ('request', '/wait', b''),
        ])

    async def test_kill_does_not_deliver_deferred_message_hook(self):
        await self.request(1, '/wait')
        await self.request(3, '/kill')

        events = self.addon.addon.module.events
        self.assertNotIn(('request', '/wait', b''), events)
        self.assertEqual(events.count(('error', '/wait')), 1)
        self.assertNotIn(1, self.peers.ended['R'])

    async def test_buffered_body_stays_native_until_resume(self):
        client = self.peers.peers['L']
        client.send_headers(1, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/wait'),
        ])
        client.send_data(1, b'private body', end_stream=True)
        await self.pump('L', client.data_to_send())

        self.assertIsNone(self.addon.addon.module.saved.request.raw_content)
        self.assertEqual(self.peers.received['R'], [])

        await self.request(3, '/release')

        self.assertEqual(self.peers.received['R'], [b'private body'])
        self.assertIn(('request', '/wait', b'private body'), self.addon.addon.module.events)

    async def start_partial_request(self, *, size=None):
        client = self.peers.peers['L']
        headers = [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/wait'),
        ]
        if size is not None:
            headers.append(('content-length', str(size)))

        client.send_headers(1, headers)
        await self.pump('L', client.data_to_send())
        return client

    async def test_partial_body_stays_hidden_until_complete_and_resumed(self):
        client = await self.start_partial_request()
        client.send_data(1, b'first')
        await self.pump('L', client.data_to_send())

        self.assertEqual(self.peers.ended['R'], [])
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.addon.addon.module.events, [('headers', '/wait', None)])
        self.assertIsNone(self.addon.addon.module.saved.request.raw_content)

        client.send_data(1, b'last', end_stream=True)
        await self.pump('L', client.data_to_send())
        self.assertEqual(self.addon.addon.module.events, [('headers', '/wait', None)])
        self.assertIsNone(self.addon.addon.module.saved.request.raw_content)

        await self.request(3, '/release')
        self.assertEqual(b''.join(self.peers.received['R']), b'firstlast')
        self.assertEqual(self.addon.addon.module.events[-1], ('request', '/wait', b'firstlast'))

    async def test_resume_before_body_end_finishes_in_last_data_callback(self):
        client = await self.start_partial_request()
        await self.request(3, '/release')
        self.assertFalse(self.addon.addon.module.saved.intercepted)
        self.assertIsNone(self.addon.addon.module.saved.request.raw_content)

        client.send_data(1, b'complete', end_stream=True)
        await self.pump('L', client.data_to_send())

        # No extra ping or unrelated callback is needed to publish the body.
        self.assertEqual(b''.join(self.peers.received['R']), b'complete')
        self.assertEqual(self.peers.ended['R'].count(1), 1)
        events = self.addon.addon.module.events
        self.assertEqual(events.count(('headers', '/wait', None)), 1)
        self.assertEqual(events.count(('request', '/wait', b'complete')), 1)

    async def test_intercepted_large_body_has_bounded_credit_without_deadlock(self):
        size = 128 * 1024
        client = await self.start_partial_request(size=size)
        remaining = size

        while remaining:
            count = min(16000, remaining, client.local_flow_control_window(1))
            self.assertGreater(count, 0, 'Header interception must not exhaust input credit')
            remaining -= count
            client.send_data(1, b'x' * count, end_stream=remaining == 0)
            await self.pump('L', client.data_to_send())

        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.addon.addon.module.events, [('headers', '/wait', None)])

        await self.request(3, '/release')

        self.assertEqual(b''.join(self.peers.received['R']), b'x' * size)
        self.assertEqual(self.peers.ended['R'].count(1), 1)
        self.assertFalse(self.peers.bridge.reserved)

    async def test_final_body_and_resume_in_same_batch_do_not_stage_conflicting_commands(self):
        client = await self.start_partial_request()
        client.send_data(1, b'complete', end_stream=True)
        client.send_headers(3, [
            (':method', 'GET'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/release'),
        ], end_stream=True)
        await self.pump('L', client.data_to_send())

        self.assertEqual(b''.join(self.peers.received['R']), b'complete')
        self.assertEqual(self.peers.ended['R'], [1, 3])
        events = self.addon.addon.module.events
        self.assertEqual(events.count(('headers', '/wait', None)), 1)
        self.assertEqual(events.count(('request', '/wait', b'complete')), 1)
        self.assertNotIn('suspension', self.peers.bridge.control)

    async def test_reverse_resume_during_reception_waits_only_for_body_end(self):
        await self.request(1, '/trigger')
        client = self.peers.peers['L']
        client.send_headers(3, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/wait'),
        ])
        await self.pump('L', client.data_to_send())

        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '204')], end_stream=True)
        await self.pump('R', server.data_to_send())
        self.assertFalse(self.addon.addon.module.saved.intercepted)

        client.send_data(3, b'last', end_stream=True)
        await self.pump('L', client.data_to_send())

        self.assertEqual(self.peers.received['R'], [b'last'])
        self.assertEqual(self.peers.ended['R'].count(3), 1)

    async def test_response_headers_resume_from_request_callback(self):
        await self.check_response_headers_resume(fragmented=False)

    async def test_partial_response_resumes_before_last_body_fragment(self):
        await self.check_response_headers_resume(fragmented=True)

    async def check_response_headers_resume(self, *, fragmented):
        await self.addon.close()
        self.addon = AddonGeneration('''
saved = None
events = []
def request(flow):
    if flow.request.path == '/release':
        saved.resume()
def responseheaders(flow):
    global saved
    saved = flow
    events.append(('headers', flow.response.raw_content))
    flow.intercept()
def response(flow):
    events.append(('response', flow.response.raw_content))
    flow.response.content = b'edited'
''', H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        await self.request(1, '/trigger')

        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '200')])
        if fragmented:
            server.send_data(1, b'ori')
        else:
            server.send_data(1, b'original', end_stream=True)
        await self.pump('R', server.data_to_send())

        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.addon.addon.module.events, [('headers', None)])

        await self.request(3, '/release')

        if fragmented:
            self.assertEqual(self.peers.received['L'], [])
            self.assertEqual(self.addon.addon.module.events, [('headers', None)])
            server.send_data(1, b'ginal', end_stream=True)
            await self.pump('R', server.data_to_send())

        self.assertEqual(b''.join(self.peers.received['L']), b'edited')
        self.assertEqual(self.addon.addon.module.events, [
            ('headers', None), ('response', b'original'),
        ])

    async def test_fragmented_frame_does_not_deliver_body_early(self):
        client = await self.start_partial_request()
        client.send_data(1, b'fragmented', end_stream=True)
        wire = client.data_to_send()

        for byte in wire:
            await self.pump('L', bytes([byte]))
            self.assertIsNone(self.addon.addon.module.saved.request.raw_content)
            self.assertEqual(self.peers.received['R'], [])

        await self.request(3, '/release')

        self.assertEqual(self.peers.received['R'], [b'fragmented'])
        self.assertEqual(self.addon.addon.module.events.count(('headers', '/wait', None)), 1)

    async def test_resume_waits_for_trailers_to_complete_the_message(self):
        client = await self.start_partial_request()
        client.send_data(1, b'body')
        await self.pump('L', client.data_to_send())
        await self.request(3, '/release')

        saved = self.addon.addon.module.saved
        self.assertIsNone(saved.request.raw_content)
        self.assertIsNone(saved.request.trailers)
        client.send_headers(1, [('x-finished', 'yes')], end_stream=True)
        await self.pump('L', client.data_to_send())

        self.assertEqual(saved.request.trailers['x-finished'], 'yes')
        self.assertEqual(self.peers.received['R'], [b'body'])
        trailers = next(
            event.headers for event in self.peers.events['R']
            if isinstance(event, h2.events.TrailersReceived) and event.stream_id == 1
        )
        self.assertEqual(trailers, [(b'x-finished', b'yes')])

    async def test_interception_keeps_existing_body_reservation_limit(self):
        self.driver = H2AddonEvents(self.addon, body_limit=8)
        client = await self.start_partial_request()
        client.send_data(1, b'too large', end_stream=True)

        with self.assertRaises(CommitException):
            await self.pump('L', client.data_to_send())

        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.peers.ended['R'], [])
        self.assertEqual(self.addon.state, 'failed')

    async def test_reset_during_body_reception_releases_native_reservation(self):
        client = await self.start_partial_request()
        client.send_data(1, b'unfinished')
        await self.pump('L', client.data_to_send())
        client.reset_stream(1, error_code=8)
        await self.pump('L', client.data_to_send())

        self.assertEqual(self.addon.addon.module.events, [
            ('headers', '/wait', None), ('error', '/wait'),
        ])
        self.assertEqual(self.peers.received['R'], [])
        self.assertIsNone(self.addon.get_flow('test', 1))
        self.assertFalse(self.peers.bridge.reserved)

    async def test_kill_partial_request_from_later_request_callback(self):
        client = await self.start_partial_request()
        client.send_data(1, b'must not escape')
        await self.pump('L', client.data_to_send())

        await self.request(3, '/kill')

        self.assertIsNone(self.addon.get_flow('test', 1))
        self.assertEqual(self.peers.received['R'], [])
        self.assertFalse(self.peers.bridge.reserved)
        self.assertEqual(self.addon.addon.module.events.count(('error', '/wait')), 1)
        self.assertFalse(any(event[:2] == ('request', '/wait')
                             for event in self.addon.addon.module.events))
        resets = [event for event in self.peers.events['L']
                  if isinstance(event, h2.events.StreamReset) and event.stream_id == 1]
        self.assertEqual(len(resets), 1)
        self.assertEqual(resets[0].error_code, 2)

    async def test_kill_partial_request_from_opposite_callback(self):
        await self.check_reverse_kill(fragmented_frame=False)

    async def test_reverse_kill_with_incomplete_data_frame(self):
        await self.check_reverse_kill(fragmented_frame=True)

    async def check_reverse_kill(self, *, fragmented_frame):
        await self.addon.close()
        script = HEADER_SCRIPT.replace(
            "events.append(('response', flow.request.path))\n    saved.resume()",
            "events.append(('response', flow.request.path))\n    saved.kill()",
        )
        self.addon = AddonGeneration(script, H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)

        # A separate live stream supplies the response callback. The held
        # request never needs another byte to settle its kill.
        await self.request(1, '/trigger')
        client = self.peers.peers['L']
        client.send_headers(3, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/wait'),
        ])
        client.send_data(3, b'must not escape')
        wire = client.data_to_send()
        tail = b''
        if fragmented_frame:
            wire, tail = wire[:-4], wire[-4:]
        await self.pump('L', wire)

        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '204')], end_stream=True)
        await self.pump('R', server.data_to_send())

        self.assertIsNone(self.addon.get_flow('test', 3))
        self.assertFalse(self.peers.bridge.reserved)
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.addon.addon.module.events.count(('error', '/wait')), 1)
        resets = [event for event in self.peers.events['L']
                  if isinstance(event, h2.events.StreamReset) and event.stream_id == 3]
        self.assertEqual(len(resets), 1)

        if tail:
            await self.pump('L', tail)
            self.assertEqual(self.peers.received['R'], [])
            self.assertEqual(self.addon.addon.module.events.count(('error', '/wait')), 1)

        # A later source block may reference the killed request's HPACK table.
        # Its source-only header tombstone must preserve that conversation.
        await self.request(5, '/after')
        self.assertIn(('request', '/after', b''), self.addon.addon.module.events)

    async def test_kill_partial_response_from_request_callback(self):
        await self.addon.close()
        self.addon = AddonGeneration('''
saved = None
events = []
def request(flow):
    if flow.request.path == '/kill':
        saved.kill()
def responseheaders(flow):
    global saved
    saved = flow
    flow.intercept()
def response(flow):
    events.append('unexpected response')
def error(flow):
    events.append('error')
''', H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        await self.request(1, '/trigger')

        server = self.peers.peers['R']
        server.send_headers(1, [(':status', '200')])
        server.send_data(1, b'private partial response')
        await self.pump('R', server.data_to_send())
        await self.request(3, '/kill')

        self.assertEqual(self.addon.addon.module.events, ['error'])
        self.assertIsNone(self.addon.get_flow('test', 1))
        self.assertEqual(self.peers.received['L'], [])
        self.assertFalse(self.peers.bridge.reserved)
        resets = [event for event in self.peers.events['L']
                  if isinstance(event, h2.events.StreamReset) and event.stream_id == 1]
        self.assertEqual(len(resets), 1)

        # Already in-flight source DATA is consumed, not delivered or turned
        # into another hook. Sibling responses still use the same HPACK context.
        server.send_data(1, b'late source bytes', end_stream=True)
        await self.pump('R', server.data_to_send())
        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.addon.addon.module.events, ['error'])

    async def test_second_intercept_keeps_native_hold_and_does_not_replay_hooks(self):
        await self.addon.close()
        self.addon = AddonGeneration(HEADER_SCRIPT + '''
original_request = request
def request(flow):
    original_request(flow)
    if flow.request.path == '/wait':
        flow.intercept()
''', H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        await self.request(1, '/wait')

        original = self.peers.bridge.control['suspension']
        await self.request(3, '/release')

        self.assertEqual(self.peers.ended['R'], [])
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.addon.state, 'running')
        self.assertTrue(self.addon.addon.module.saved.intercepted)
        current = self.peers.bridge.control['suspension']
        self.assertEqual(current['L']['paused'], original['L']['paused'])

        await self.request(5, '/release')

        events = self.addon.addon.module.events
        self.assertEqual(events.count(('headers', '/wait', None)), 1)
        self.assertEqual(events.count(('request', '/wait', b'')), 1)
        self.assertEqual(self.peers.ended['R'].count(1), 1)
        self.assertNotIn('suspension', self.peers.bridge.control)

    async def test_reset_retires_header_without_delivering_message_hook(self):
        await self.request(1, '/wait')
        client = self.peers.peers['L']
        client.reset_stream(1, error_code=8)
        await self.pump('L', client.data_to_send())

        self.assertEqual(self.addon.addon.module.events, [
            ('headers', '/wait', None), ('error', '/wait'),
        ])
        self.assertIsNone(self.addon.get_flow('test', 1))
        self.assertEqual(self.peers.ended['R'], [])

    async def test_replaced_header_object_receives_body_before_deferred_hook(self):
        client = self.peers.peers['L']
        client.send_headers(1, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/wait'),
        ])
        client.send_data(1, b'original', end_stream=True)
        await self.pump('L', client.data_to_send())

        saved = self.addon.addon.module.saved
        replacement = saved.request.copy()
        replacement.headers['x-replaced'] = 'yes'
        saved.request = replacement
        await self.request(3, '/release')

        self.assertIs(saved.request, replacement)
        self.assertIn(('request', '/wait', b'original'), self.addon.addon.module.events)
        self.assertEqual(self.peers.received['R'], [b'original'])
        headers = next(
            event.headers for event in self.peers.events['R']
            if isinstance(event, h2.events.RequestReceived) and event.stream_id == 1
        )
        self.assertIn((b'x-replaced', b'yes'), headers)

    async def test_missing_native_state_cannot_enable_header_interception(self):
        self.http2_view = lambda side, message: H2

        with self.assertRaisesRegex(AddonMessageError, 'interception'):
            await self.request(1, '/wait')

        self.assertEqual(self.peers.ended['R'], [])
        self.assertEqual(self.addon.state, 'failed')


LOCAL_RESPONSE_SCRIPT = '''
from mitmproxy import http
saved = None
events = []

def report(hook, flow):
    events.append({
        'hook': hook, 'path': flow.request.path,
        'body': flow.response.raw_content.decode('ascii'),
        'error': None if flow.error is None else flow.error.msg,
    })

def release():
    if saved.request.path.endswith('/kill'):
        saved.kill()
    else:
        saved.response.content = b'edited while held'
        saved.resume()
    report('released', saved)

def request(flow):
    global saved
    if flow.request.path == '/release':
        release()
    elif flow.request.path != '/trigger':
        saved = flow
        flow.response = http.Response.make(200, b'local original')
        report('request', flow)

def responseheaders(flow):
    if flow.request.path == '/trigger':
        return
    report('responseheaders', flow)
    if flow.request.path.startswith(('/headers/', '/both/')):
        flow.intercept()

def response(flow):
    if flow.request.path == '/trigger':
        release()
        return
    report('response', flow)
    if flow.request.path.startswith(('/response/', '/both/')):
        flow.intercept()

def error(flow):
    report('error', flow)
'''


class LocalResponseSuspensionTests(unittest.IsolatedAsyncioTestCase):
    pump = AddonSuspensionTests.pump
    request = AddonSuspensionTests.request
    http2_view = AddonSuspensionTests.http2_view
    asyncTearDown = AddonSuspensionTests.asyncTearDown

    async def asyncSetUp(self):
        self.addon = AddonGeneration(LOCAL_RESPONSE_SCRIPT, H2AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H2AddonEvents(self.addon)
        self.peers = Peers()

    async def check_reference_resume(self, stage, *, reverse=False):
        reference = json.loads(Path(__file__).with_name('corpus').joinpath(
            'addon_local_intercept_h2_v12.json').read_text())
        path = '/' + stage + '/resume'
        stream = 3 if reverse else 1
        if reverse:
            await self.request(1, '/trigger')
        await self.request(stream, path)

        self.assertEqual(self.peers.received['L'], [])
        self.assertNotIn(stream, self.peers.ended['R'])
        self.assertTrue(self.addon.addon.module.saved.intercepted)

        if reverse:
            server = self.peers.peers['R']
            server.send_headers(1, [(':status', '204')], end_stream=True)
            await self.pump('R', server.data_to_send())
        else:
            await self.request(3, '/release')

        expected = reference['responses'][path]
        self.assertEqual(b''.join(self.peers.received['L']).decode(), expected['body'])
        self.assertEqual(self.peers.ended['L'].count(stream), 1)
        self.assertIsNone(self.addon.get_flow('test', stream))
        self.assertEqual(self.addon.addon.module.events,
                         [event for event in reference['hooks'] if event['path'] == path])
        self.assertFalse(self.peers.bridge.reserved)

    async def test_header_resume_matches_reference(self):
        await self.check_reference_resume('headers')

    async def test_response_resume_matches_reference(self):
        await self.check_reference_resume('response')

    async def test_header_resume_from_opposite_callback_matches_reference(self):
        await self.check_reference_resume('headers', reverse=True)

    async def test_response_resume_from_opposite_callback_matches_reference(self):
        await self.check_reference_resume('response', reverse=True)

    async def check_local_kill(self, stage, *, reverse=False):
        reference = json.loads(Path(__file__).with_name('corpus').joinpath(
            'addon_local_intercept_h2_v12.json').read_text())
        path = '/' + stage + '/kill'
        reference_path = '/' + stage + '/resume-kill'
        stream = 3 if reverse else 1
        if reverse:
            await self.request(1, '/trigger')
        await self.request(stream, path)

        if reverse:
            server = self.peers.peers['R']
            server.send_headers(1, [(':status', '204')], end_stream=True)
            await self.pump('R', server.data_to_send())
        else:
            await self.request(3, '/release')

        # Deliberate difference: kill alone must not inherit the reference's
        # lost wakeup. Its resume-then-kill trace supplies the terminal contract.
        self.assertTrue(reference['responses'][path]['pending'])
        expected = reference['responses'][reference_path]
        resets = [event for event in self.peers.events['L']
                  if isinstance(event, h2.events.StreamReset) and event.stream_id == stream]
        self.assertEqual([int(event.error_code) for event in resets], [expected['reset']])
        self.assertEqual(self.peers.received['L'], [])
        self.assertNotIn(stream, self.peers.ended['R'])
        expected_hooks = [dict(event, path=path) for event in reference['hooks']
                          if event['path'] == reference_path]
        self.assertEqual(self.addon.addon.module.events, expected_hooks)
        self.assertIsNone(self.addon.get_flow('test', stream))
        self.assertFalse(self.peers.bridge.reserved)

    async def test_kill_at_local_headers_resets_and_delivers_error_once(self):
        await self.check_local_kill('headers')

    async def test_kill_at_local_response_resets_without_error_hook(self):
        await self.check_local_kill('response')

    async def test_reverse_kill_at_local_headers(self):
        await self.check_local_kill('headers', reverse=True)

    async def test_reverse_kill_at_local_response(self):
        await self.check_local_kill('response', reverse=True)

    async def test_response_hook_can_intercept_after_header_resume(self):
        await self.request(1, '/both/resume')
        await self.request(3, '/release')

        self.assertEqual(self.peers.received['L'], [])
        self.assertTrue(self.addon.addon.module.saved.intercepted)
        await self.request(5, '/release')

        self.assertEqual(self.peers.received['L'], [b'edited while held'])
        self.assertEqual([item['hook'] for item in self.addon.addon.module.events], [
            'request', 'responseheaders', 'released', 'response', 'released',
        ])
        self.assertFalse(self.peers.bridge.reserved)

    async def test_source_reset_discards_generated_response(self):
        await self.request(1, '/headers/resume')
        client = self.peers.peers['L']
        client.reset_stream(1, error_code=8)
        await self.pump('L', client.data_to_send())

        self.assertEqual(self.peers.received['L'], [])
        self.assertIsNone(self.addon.get_flow('test', 1))
        self.assertEqual([item['hook'] for item in self.addon.addon.module.events], [
            'request', 'responseheaders', 'error',
        ])
        self.assertFalse(self.peers.bridge.reserved)

    async def test_held_response_replacement_and_trailers_use_native_output(self):
        await self.request(1, '/response/resume')
        flow = self.addon.addon.module.saved
        replacement = type(flow.response).make(202, b'replaced', {'x-local': 'yes'})
        replacement.trailers = type(replacement.headers)([(b'x-end', b'complete')])
        flow.response = replacement
        flow.resume()

        await self.pump('R', frame(b'12345678', 6, 0, 0))

        self.assertEqual(self.peers.received['L'], [b'replaced'])
        replies = [event for event in self.peers.events['L']
                   if isinstance(event, h2.events.ResponseReceived)]
        trailers = [event for event in self.peers.events['L']
                    if isinstance(event, h2.events.TrailersReceived)]
        self.assertIn((b':status', b'202'), replies[0].headers)
        self.assertEqual(trailers[0].headers, [(b'x-end', b'complete')])
        self.assertEqual([item['hook'] for item in self.addon.addon.module.events], [
            'request', 'responseheaders', 'response',
        ])

    async def test_resumed_local_body_exceeding_initial_window_drains(self):
        await self.request(1, '/response/resume')
        flow = self.addon.addon.module.saved
        flow.response.content = b'x' * (128 * 1024)
        flow.resume()

        await self.pump('R', frame(b'12345678', 6, 0, 0))

        self.assertEqual(b''.join(self.peers.received['L']), b'x' * (128 * 1024))
        self.assertEqual(self.peers.ended['L'].count(1), 1)
        self.assertFalse(self.peers.bridge.reserved)
        self.assertNotIn(1, self.peers.ended['R'])

    async def test_retained_local_body_is_bounded(self):
        self.driver.body_limit = 4
        with self.assertRaisesRegex(AddonMessageError, 'retained body limit'):
            await self.request(1, '/headers/resume')
        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.addon.state, 'failed')

    async def test_local_resume_behind_incomplete_prefix_does_not_replay_hooks(self):
        await self.check_blocked_prefix(kill=False)

    async def test_local_kill_behind_incomplete_prefix_keeps_response_hook_identity(self):
        await self.check_blocked_prefix(kill=True)

    async def check_blocked_prefix(self, *, kill):
        client = self.peers.peers['L']
        client.send_headers(1, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/trigger'),
            ('content-length', '2'),
        ])
        await self.pump('L', client.data_to_send())
        path = '/headers/kill' if kill else '/headers/resume'
        await self.request(3, path)
        await self.request(5, '/release')
        self.assertEqual(self.peers.received['L'], [])

        # The older prefix owns ordering. Completing it must publish or
        # discard the local anchor without replaying either response hook.
        client.send_data(1, b'ok', end_stream=True)
        await self.pump('L', client.data_to_send())

        expected_body = [] if kill else [b'edited while held']
        expected_last_hook = 'error' if kill else 'response'
        self.assertEqual(self.peers.received['L'], expected_body)
        self.assertEqual([event['hook'] for event in self.addon.addon.module.events], [
            'request', 'responseheaders', 'released', expected_last_hook,
        ])
        self.assertIsNone(self.addon.get_flow('test', 3))

    async def test_local_native_publication_failure_invalidates_without_hook_replay(self):
        await self.request(1, '/response/resume')
        saved = self.addon.addon.module.saved
        saved.response.status_code = 100
        saved.resume()
        before = list(self.addon.addon.module.events)

        with self.assertRaises(CommitException):
            await self.pump('R', frame(b'12345678', 6, 0, 0))

        self.assertEqual(self.addon.addon.module.events, before)
        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.addon.state, 'failed')

    async def test_removing_intercepted_local_response_cannot_forward_request(self):
        await self.request(1, '/response/resume')
        saved = self.addon.addon.module.saved
        saved.response = None
        saved.resume()

        with self.assertRaisesRegex(AddonMessageError, 'retain the local HTTP Response'):
            await self.pump('R', frame(b'12345678', 6, 0, 0))
        self.assertEqual(self.peers.ended['R'], [])
        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.addon.state, 'failed')


if __name__ == '__main__':
    unittest.main()
