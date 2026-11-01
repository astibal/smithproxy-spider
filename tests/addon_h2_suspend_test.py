"""Completed addon interception uses native Parts in either callback direction."""
from collections import deque
import unittest
import base64
import subprocess

import hpack
import h2.events

from addon_parts_test import H2, ApiConnection, AddonGeneration, H2AddonEvents, Peers, AddonMessageError
from inspection_h2_test import frame


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
                connection_id, source, message, H2, ApiConnection(message), None, None,
            )
            self.assertEqual(failures, ())
            forward = peers.bridge.accept(source, message, result)
            peers.deliver('R' if source == 'L' else 'L', forward, queue)
            peers.deliver(source, peers.bridge.reverse, queue)

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
        with self.assertRaisesRegex(AddonMessageError, 'generated local responses'):
            await self.request(3, '/release')
        self.assertEqual(self.peers.received['L'], [])
        self.assertEqual(self.peers.received['R'], [])
        self.assertEqual(self.addon.state, 'failed')


class PackagedSuspensionTests(unittest.TestCase):
    def test_persistent_worker_returns_then_resumes_without_replaying_hook(self):
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
            ready = exchange({'script': '#!mitmproxy\n' + SCRIPT})
            self.assertTrue(ready['ready'])
            self.assertTrue(exchange(worker_tools.callback('test', 'connection-start'))['ok'])
            tables = peers.bridge.tables.copy()
            control = peers.bridge.control
            reserved = False
            output = b''
            for stream, path in ((1, b'/wait'), (3, b'/release')):
                wire = frame(encoder.encode([
                    (b':method', b'POST'), (b':scheme', b'https'),
                    (b':authority', b'example.test'), (b':path', path),
                ]), 1, 5, stream)
                request = worker_tools.callback('test', 'connection-content', wire)
                request.update(
                    translate_allowed=False, translate_active=True,
                    translate_state=tables['L'], peer_translate_state=tables['R'],
                    translate_control=control, hold_credit_reserved=reserved,
                )
                result = exchange(request)
                self.assertTrue(result['ok'], result)
                tables['L'] = result['translate_state']
                control = result['translate_control']
                reserved = result.get('hold_credit_reservation', False)
                current = base64.b64decode(result['replacement'])
                if stream == 1:
                    self.assertEqual(current, b'')
                    self.assertIn('suspension', control)
                output += current
            events = peers.peers['R'].receive_data(output)
            self.assertEqual([event.stream_id for event in events
                              if isinstance(event, h2.events.RequestReceived)], [1, 3])
            self.assertEqual([event.data for event in events
                              if isinstance(event, h2.events.DataReceived)], [b'changed after intercept'])
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


if __name__ == '__main__':
    unittest.main()
