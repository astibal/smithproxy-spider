"""HTTP/1 addon pauses use native ordered lanes, including peer publication."""

import copy
import gzip
import json
import unittest
from pathlib import Path

from addon_parts_test import AddonGeneration, H1AddonEvents
from inspection_api import CommitException, HeldCommit
import inspection_chunked_test as native_tests


def request(path):
    return b'GET ' + path.encode() + b' HTTP/1.1\r\nHost: example.test\r\n\r\n'


RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody'


class H1AddonSuspensionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.held = {'L': None, 'R': None}
        self.state = None
        self.addon = None
        self.driver = None

    async def asyncTearDown(self):
        if self.driver is not None:
            self.driver.release_connection('test')
        if self.addon is not None:
            await self.addon.close()

    async def start(self, source):
        self.addon = AddonGeneration(source, H1AddonEvents.HOOKS)
        await self.addon.start()
        self.driver = H1AddonEvents(self.addon)

    async def callback(self, side, *items):
        peer = 'R' if side == 'L' else 'L'
        message = native_tests.H1SuspensionTests().callback(
            side, *items, state=self.state,
            held=self.held[side], peer=self.held[peer])

        result, failures = await self.driver.rewrite(
            'test', side, message, None, None)
        self.assertEqual(failures, ())

        # Model the host's atomic checkpoint transfer, not a parallel buffer
        # owned by the compatibility driver.
        self.held[side] = result.checkpoint if isinstance(result, HeldCommit) else None
        transaction = message._h1_response
        self.last_termination = transaction.termination
        suspension = transaction.suspension
        if suspension.peer_hold_changed:
            self.held[peer] = suspension.peer_hold_result
        self.state = transaction.checkpoint

        forward = result.prefix if isinstance(result, HeldCommit) else result
        return forward, transaction.reverse_output

    async def test_response_resumes_edited_request_without_hook_replay(self):
        await self.start('''
events = []
saved = None
def request(flow):
    global saved
    events.append(('request', flow.request.path))
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()
def response(flow):
    events.append(('response', flow.request.path))
    if flow.request.path == '/first':
        saved.request.headers['x-resumed'] = 'yes'
        saved.resume()
''')
        forward, reverse = await self.callback('L', request('/first'), request('/wait'))
        self.assertEqual(forward, request('/first'))
        self.assertFalse(reverse)

        forward, reverse = await self.callback('R', RESPONSE)
        self.assertEqual(forward, RESPONSE)
        self.assertIn(b'x-resumed: yes\r\n', reverse)
        self.assertIn(b'GET /wait ', reverse)
        self.assertIsNone(self.held['L'])

        await self.callback('R', RESPONSE)
        self.assertEqual(self.addon.addon.module.events, [
            ('request', '/first'), ('request', '/wait'),
            ('response', '/first'), ('response', '/wait')])
        self.assertEqual(self.addon.active_flows, 0)

    async def test_request_resumes_edited_response(self):
        await self.start('''
saved = None
def response(flow):
    global saved
    saved = flow
    flow.intercept()
def request(flow):
    if flow.request.path == '/release':
        saved.response.content = b'edited response'
        saved.resume()
''')
        await self.callback('L', request('/first'))
        self.assertEqual(await self.callback('R', RESPONSE), (b'', b''))

        forward, reverse = await self.callback('L', request('/release'))
        self.assertEqual(forward, request('/release'))
        self.assertTrue(reverse.endswith(b'edited response'))
        self.assertIn(b'Content-Length: 15\r\n', reverse)
        self.assertIsNone(self.held['R'])

    async def test_younger_pipeline_waits_and_can_intercept_after_resume(self):
        await self.start('''
events = []
saved = None
def request(flow):
    global saved
    events.append(flow.request.path)
    if flow.request.path != '/first':
        saved = flow
        flow.intercept()
def response(flow):
    saved.resume()
''')
        await self.callback('L', request('/first'), request('/wait'), request('/younger'))
        self.assertEqual(self.addon.addon.module.events, ['/first', '/wait'])

        forward, reverse = await self.callback('R', RESPONSE)
        self.assertEqual(reverse, request('/wait'))
        self.assertEqual(self.addon.addon.module.events, ['/first', '/wait', '/younger'])
        self.assertIsNotNone(self.held['L'])

        forward, reverse = await self.callback('R', RESPONSE)
        self.assertEqual(reverse, request('/younger'))
        self.assertIsNone(self.held['L'])

    async def test_kill_paused_request_closes_without_publishing_suffix(self):
        await self.start('''
saved = None
events = []
def request(flow):
    global saved
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()
def response(flow):
    saved.kill()
def error(flow):
    events.append(flow.error.msg)
''')
        await self.callback('L', request('/first'), request('/wait'))
        forward, reverse = await self.callback('R', RESPONSE)

        self.assertFalse(reverse)
        self.assertIsNone(self.held['L'])
        self.assertEqual(self.addon.addon.module.events, ['Connection killed.'])
        self.assertEqual(self.last_termination['reason'], 'Connection killed.')
        self.assertEqual(self.addon.active_flows, 0)

    async def test_generated_response_pause_does_not_repeat_request_hooks(self):
        await self.start('''
from mitmproxy import http
saved = None
events = []
def request(flow):
    events.append(('request', flow.request.path))
    if flow.request.path == '/local':
        flow.response = http.Response.make(200, b'local')
def responseheaders(flow):
    global saved
    events.append(('headers', flow.request.path))
    if flow.request.path == '/local':
        saved = flow
        flow.intercept()
def response(flow):
    events.append(('response', flow.request.path))
    if flow.request.path == '/first':
        saved.response.content = b'edited local'
        saved.resume()
''')
        forward, reverse = await self.callback('L', request('/first'), request('/local'))
        self.assertEqual(forward, request('/first'))
        self.assertFalse(reverse)

        forward, reverse = await self.callback('R', RESPONSE)
        self.assertTrue(forward.startswith(RESPONSE))
        self.assertTrue(forward.endswith(b'edited local'))
        self.assertFalse(reverse)
        self.assertEqual(self.addon.addon.module.events, [
            ('request', '/first'), ('request', '/local'), ('headers', '/local'),
            ('headers', '/first'), ('response', '/first'), ('response', '/local')])
        self.assertEqual(self.addon.active_flows, 0)

    async def test_header_pause_resumes_before_body_completion(self):
        await self.start('''
events = []
saved = None
def requestheaders(flow):
    global saved
    events.append(('headers', flow.request.path))
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()
def request(flow):
    events.append(('request', flow.request.path))
def response(flow):
    saved.resume()
''')
        await self.callback('L', request('/first'))
        head = b'POST /wait HTTP/1.1\r\nHost: example.test\r\nContent-Length: 6\r\n\r\n'
        self.assertEqual(await self.callback('L', head + b'abc'), (b'', b''))

        # Resume is not body completion. Keep the normal reassembly hold,
        # then deliver the complete-message hook once the tail arrives.
        forward, reverse = await self.callback('R', RESPONSE)
        self.assertEqual(forward, RESPONSE)
        self.assertFalse(reverse)
        self.assertIsNotNone(self.held['L'])

        forward, reverse = await self.callback('L', b'def')
        self.assertEqual(forward, head + b'abcdef')
        self.assertFalse(reverse)
        self.assertEqual(self.addon.addon.module.events, [
            ('headers', '/first'), ('request', '/first'),
            ('headers', '/wait'), ('request', '/wait')])

    async def test_header_resume_waits_for_final_trailer_before_editing_trailers(self):
        await self.start('''
events = []
saved = None

def requestheaders(flow):
    global saved

    events.append(('headers', flow.request.path))

    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()

def request(flow):
    events.append(('request', flow.request.path))

    if flow.request.path == '/wait':
        assert flow.request.content == b'old'
        assert flow.request.trailers['x-end'] == 'original'

        flow.request.trailers.set_all('x-end', ['changed', 'again'])

def response(flow):
    saved.resume()
''')
        await self.callback('L', request('/first'))
        head = (b'POST /wait HTTP/1.1\r\nHost: example.test\r\n'
                b'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n')
        partial = head + b'3\r\nold\r\n0\r\nX-End: original\r\n'

        self.assertEqual(await self.callback('L', partial), (b'', b''))

        # The zero chunk does not finish a message whose trailers are pending.
        self.assertEqual(await self.callback('R', RESPONSE), (RESPONSE, b''))
        self.assertIsNotNone(self.held['L'])
        self.assertEqual(self.addon.addon.module.events, [
            ('headers', '/first'), ('request', '/first'), ('headers', '/wait')])

        forward, reverse = await self.callback('L', b'\r\n', request('/younger'))
        self.assertFalse(reverse)
        self.assertTrue(forward.endswith(request('/younger')))
        published = forward[:-len(request('/younger'))]

        # Decode framing with an independent HTTP peer. Only the request
        # start line changes to let the response reader consume this body.
        peer_wire = b'HTTP/1.1 200 OK\r\n' + published.split(b'\r\n', 1)[1]
        self.assertEqual(native_tests.peer_body(peer_wire), b'old')
        self.assertTrue(published.endswith(
            b'0\r\nX-End: changed\r\nx-end: again\r\n\r\n'))
        self.assertIsNone(self.held['L'])
        self.assertEqual(self.addon.addon.module.events, [
            ('headers', '/first'), ('request', '/first'), ('headers', '/wait'),
            ('request', '/wait'), ('headers', '/younger'), ('request', '/younger')])

    async def test_peer_resume_edits_gzip_chunked_response_after_removing_trailers(self):
        await self.start('''
saved = None
events = []

def response(flow):
    global saved

    events.append(flow.request.path)

    if flow.request.path == '/first':
        assert flow.response.content == b'original compressed body'

        saved = flow
        flow.intercept()

def request(flow):
    if flow.request.path == '/release':
        saved.response.content = b'edited compressed body with a different length'
        # Removing trailers avoids retaining metadata tied to the old body.
        saved.response.trailers = None
        saved.resume()
''')
        compressed = gzip.compress(b'original compressed body', mtime=0)
        head = (b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n'
                b'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n')
        chunk_size = format(len(compressed), 'x').encode('ascii')
        chunk = chunk_size + b'\r\n' + compressed
        wire = head + chunk + b'\r\n0\r\nX-End: original\r\n\r\n'
        await self.callback('L', request('/first'), request('/second'))

        # A younger response shares the held lane and must not overtake it.
        self.assertEqual(await self.callback('R', wire, RESPONSE), (b'', b''))
        self.assertEqual(self.addon.addon.module.events, ['/first'])

        forward, reverse = await self.callback('L', request('/release'))
        self.assertEqual(forward, request('/release'))
        self.assertTrue(reverse.endswith(RESPONSE))
        published = reverse[:-len(RESPONSE)]

        encoded_body = native_tests.peer_body(published)
        decoded_body = gzip.decompress(encoded_body)
        self.assertEqual(decoded_body, b'edited compressed body with a different length')

        headers = published.split(b'\r\n\r\n', 1)[0].lower()
        self.assertIn(b'content-encoding: gzip', headers)
        self.assertIn(b'transfer-encoding: chunked', headers)
        self.assertNotIn(b'content-length:', headers)
        self.assertNotIn(b'trailer:', headers)
        self.assertTrue(published.endswith(b'0\r\n\r\n'))

        self.assertEqual(self.addon.addon.module.events, ['/first', '/second'])
        self.assertIsNone(self.held['R'])

        await self.callback('R', RESPONSE)
        self.assertEqual(self.addon.addon.module.events, ['/first', '/second', '/release'])
        self.assertEqual(self.addon.active_flows, 0)

    async def test_header_only_peer_edit_preserves_chunk_extensions_and_suffix(self):
        await self.start('''
saved = None
events = []

def request(flow):
    global saved

    events.append(flow.request.path)

    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()

def response(flow):
    if flow.request.path == '/first':
        saved.request.headers['x-resumed'] = 'yes'
        saved.resume()
''')
        head = (b'POST /wait HTTP/1.1\r\nHost: example.test\r\n'
                b'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n')
        body = b'03;hello="world"\r\nold\r\n0\r\nX-End: original\r\n\r\n'
        forward, reverse = await self.callback(
            'L', request('/first'), head + body, request('/younger'))
        self.assertEqual((forward, reverse), (request('/first'), b''))
        self.assertEqual(self.addon.addon.module.events, ['/first', '/wait'])

        forward, reverse = await self.callback('R', RESPONSE)
        self.assertEqual(forward, RESPONSE)
        published_head, published_body = reverse.split(b'\r\n\r\n', 1)
        self.assertIn(b'x-resumed: yes\r\n', published_head + b'\r\n')
        self.assertEqual(published_body, body + request('/younger'))

        self.assertIsNone(self.held['L'])
        self.assertEqual(self.addon.addon.module.events, ['/first', '/wait', '/younger'])

        await self.callback('R', RESPONSE, RESPONSE)
        self.assertEqual(self.addon.active_flows, 0)

    async def test_body_edit_with_retained_trailers_preserves_checkpoints_on_rejection(self):
        await self.start('''
saved = None

def response(flow):
    global saved

    saved = flow
    flow.intercept()

def request(flow):
    if flow.request.path == '/release':
        saved.response.content = b'changed'
        saved.resume()
''')
        wire = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
                b'Trailer: X-End\r\n\r\n3\r\nold\r\n0\r\nX-End: original\r\n\r\n')
        await self.callback('L', request('/first'))
        self.assertEqual(await self.callback('R', wire), (b'', b''))
        original_held = copy.deepcopy(self.held)
        original_state = copy.deepcopy(self.state)

        # Native Easy safety cannot repair trailers that depend on the body.
        # Rejection must leave the simulated host's owned checkpoints intact.
        with self.assertRaisesRegex(CommitException, 'Body edits with trailers require Expert'):
            await self.callback('L', request('/release'))

        self.assertEqual(self.held, original_held)
        self.assertEqual(self.state, original_state)

    async def test_same_direction_resume_keeps_arriving_pipeline_order(self):
        await self.start('''
saved = None
events = []
def request(flow):
    global saved
    events.append(flow.request.path)
    if flow.request.path == '/wait':
        saved = flow
        flow.intercept()
''')
        await self.callback('L', request('/wait'))
        self.assertEqual(await self.callback('L', request('/second')), (b'', b''))
        self.assertEqual(self.addon.addon.module.events, ['/wait'])

        # A public resume changes the intent; only the next real callback
        # can publish those retained bytes.
        self.addon.addon.module.saved.resume()
        forward, reverse = await self.callback('L', request('/third'))
        self.assertEqual(forward, request('/wait') + request('/second') + request('/third'))
        self.assertFalse(reverse)
        self.assertEqual(self.addon.addon.module.events, ['/wait', '/second', '/third'])

    async def test_local_response_lifecycle_matches_reference_resume(self):
        reference = json.loads((Path(__file__).parent / 'corpus' /
                                'mitmproxy_v12_h1_local_intercept.json').read_text())
        for phase in ('headers', 'response'):
            with self.subTest(phase=phase):
                await self.start('''
from mitmproxy import http
events = []
saved = None
def report(hook, flow):
    events.append(dict(hook=hook, path=flow.request.path,
                       body=flow.response.raw_content.decode('ascii'),
                       error=None if flow.error is None else flow.error.msg))
def request(flow):
    flow.response = http.Response.make(200, b'local original')
    report('request', flow)
def responseheaders(flow):
    global saved
    report('responseheaders', flow)
    if flow.request.path.startswith('/headers/'):
        saved = flow
        flow.intercept()
def response(flow):
    global saved
    report('response', flow)
    if flow.request.path.startswith('/response/'):
        saved = flow
        flow.intercept()
''')
                path = '/' + phase + '/resume'
                self.assertEqual(await self.callback('L', request(path)), (b'', b''))
                module = self.addon.addon.module
                module.saved.response.content = b'edited while held'
                module.saved.resume()
                module.report('released', module.saved)

                forward, reverse = await self.callback('L', b'')
                expected = reference['responses'][path]
                self.assertFalse(expected['pending'])
                self.assertFalse(forward)
                self.assertEqual(reverse.split(b'\r\n\r\n', 1)[1].decode(), expected['body'])
                self.assertEqual(module.events, [event for event in reference['hooks']
                                                 if event['path'] == path])

                self.driver.release_connection('test')
                await self.addon.close()
                self.held = {'L': None, 'R': None}
                self.state = None

    async def test_local_response_kill_uses_native_close_instead_of_reference_wait(self):
        reference = json.loads((Path(__file__).parent / 'corpus' /
                                'mitmproxy_v12_h1_local_intercept.json').read_text())
        for phase in ('headers', 'response'):
            for decision in ('kill', 'resume-kill', 'kill-resume'):
                with self.subTest(phase=phase, decision=decision):
                    await self.start('''
from mitmproxy import http
saved = None
events = []
def request(flow):
    flow.response = http.Response.make(200, b'local original')
def responseheaders(flow):
    global saved
    if flow.request.path.startswith('/headers/'):
        saved = flow
        flow.intercept()
def response(flow):
    global saved
    if flow.request.path.startswith('/response/'):
        saved = flow
        flow.intercept()
def error(flow):
    events.append(flow.error.msg)
''')
                    path = '/' + phase + '/' + decision
                    await self.callback('L', request(path))
                    flow = self.addon.addon.module.saved
                    for operation in decision.split('-'):
                        getattr(flow, operation)()

                    forward, reverse = await self.callback('L', b'')
                    self.assertFalse(forward)
                    self.assertFalse(reverse)
                    self.assertEqual(self.addon.active_flows, 0)
                    self.assertEqual(self.last_termination['reason'], 'Connection killed.')
                    self.assertEqual(self.held, {'L': None, 'R': None})
                    expected = reference['responses'][path]
                    self.assertEqual(expected['pending'], decision != 'resume-kill')
                    self.assertEqual(expected['closed'], decision == 'resume-kill')
                    errors = ['Connection killed.'] if phase == 'headers' else []
                    self.assertEqual(self.addon.addon.module.events, errors)

                    self.driver.release_connection('test')
                    await self.addon.close()
                    self.state = None


if __name__ == '__main__':
    unittest.main()
