import dataclasses
import pathlib
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import make_views, api_schema, Message, Header, CommitException


class WriteTests(unittest.TestCase):
    request = b'POST /old HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\nX-A: one\r\nX-A: two\r\n\r\nabc'

    def draft(self, data=None):
        data = self.request if data is None else data
        return Message(data, len(data)).snapshot()

    def test_noop_and_independent_snapshots(self):
        one, two = self.draft(), self.draft()
        self.assertEqual(one.commit(), self.request)
        one.http1.body = 'longer ž'.encode()
        one.http1.target = '/new/path'
        one.http1.set_header('X-A', 'replaced')
        result = one.commit()
        self.assertIn(b'Content-Length: 9\r\n', result)
        self.assertIn(b'POST /new/path HTTP/1.1', result)
        self.assertEqual(result.count(b'X-A:'), 1)
        self.assertTrue(result.endswith('longer ž'.encode()))
        self.assertEqual(two.commit(), self.request)
        self.assertEqual(one.commit(), result)
        self.assertIn(Header('Content-Length', '3'), one.http1.headers)  # commit does not mutate draft

    def test_failure_retry_and_injection(self):
        draft = self.draft()
        draft.http1.set_header('X-Test', 'bad\r\nInjected: yes')
        with self.assertRaises(CommitException): draft.commit()
        self.assertEqual(self.draft().commit(), self.request)
        draft.http1.set_header('X-Test', 'ok')
        self.assertIn(b'X-Test: ok', draft.commit())
        for target in ('/x\r\nBad: yes', '/white space', '', None, 42):
            draft.http1.target = target
            with self.subTest(target=target), self.assertRaises(CommitException): draft.commit()

    def test_unsupported_edits_noop_preserved(self):
        for raw in (b'', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', self.request[:-1],
                    self.request + self.request, b'HTTP/1.1 200 OK\r\n\r\nclose delimited',
                    b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
                    b'GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n',
                    b'CONNECT x:443 HTTP/1.1\r\nHost: x\r\n\r\n',
                    b'GET / HTTP/1.1\r\nConnection: keep-alive, upgrade\r\n\r\n'):
            with self.subTest(raw=raw):
                draft = self.draft(raw)
                self.assertFalse(draft.http1.available)
                self.assertEqual(draft.commit(), raw)
                draft.http1.set_header('X-Test', 'edit')
                with self.assertRaises(CommitException): draft.commit()

    def test_length_management_and_duplicate_headers(self):
        draft = self.draft()
        draft.http1.remove_header('Content-Length')
        draft.http1.body = b''
        self.assertIn(b'Content-Length: 0', draft.commit())
        draft.http1.headers += [Header('Set-Cookie', 'a=1'), Header('Set-Cookie', 'b=2')]
        draft.http1.set_header('Content-Length', 'incorrect user value')
        self.assertEqual(draft.commit().count(b'Set-Cookie:'), 2)
        self.assertIn(b'Content-Length: 0', draft.commit())
        draft = self.draft(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
        draft.http1.body = b'new'
        self.assertIn(b'Content-Length: 3', draft.commit())

    def test_response_and_bodyless_semantics(self):
        draft = self.draft(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc')
        draft.http1.body = b'longer'
        self.assertIn(b'Content-Length: 6', draft.commit())
        for status, length in ((204, b''), (304, b'Content-Length: 999\r\n'), (100, b'')):
            draft = self.draft(f'HTTP/1.1 {status} Status\r\n'.encode() + length + b'\r\n')
            self.assertTrue(draft.http1.available)
            draft.http1.set_header('X-Test', 'ok')
            self.assertIn(b'X-Test: ok', draft.commit())
            draft.http1.body = b'x'
            with self.assertRaises(CommitException): draft.commit()

    def test_reject_encoding_integrity_and_oversize(self):
        for name in ('Content-Encoding', 'Digest', 'ETag', 'Content-Range'):
            draft = self.draft(self.request.replace(b'Host:', f'{name}: value\r\nHost:'.encode()))
            draft.http1.body = b'changed'
            with self.subTest(name=name), self.assertRaises(CommitException): draft.commit()
        for name, value in (('Transfer-Encoding', 'chunked'), ('Connection', 'keep-alive, upgrade'),
                            ('Content-Encoding', 'gzip'), ('X-Bad', 'snowman ☃'), ('Bad Name', 'x')):
            draft = self.draft()
            draft.http1.set_header(name, value)
            with self.subTest(name=name), self.assertRaises(CommitException): draft.commit()
        draft = self.draft()
        draft.http1.body = b'x' * (1024 * 1024)
        with self.assertRaises(CommitException): draft.commit()
        draft.http1.body = 'not bytes'
        with self.assertRaises(CommitException): draft.commit()

    def test_worker_publish_discard_and_catch(self):
        import base64, json, subprocess
        source_dir = pathlib.Path(__file__).resolve().parents[1] / 'src'
        worker = '\n'.join((source_dir / name).read_text() for name in (
            'inspection_api.py', 'inspection_h2.py', 'inspection_hold.py', 'inspection_translate.py', 'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py'))
        def run(script):
            request = {'script': script, 'event': {'details': {'info': {
                'content': base64.b64encode(self.request).decode()}}}}
            result = subprocess.run([sys.executable, '-c', worker], input=json.dumps(request),
                                    text=True, capture_output=True, timeout=5, check=True)
            return json.loads(result.stdout)
        prefix = 'draft = api.message.snapshot()\ndraft.http1.body = b"longer"\n'
        result = run(prefix + 'return draft.commit()')
        self.assertTrue(result['ok'], result)
        self.assertIn(b'Content-Length: 6', base64.b64decode(result['replacement']))
        self.assertIsNone(run(prefix + 'draft.commit()\nreturn None')['replacement'])
        result = run(prefix + 'draft.http1.target = "bad target"\ntry:\n    return draft.commit()\nexcept CommitException:\n    return None')
        self.assertTrue(result['ok'], result)
        self.assertIsNone(result['replacement'])
        result = run(prefix + 'draft.http1.target = "bad target"\nreturn draft.commit()')
        self.assertFalse(result['ok'])
        self.assertIsNone(result['replacement'])
        self.assertIn('CommitException', result['error'])


class Http2Tests(unittest.TestCase):
    def view(self, payload=b'', annotations=(), enrichments=()):
        return make_views({'details': {'info': {'content_annotations': annotations}}},
                          payload, enrichments).http2

    def test_data_and_immutability(self):
        payload = b'\x00\x00\x05\x00\x09\x00\x00\x00\x03\x01abc\x00'
        view = self.view(payload, [(0, 9, 'h2.frame.header')])
        frame = view.frames[0]
        self.assertEqual((frame.stream_id, frame.flags, frame.complete), (3, 9, True))
        self.assertEqual(bytes(frame.data), b'abc')
        self.assertIs(frame.payload.obj, payload)
        with self.assertRaises(TypeError):
            frame.data[0] = 0
        with self.assertRaises(dataclasses.FrozenInstanceError):
            frame.flags = 0

    def test_partial_and_invalid(self):
        payload = b'\x00\x00\x05\x00\x00\x00\x00\x00\x03ab'
        frame = self.view(payload, [(0, 9, 'h2.frame.header')]).frames[0]
        self.assertFalse(frame.complete)
        self.assertIsNone(frame.data)
        self.assertEqual(bytes(frame.payload), b'ab')
        self.assertFalse(self.view(payload).available)
        self.assertEqual(self.view(payload, [(-1, 8, 'h2.frame.header'),
            (0, 8, 'h2.frame.header')]).frames, ())
        self.assertTrue(self.view(b'abc', [(0, 3, 'h2.data')]).available)

    def test_multiple_blocks_and_context(self):
        def block(stream):
            return {'metadata': {'operation': 'hpack.decode', 'context': 'complete',
                'source': {'stream_id': stream, 'kind': 'h2.headers', 'spans_previous_envelopes': True},
                'headers': [{'name': ':method', 'value': 'GET'},
                            {'name': 'x-test', 'value': 'one'}, {'name': 'x-test', 'value': 'two'}]}}
        view = self.view(enrichments=[block(3), block(5)])
        self.assertEqual([b.stream_id for b in view.header_blocks], [3, 5])
        self.assertTrue(view.header_blocks[0].spans_previous_envelopes)
        self.assertEqual([h.value for h in view.header_blocks[0].headers], ['GET', 'one', 'two'])
        bad = block(7); bad['metadata']['context'] = 'incomplete'
        self.assertFalse(self.view(enrichments=[bad]).available)

    def test_schema(self):
        schema = api_schema()
        self.assertIn('Http2', schema['types'])
        self.assertIn('http2', [f['name'] for f in schema['types'][schema['root']]['fields']])
        for name in ('Http2', 'H2Frame', 'H2HeaderBlock'):
            for field in schema['types'][name]['fields']:
                self.assertTrue(field['example'])
                self.assertEqual(field['access'], 'read-only snapshot')

    def test_documented_examples_run_on_empty_and_populated_callbacks(self):
        payload = b'\x00\x00\x05\x00\x09\x00\x00\x00\x03\x01abc\x00'
        h2 = {'metadata': {'operation': 'hpack.decode', 'context': 'complete',
            'source': {'stream_id': 3, 'parent_stream_id': 1,
                       'kind': 'h2.push_promise', 'spans_previous_envelopes': True},
            'headers': [{'name': ':status', 'value': '404'}]}}
        fixtures = [({}, b'', [])]
        for head in ({'method': 'GET', 'target': '/search?q=spider'}, {'status': 404}):
            head['headers'] = [{'name': 'Content-Type', 'value': 'text/plain'}]
            fixtures.append(({'details': {'info': {'side': 'R', 'payload_layer': 'test',
                'content_annotations': [(0, 9, 'h2.frame.header')]}}}, payload,
                [h2, {'metadata': {'operation': 'http1.parse-head', 'context': 'complete', 'message': head}}]))
        fixtures.append((fixtures[1][0], payload[:-2], []))
        for event, data, enrichments in fixtures:
            for name, definition in api_schema()['types'].items():
                for field in definition['fields'] + definition.get('methods', []):
                    with self.subTest(type=name, field=field['name'], size=len(data)):
                        from inspection_api import PartType, Mode
                        from textwrap import indent
                        views = make_views(event, data, enrichments)
                        api = SimpleNamespace(**vars(views), print=lambda *args: None)
                        # Part/entry reference examples assume an existing draft.
                        # Execute each independently, inside a real script function
                        # so explicit `return api.message.commit()` is exercised.
                        part = api.http2.Frame(1, 5, 1, b'\x00\x01x\x01v')
                        scope = {'Mode': Mode}
                        source = 'def example(api, part, entry, PartType):\n' + indent(field['example'], '    ')
                        exec(compile(source, '<api-example>', 'exec'), scope)
                        if name in ('Connection', 'ConnectionHttp2') or field['name'] == 'connection':
                            # Offline views cannot activate live connection policy.
                            with self.assertRaisesRegex(CommitException, 'flow instantiation'):
                                scope['example'](api, part, part.headers.entries[0], PartType)
                        else:
                            scope['example'](api, part, part.headers.entries[0], PartType)


if __name__ == '__main__':
    unittest.main()
