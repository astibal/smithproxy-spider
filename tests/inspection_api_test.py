import dataclasses
import pathlib
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import make_views, api_schema


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
            views = make_views(event, data, enrichments)
            api = SimpleNamespace(**vars(views), print=lambda *args: None)
            for name, definition in api_schema()['types'].items():
                for field in definition['fields']:
                    with self.subTest(type=name, field=field['name'], size=len(data)):
                        exec(compile(field['example'], '<api-example>', 'exec'), {'api': api})


if __name__ == '__main__':
    unittest.main()
