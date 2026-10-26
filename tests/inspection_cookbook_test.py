"""Execute every cookbook block in the real sandboxed inspection worker."""
import base64
import ast
import gzip
import json
import pathlib
import re
import subprocess
import sys
import unittest
from worker_bootstrap import packed

from inspection_h2_test import frame, literal, unpack, Oracle

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ('inspection_api.py', 'inspection_h2.py', 'inspection_hold.py', 'inspection_chunked.py', 'inspection_translate.py',
           'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py')
WORKER = '\n'.join((ROOT / 'src' / name).read_text() for name in SOURCES)


def fixture(name):
    if name == 'setup':
        return {'action': 'connection-start', 'id': 'cookbook', 'details': {'info': {
            'phase': 'setup', 'webhook_control': {'version': 1, 'sequence': 0, 'rewrite': False},
        }}}
    annotations = []
    if name == 'h2':
        head = frame(literal(b':method', b'POST') + literal(b'content-length', b'3'), 1, 4, 3)
        data = head + frame(b'abc', stream=3)
        annotations = [[0, 9, 'h2.frame.header'], [len(head), len(head) + 9, 'h2.frame.header']]
    elif name == 'opaque':
        data = b'\x01\x02custom'
    else:
        import zlib
        body = b'abc'
        if name == 'gzip':
            body = gzip.compress(body, mtime=0)
        elif name == 'deflate':
            body = zlib.compress(body)
        head = b'POST / HTTP/1.1\r\nHost: lab.test\r\nX-Old: yes\r\n'
        if name == 'gzip':
            head += b'Content-Encoding: gzip\r\n'
        if name == 'deflate':
            head += b'Content-Encoding: deflate\r\n'
        if name == 'h1-chunked':
            head += b'Transfer-Encoding: chunked\r\n\r\n'
            body = b'3\r\nabc\r\n0\r\n\r\n'
        else:
            head += b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        start_end = head.index(b'\r\n') + 2
        annotations = [[0, start_end, 'http1.start_line'], [start_end, len(head), 'http1.headers']]
        data = head + (body[:1] if name == 'h1-partial' else body)
    event = {'id': 'cookbook', 'details': {'info': {
        'side': 'L', 'session': 'lab.test', 'payload_layer': 'tcp',
        'content': base64.b64encode(data).decode(), 'content_annotations': annotations,
    }}}

    if name == 'h1-unreserved':
        event['details']['info']['webhook_control'] = {'rewrite': False}

    return event


def run(script, event, **extra):
    request = {'script': script, 'event': event, **extra}
    result = subprocess.run([sys.executable, '-c', packed(WORKER)], input=json.dumps(request),
                            capture_output=True, text=True, timeout=10, check=True)
    return json.loads(result.stdout)


class CookbookTests(unittest.TestCase):
    def test_readme_live_examples_setup_content_and_hold(self):
        """README snippets must work as deployments, not only offline fragments."""
        document = (ROOT / 'README.md').read_text()
        blocks = re.findall(
            r'<!-- live-example: (\S+) -->\s*```python\n(.*?)```',
            document, re.S,
        )
        examples = dict(blocks)
        self.assertEqual(len(blocks), len(examples))
        self.assertEqual(set(examples), {'h1-snapshot', 'h2-rewrite', 'h1-hold'})

        for name, script in examples.items():
            with self.subTest(example=name):
                options = {'instance': {'mode': 'flow'}, 'hold_allowed': True}
                setup = run(script, fixture('setup'), **options)
                self.assertTrue(setup['ok'], setup)
                self.assertTrue(setup['rewrite_requested'])
                self.assertIsNone(setup['replacement'])
                self.assertIsNone(setup['held_parts'])

                kind = {'h1-snapshot': 'h1', 'h2-rewrite': 'h2',
                        'h1-hold': 'h1-partial'}[name]
                event = fixture(kind)
                event['action'] = 'connection-content'
                event['details']['info']['webhook_control'] = {
                    'version': 1, 'sequence': 1, 'rewrite': setup['rewrite_requested'],
                }
                result = run(script, event, instance_state=setup['instance_state'], **options)
                self.assertTrue(result['ok'], result)

                if name == 'h1-hold':
                    self.assertTrue(result['need_more'])
                    self.assertEqual(base64.b64decode(result['replacement']), b'')
                    self.assertIsNotNone(result['held_parts'])
                    # Only fresh tail bytes arrive; the backend returns the saved Parts.
                    tail = {'action': 'connection-content', 'id': event['id'],
                            'details': {'info': {'side': 'L', 'content': 'YmM=',
                                'webhook_control': {'version': 1, 'sequence': 2, 'rewrite': True}}}}
                    result = run(script, tail, held_parts=result['held_parts'],
                                 instance_state=result['instance_state'], **options)
                    self.assertTrue(result['ok'], result)
                    self.assertIsNone(result['held_parts'])
                    self.assertEqual(result['hold']['state'], 'released')

                wire = base64.b64decode(result['replacement'])
                if name == 'h1-snapshot':
                    self.assertTrue(wire.startswith(b'POST /new/path HTTP/1.1\r\n'))
                    self.assertIn(b'X-Inspected-By: Spider\r\n', wire)
                    self.assertTrue(wire.endswith(b'\r\n\r\nabc'))
                elif name == 'h2-rewrite':
                    frames = unpack(wire)
                    headers = Oracle().decode(frames[0][3])
                    self.assertIn((b'x-spider', b'rewrite'), headers)
                    self.assertIn((b'content-length', b'8'), headers)
                    self.assertEqual(b''.join(f[3] for f in frames if f[0] == 0), b'new body')
                else:
                    head, body = wire.split(b'\r\n\r\n', 1)
                    self.assertEqual(body, b'a different body')
                    self.assertIn(b'Content-Length: 16', head)

    def test_flat_helpers_are_documented_too(self):
        tree = ast.parse((ROOT / 'src/inspection_worker.py').read_text())
        api_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Api')
        members = {
            node.attr for node in ast.walk(api_class)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Name) and node.value.id == 'self'
        }
        members.update(node.name for node in api_class.body
                       if isinstance(node, ast.FunctionDef) and not node.name.startswith('_'))
        documentation = (ROOT / 'docs/INSPECTION_COOKBOOK.md').read_text()
        for name in members:
            with self.subTest(member=name):
                self.assertIn('api.' + name, documentation)

    def test_reference_matches_current_schema(self):
        subprocess.run([sys.executable, str(ROOT / 'tools/generate-api-examples.py'), '--check'],
                       check=True, timeout=10)

    def test_all_cookbook_examples(self):
        doc = (ROOT / 'docs/INSPECTION_COOKBOOK.md').read_text()
        examples = re.findall(
            r'<!-- example: (\S+) fixture=(\S+) expect=(\S+) -->\s*```python\n(.*?)\n```',
            doc, re.S)
        self.assertEqual(len(examples), doc.count('```python'))
        self.assertGreaterEqual(len(examples), 18)
        self.assertEqual(len({e[0] for e in examples}), len(examples))

        for name, kind, expected, script in examples:
            with self.subTest(example=name):
                event = fixture(kind)
                options = {}
                if expected == 'hold-resume':
                    options = {'hold_allowed': True, 'instance': {'mode': 'flow'}}
                result = run(script, event, **options)

                if expected in ('CommitException', 'TypeError'):
                    self.assertFalse(result['ok'], result)
                    self.assertIn(expected, result['error'])
                    self.assertIsNone(result['replacement'])
                    continue

                self.assertTrue(result['ok'], result)
                if expected == 'setup':
                    self.assertTrue(result['rewrite_requested'])
                    self.assertIsNone(result['replacement'])
                    continue
                if expected == 'unchanged':
                    self.assertIsNone(result['replacement'])
                    continue

                if expected == 'hold-resume':
                    self.assertTrue(result['need_more'])
                    self.assertEqual(base64.b64decode(result['replacement']), b'')
                    tail = {'details': {'info': {'side': 'L', 'content': 'YmM='}}}
                    result = run(script, tail, held_parts=result['held_parts'], **options)
                    self.assertTrue(result['ok'], result)
                    self.assertIsNone(result['held_parts'])

                wire = base64.b64decode(result['replacement'])
                original = base64.b64decode(event['details']['info']['content'])
                self.assertNotEqual(wire, original)

                if name == 'h1-route':
                    self.assertTrue(wire.startswith(b'POST /lab/echo HTTP/1.1'))
                    self.assertNotIn(b'X-Old:', wire)
                    self.assertEqual(wire.count(b'X-Tag:'), 2)
                elif name == 'expert-digest':
                    self.assertIn(b'Digest: old-digest\r\n', wire)
                    self.assertIn(b'Content-Length: 7\r\n', wire)
                    self.assertTrue(wire.endswith(b'changed'))
                elif name == 'h1-body':
                    self.assertTrue(wire.endswith(b'{"lab":true}'))
                    self.assertIn(b'Content-Length: 12\r\n', wire)
                elif name in ('body-gzip', 'body-deflate'):
                    import zlib
                    encoded = wire.split(b'\r\n\r\n', 1)[1]
                    plain = gzip.decompress(encoded) if name == 'body-gzip' else zlib.decompress(encoded)
                    self.assertEqual(plain, b'abc-checked')
                    self.assertIn(f'Content-Length: {len(encoded)}\r\n'.encode(), wire)
                elif name in ('h1-chunked-body', 'h1-chunked-chunk'):
                    self.assertNotIn(b'Content-Length:', wire)
                    self.assertTrue(wire.endswith(b'7\r\nchanged\r\n0\r\n\r\n'))
                elif name == 'h1-hold':
                    self.assertTrue(wire.endswith(b'abc-checked'))
                    self.assertIn(b'Content-Length: 11\r\n', wire)
                elif name == 'h2-header':
                    self.assertIn((b'x-test-id', b'spider-lab'), Oracle().decode(unpack(wire)[0][3]))
                elif name == 'h2-body':
                    frames = unpack(wire)
                    self.assertIn((b'content-length', b'20000'), Oracle().decode(frames[0][3]))
                    self.assertEqual(b''.join(f[3] for f in frames if f[0] == 0), b'A' * 20000)
                elif name == 'h2-logical-body':
                    frames = unpack(wire)
                    self.assertIn((b'content-length', b'7'), Oracle().decode(frames[0][3]))
                    self.assertEqual(b''.join(f[3] for f in frames if f[0] == 0), b'changed')
                elif name == 'h2-construct':
                    frames = unpack(wire)
                    self.assertEqual(Oracle().decode(frames[0][3]), [
                        (b':method', b'GET'), (b'x-lab', b'value'), (b'authorization', b'lab-only')])
                    self.assertEqual(frames[-2][3], b'lab-ping')
                elif name == 'opaque':
                    self.assertEqual(wire, original + b'\x00')
                elif name == 'retry':
                    self.assertTrue(wire.startswith(b'POST /safe HTTP/1.1'))


if __name__ == '__main__':
    unittest.main()
