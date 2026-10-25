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

from inspection_h2_test import frame, literal, unpack, Oracle

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCES = ('inspection_api.py', 'inspection_h2.py', 'inspection_hold.py', 'inspection_translate.py',
           'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py')
WORKER = '\n'.join((ROOT / 'src' / name).read_text() for name in SOURCES)


def fixture(name):
    annotations = []
    if name == 'h2':
        head = frame(literal(b':method', b'POST') + literal(b'content-length', b'3'), 1, 4, 3)
        data = head + frame(b'abc', stream=3)
        annotations = [[0, 9, 'h2.frame.header'], [len(head), len(head) + 9, 'h2.frame.header']]
    elif name == 'opaque':
        data = b'\x01\x02custom'
    else:
        body = gzip.compress(b'abc', mtime=0) if name == 'gzip' else b'abc'
        head = b'POST / HTTP/1.1\r\nHost: lab.test\r\nX-Old: yes\r\n'
        if name == 'gzip':
            head += b'Content-Encoding: gzip\r\n'
        head += b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n'
        start_end = head.index(b'\r\n') + 2
        annotations = [[0, start_end, 'http1.start_line'], [start_end, len(head), 'http1.headers']]
        data = head + (body[:1] if name == 'h1-partial' else body)
    return {'id': 'cookbook', 'details': {'info': {
        'side': 'L', 'session': 'lab.test', 'payload_layer': 'tcp',
        'content': base64.b64encode(data).decode(), 'content_annotations': annotations,
    }}}


def run(script, event, **extra):
    request = {'script': script, 'event': event, **extra}
    result = subprocess.run([sys.executable, '-c', WORKER], input=json.dumps(request),
                            capture_output=True, text=True, timeout=10, check=True)
    return json.loads(result.stdout)


class CookbookTests(unittest.TestCase):
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
                elif name == 'h1-body':
                    self.assertTrue(wire.endswith(b'{"lab":true}'))
                    self.assertIn(b'Content-Length: 12\r\n', wire)
                elif name == 'h1-hold':
                    self.assertTrue(wire.endswith(b'abc-checked'))
                    self.assertIn(b'Content-Length: 11\r\n', wire)
                elif name == 'h2-header':
                    self.assertIn((b'x-test-id', b'spider-lab'), Oracle().decode(unpack(wire)[0][3]))
                elif name == 'h2-body':
                    frames = unpack(wire)
                    self.assertIn((b'content-length', b'20000'), Oracle().decode(frames[0][3]))
                    self.assertEqual(b''.join(f[3] for f in frames if f[0] == 0), b'A' * 20000)
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
