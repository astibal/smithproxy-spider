"""Typed checkpoints, real fresh workers, incremental H1/H2 and prefix emission."""
import base64
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from inspection_api import Message, HeldCommit, CommitException, PartType, resume_message
from inspection_h2_test import frame, literal, unpack, Oracle, message

HEAD = b'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\n'
INFO = {'content_annotations': [[0, 17, 'http1.start_line'], [17, len(HEAD), 'http1.headers']]}


def checkpoint(msg, index=0):
    msg.parts.hold_from(msg.parts[index])
    result = msg.commit()
    assert isinstance(result, HeldCommit)
    return json.loads(json.dumps(result.checkpoint))


def resume(held, data, info=None, enrichments=()):
    msg = Message(data, len(data), info or {}, enrichments)
    resume_message(msg, held, info or {}, enrichments)
    return msg


class HoldTests(unittest.TestCase):
    def test_h1_adjacent_header_candidates_keep_annotation_order(self):
        from inspection_api import _h1_head_ranges

        annotations = [
            (20, 30, 'http1.start_line'),
            (0, 10, 'http1.start_line'),
            (10, 18, 'http1.headers'),
            (30, 45, 'http1.headers'),
            (30, 50, 'http1.headers'),
            (60, 70, 'unrelated'),
        ]
        self.assertEqual(
            list(_h1_head_ranges(annotations)),
            [(20, 45), (20, 50), (0, 18)],
        )

    def test_h1_partial_body_edit_header_and_commit(self):
        msg = Message(HEAD + b'a', len(HEAD) + 1, INFO)
        self.assertEqual([p.type for p in msg.parts], [PartType.Http1.Header, PartType.Http1.Body])
        self.assertFalse(msg.parts[1].content.complete)
        msg.parts[0].http1.set_header('X-Test', 'retained')
        held = checkpoint(msg)
        for letter in b'bcde':
            msg = resume(held, bytes([letter]))
            self.assertFalse(msg.parts[1].content.complete)
            held = checkpoint(msg)
        msg = resume(held, b'f')
        self.assertTrue(msg.parts[1].content.complete)
        self.assertEqual(msg.parts[1].get_bytes(), b'abcdef')
        msg.parts[1].set_bytes(b'longer body')
        expected = HEAD.replace(b'Length: 6', b'Length: 11')[:-2] + b'X-Test: retained\r\n\r\nlonger body'
        self.assertEqual(msg.commit(), expected)
        self.assertEqual(msg.commit(), expected)

    def test_h1_every_body_split_and_trailing_opaque(self):
        for cut in range(7):
            with self.subTest(cut=cut):
                msg = Message(HEAD + b'abcdef'[:cut], len(HEAD) + cut, INFO)
                held = checkpoint(msg)
                msg = resume(held, b'abcdef'[cut:] + b'next-message')
                self.assertEqual(msg.commit(), HEAD + b'abcdefnext-message')

    def test_prefix_and_pending_opaque_are_preserved(self):
        msg = message(frame(b'first'), frame(b'second', stream=3))
        msg.parts[1].set_bytes(b'changed')
        msg.parts.hold_from(msg.parts[1])
        result = msg.commit()
        self.assertEqual(result.prefix, frame(b'first'))
        msg = resume(json.loads(json.dumps(result.checkpoint)), b'tail')
        self.assertEqual(msg.commit(), frame(b'changed', stream=3) + b'tail')

    def test_h2_partial_data_every_split(self):
        wire = frame(b'abcdefgh')
        for cut in range(9, len(wire)):
            with self.subTest(cut=cut):
                first = message(wire[:cut])
                held = checkpoint(first)
                msg = resume(held, wire[cut:])
                self.assertTrue(msg.parts[0].complete)
                msg.parts[0].set_bytes(b'rewritten')
                self.assertEqual(msg.commit(), frame(b'rewritten'))

    def test_h2_continuation_and_logical_edits_survive_worker_boundary(self):
        block = literal(b'x', b'value')
        msg = message(frame(block[:3], 1, 0))
        held = checkpoint(msg)
        tail = frame(block[3:], 9, 4)
        msg = resume(held, tail, {'content_annotations': [[0, 9, 'h2.frame.header']]})
        self.assertTrue(msg.parts[0].complete)
        msg.parts[0].headers.set_header(b'x', b'changed')
        held = checkpoint(msg)
        msg = resume(held, b'')
        fields = Oracle().decode(b''.join(f[3] for f in unpack(msg.commit())))
        self.assertEqual(fields, [(b'x', b'changed')])

    def test_h2_content_length_across_callbacks(self):
        msg = message(frame(literal(b':status', b'200') + literal(b'content-length', b'6'), 1, 4), frame(b'abc', flags=0))
        held = checkpoint(msg)
        data = frame(b'def')
        msg = resume(held, data, {'content_annotations': [[0, 9, 'h2.frame.header']]})
        self.assertTrue(all(p.content.complete for p in msg.parts))
        msg.parts[1].set_bytes(b'longer')
        frames = unpack(msg.commit())
        self.assertEqual(Oracle().decode(frames[0][3])[-1], (b'content-length', b'9'))

    def test_h2_removed_body_dependency_survives_hold(self):
        msg = message(frame(literal(b':status', b'200') + literal(b'content-length', b'6'), 1, 4),
                      frame(b'abc', flags=0), frame(b'def'))
        del msg.parts[1]
        held = checkpoint(msg)
        msg = resume(held, b'')
        held = checkpoint(msg)
        msg = resume(held, b'')
        frames = unpack(msg.commit())
        self.assertEqual(Oracle().decode(frames[0][3])[-1], (b'content-length', b'3'))
        self.assertEqual(frames[1][3], b'def')

    def test_validation_atomicity_and_quotas(self):
        msg = message(frame(b'body'))
        with self.assertRaises(CommitException): msg.parts.hold_from(object())
        msg.parts.hold_from(msg.parts[0])
        msg.parts.clear()
        with self.assertRaises(CommitException): msg.commit()
        msg = Message(b'x' * (1024 * 1024), 1024 * 1024)
        with self.assertRaises(CommitException): checkpoint(msg)
        msg = Message(HEAD + b'a', len(HEAD) + 1, INFO)
        with self.assertRaises(CommitException): msg.commit()
        self.assertEqual(checkpoint(msg)['version'], 1)

    def test_bad_annotations_do_not_corrupt_continuation(self):
        raw = frame(b'abcdef')
        held = checkpoint(message(raw[:10]))
        msg = resume(held, raw[10:], {'content_annotations': [None, 7, [0], [-1, 99, 'bad']]})
        self.assertEqual(msg.commit(), raw)

    def test_return_contract_and_instancing_guards(self):
        source = '\n'.join((ROOT / 'src' / name).read_text() for name in (
            'inspection_api.py', 'inspection_h2.py', 'inspection_hold.py',
            'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py'))
        msg = Message(b'old', 3)
        held = checkpoint(msg)
        hold_script = 'api.message.parts.hold_from(api.message.parts[0])\nreturn api.message.commit()'
        for mode, allowed, script, previous in (
                ('message', True, hold_script, None),
                ('endpoint', True, hold_script, None),
                ('flow', False, hold_script, None),
                ('flow', True, 'return None', held),
                ('flow', True, 'api.message.parts.hold_from(api.message.parts[0])\nreturn None', None)):
            with self.subTest(mode=mode, allowed=allowed, previous=bool(previous)):
                request = {'script': script, 'hold_allowed': allowed, 'held_parts': previous,
                    'instance': {'mode': mode}, 'event': {'id': 'guard', 'details': {'info': {
                        'side': 'L', 'content': base64.b64encode(b'new').decode()}}}}
                run = subprocess.run([sys.executable, '-I', '-c', source], input=json.dumps(request),
                    text=True, capture_output=True, check=True, timeout=10)
                result = json.loads(run.stdout)
                self.assertFalse(result['ok'], result)
                self.assertIn('CommitException', result['error'])
                self.assertIsNone(result['replacement'])
                self.assertNotIn('held_parts', result)

    def test_real_fresh_workers_need_more_then_replace(self):
        source = '\n'.join((ROOT / 'src' / name).read_text() for name in (
            'inspection_api.py', 'inspection_h2.py', 'inspection_hold.py',
            'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py'))
        script = ('for part in api.message.parts:\n'
            '    if part.type == PartType.Http1.Body:\n'
            '        if not part.content.complete:\n'
            '            api.message.parts.hold_from(api.message.parts[0])\n'
            '            return api.message.commit()\n'
            '        part.set_bytes(b"changed body")\n'
            'return api.message.commit()')
        held = None
        for data, info in ((HEAD + b'a', INFO), (b'bc', {}), (b'def', {})):
            request = {'script': script, 'hold_allowed': True, 'held_parts': held,
                'instance': {'mode': 'flow'}, 'event': {'id': 'test', 'details': {'info': {
                    **info, 'side': 'L', 'content': base64.b64encode(data).decode()}}}}
            run = subprocess.run([sys.executable, '-I', '-c', source], input=json.dumps(request),
                text=True, capture_output=True, check=True, timeout=10)
            result = json.loads(run.stdout)
            self.assertTrue(result['ok'], result)
            held = result['held_parts']
            if data != b'def':
                self.assertTrue(result['need_more'])
                self.assertEqual(result['replacement'], '')
        self.assertIsNone(held)
        self.assertEqual(base64.b64decode(result['replacement']), HEAD.replace(b'Length: 6', b'Length: 12') + b'changed body')


if __name__ == '__main__':
    unittest.main()
