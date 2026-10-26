"""Content-Digest repair: both safety contracts, Parts and sandbox execution."""
import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import MessageSnapshot, Message, Safety, CommitException, resume_message
from inspection_cookbook_test import run


def wire(value='sha-256=:YWJj:', extra=b'', body=b'abc'):
    return (b'POST / HTTP/1.1\r\nHost: lab.test\r\nContent-Digest: ' + value.encode() +
            b'\r\n' + extra + b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def expected(algorithm, body):
    digest = hashlib.new(algorithm.replace('-', ''), body).digest()
    return algorithm.encode() + b'=:' + base64.b64encode(digest) + b':'


class DigestTests(unittest.TestCase):
    def test_body_matrix_and_atomic_draft(self):
        for mode in (Safety.Easy, Safety.Expert):
            for body in (b'', b'abc', b'longer body', bytes(range(256)), b'x' * 65536):
                draft = MessageSnapshot(wire())
                draft.http1.body = body
                # Force repair even when body is unchanged by changing the field.
                draft.http1.set_header('Content-Digest', 'sha-256=::, sha-512=::')
                before = list(draft.http1.headers)
                result = draft.commit(safety=mode)
                for algorithm in ('sha-256', 'sha-512'):
                    self.assertIn(expected(algorithm, body), result)
                self.assertIn(b'Content-Length: ' + str(len(body)).encode(), result)
                self.assertEqual(draft.http1.headers, before)
                self.assertEqual(draft.commit(safety=mode), result)

    def test_unsupported_dictionaries(self):
        for value in ('md5=:YWJj:', 'sha-256=:!:', 'sha-256=:Y:',
                      'sha-256=::;foo=1', 'sha-256=::, sha-256=::',
                      '', 'sha-256', 'sha-256=::, md5=::'):
            for mode in (Safety.Easy, Safety.Expert):
                with self.subTest(value=value, mode=mode):
                    draft = MessageSnapshot(wire(value))
                    draft.http1.body = b'changed'
                    if mode == Safety.Easy:
                        with self.assertRaises(CommitException):
                            draft.commit(safety=mode)
                    else:
                        self.assertIn(b'Content-Digest: ' + value.encode() + b'\r\n',
                                      draft.commit(safety=mode))

    def test_noop_removal_and_split_fields(self):
        original = wire('unknown=::')
        self.assertEqual(MessageSnapshot(original).commit(), original)
        draft = MessageSnapshot(original)
        draft.http1.body = b'new'
        draft.http1.remove_header('Content-Digest')
        self.assertNotIn(b'Content-Digest', draft.commit())
        draft = MessageSnapshot(wire(extra=b'content-digest: sha-512=::\r\n'))
        draft.http1.body = b'new'
        result = draft.commit()
        self.assertEqual(result.lower().count(b'content-digest:'), 1)
        self.assertIn(expected('sha-512', b'new'), result)

    def test_other_dependencies_still_reject(self):
        for extra in (b'Repr-Digest: sha-256=::\r\n', b'ETag: "v1"\r\n',
                      b'Signature: old\r\n', b'Content-Encoding: gzip\r\n',
                      b'Content-Range: bytes 0-2/5\r\n'):
            draft = MessageSnapshot(wire(extra=extra))
            draft.http1.body = b'new'
            with self.assertRaises(CommitException):
                draft.commit()

    def test_hold_every_body_boundary(self):
        original = wire()
        boundary = original.index(b'\r\n\r\n') + 4
        start = original.index(b'\r\n') + 2
        info = {'content_annotations': [[0, start, 'http1.start_line'], [start, boundary, 'http1.headers']]}
        for mode in (Safety.Easy, Safety.Expert):
            for size in range(3):
                first = original[:boundary + size]
                message = Message(first, len(first), info)
                message.parts.hold_from(message.parts[0])
                held = message.commit(safety=mode)
                self.assertEqual(held.prefix, b'')
                tail = original[boundary + size:]
                resumed = Message(tail, len(tail))
                resume_message(resumed, json.loads(json.dumps(held.checkpoint)), {}, [])
                resumed.parts[-1].set_bytes(b'changed')
                output = resumed.commit(safety=mode)
                self.assertIn(expected('sha-256', b'changed'), output)
                self.assertTrue(output.endswith(b'changed'))

    def test_real_worker(self):
        for mode in ('Easy', 'Expert'):
            result = run('draft = api.message.snapshot()\ndraft.http1.body = b"changed"\n'
                         f'return draft.commit(safety=Safety.{mode})',
                         {'details': {'info': {'content': base64.b64encode(wire()).decode()}}})
            self.assertTrue(result['ok'], result)
            self.assertIn(expected('sha-256', b'changed'), base64.b64decode(result['replacement']))

    def test_failure_retry_and_partial_input(self):
        draft = MessageSnapshot(wire('unknown=::'))
        draft.http1.body = b'changed'
        with self.assertRaises(CommitException):
            draft.commit()
        draft.http1.set_header('Content-Digest', 'sha-256=::')
        self.assertIn(expected('sha-256', b'changed'), draft.commit())
        for mode in (Safety.Easy, Safety.Expert):
            partial = MessageSnapshot(wire()[:-1])
            partial.http1.body = b'changed'
            with self.assertRaises(CommitException):
                partial.commit(safety=mode)

    def test_no_implicit_digest_and_expert_encoded_preservation(self):
        draft = MessageSnapshot(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc')
        draft.http1.body = b'changed'
        self.assertNotIn(b'Content-Digest', draft.commit())
        draft = MessageSnapshot(wire(extra=b'Content-Encoding: gzip\r\n'))
        draft.http1.body = b'raw-research'
        output = draft.commit(safety=Safety.Expert)
        self.assertIn(b'Content-Digest: sha-256=:YWJj:', output)


if __name__ == '__main__':
    unittest.main()
