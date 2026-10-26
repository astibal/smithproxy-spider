"""Shared fixtures, separately executed Easy and Expert contracts."""
import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import Message, MessageSnapshot, Header, Safety, CommitException, api_schema, resume_message
from inspection_h2_test import H2, frame, message, literal, unpack
from inspection_cookbook_test import run
from inspection_translate_settings_test import Connection
from inspection_translate_worker_test import event

MODE = sys.argv.pop(1) if len(sys.argv) > 1 else Safety.Easy
assert MODE in (Safety.Easy, Safety.Expert)


def request(extra=b'', body=b'abc'):
    return (b'POST / HTTP/1.1\r\nHost: lab.test\r\n' + extra +
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


class SafetyTests(unittest.TestCase):
    def semantic_result(self, operation):
        if MODE == Safety.Easy:
            with self.assertRaises(CommitException):
                operation()
            return None
        return operation()

    def test_h1_metadata_matrix(self):
        for metadata in (b'Digest: old\r\n', b'Content-Range: bytes 0-2/3\r\n',
                         b'Content-Encoding: gzip\r\n', b'Signature: old\r\n'):
            with self.subTest(metadata=metadata):
                draft = MessageSnapshot(request(metadata))
                draft.http1.body = b'longer body'
                output = self.semantic_result(lambda: draft.commit(safety=MODE))
                if output is not None:
                    self.assertIn(metadata, output)
                    self.assertIn(b'Content-Length: 11\r\n', output)
                    self.assertTrue(output.endswith(b'longer body'))

    def test_h1_encoding_host_and_bodyless_semantics(self):
        encoding = MessageSnapshot(request())
        encoding.http1.headers.append(Header('Content-Encoding', 'gzip'))
        self.semantic_result(lambda: encoding.commit(safety=MODE))
        host = MessageSnapshot(request())
        host.http1.headers = [h for h in host.http1.headers if h.name.lower() != 'host']
        self.semantic_result(lambda: host.commit(safety=MODE))
        bodyless = MessageSnapshot(b'HTTP/1.1 204 No Content\r\n\r\n')
        bodyless.http1.body = b'abc'
        self.semantic_result(lambda: bodyless.commit(safety=MODE))

    def test_h1_technical_boundaries_remain(self):
        for name, value in [('Transfer-Encoding', 'chunked'), ('Trailer', 'x'),
                            ('Upgrade', 'websocket'), ('Bad Name', 'x'), ('X', 'x\r\ny')]:
            with self.subTest(header=name):
                draft = MessageSnapshot(request())
                draft.http1.headers.append(Header(name, value))
                with self.assertRaises(CommitException):
                    draft.commit(safety=MODE)
        draft = MessageSnapshot(request()[:-1])
        draft.http1.headers.append(Header('X', 'y'))
        with self.assertRaises(CommitException):
            draft.commit(safety=MODE)

    def test_noop_and_regular_repair(self):
        wire = request(b'Signature: old\r\n')
        self.assertEqual(MessageSnapshot(wire).commit(safety=MODE), wire)
        draft = MessageSnapshot(request())
        draft.http1.body = b'four'
        self.assertIn(b'Content-Length: 4\r\n', draft.commit(safety=MODE))
        self.assertEqual(draft.http1.headers[-1], Header('Content-Length', '3'))

    def test_large_control_and_small_fragmentation(self):
        part = H2.Frame(0xfe, 0, 0, b'x' * 20000)
        output = self.semantic_result(lambda: part.commit(safety=MODE))
        if output is not None:
            self.assertEqual(len(output), 20009)
        part.max_frame_size = 32768
        self.assertEqual(len(part.commit(safety=MODE)), 20009)
        part = H2.Frame(0, 1, 1, b'abcdefghij')
        part.max_frame_size = 3
        output = self.semantic_result(lambda: part.commit(safety=MODE))
        if output is not None:
            frames = unpack(output)
            self.assertEqual([len(f[3]) for f in frames], [3, 3, 3, 1])
            self.assertEqual([f[1] for f in frames], [0, 0, 0, 1])

    def test_shared_quotas_ambiguity_and_incomplete(self):
        draft = MessageSnapshot(request())
        draft.http1.body = b'x' * (1024 * 1024 + 1)
        with self.assertRaises(CommitException):
            draft.commit(safety=MODE)
        msg = message(frame(b'abc'))
        msg.parts.append(msg.parts[0])
        with self.assertRaises(CommitException):
            msg.commit(safety=MODE)
        msg = message(frame(b'abc')[:-1])
        msg.parts[0].set_bytes(b'new')
        with self.assertRaises(CommitException):
            msg.commit(safety=MODE)
        part = H2.Frame(0, 1, 1, b'x' * 200000)
        part.max_frame_size = 1
        with self.assertRaises(CommitException):
            part.commit(safety=MODE)

    def test_h2_explicit_length_policy_is_independent(self):
        msg = message(frame(literal(b':status', b'200') + literal(b'content-length', b'3'), 1, 4, 1), frame(b'abc'))
        msg.parts[-1].set_bytes(b'longer')
        self.assertIn(b'6', unpack(msg.commit(safety=MODE))[0][3])
        self.assertIn(b'3', unpack(msg.commit(False, safety=MODE))[0][3])

    def test_h1_parts_hold_and_safety_does_not_persist(self):
        wire = request(b'Digest: old\r\n')
        boundary = wire.index(b'\r\n\r\n') + 4
        start_end = wire.index(b'\r\n') + 2
        info = {'content_annotations': [[0, start_end, 'http1.start_line'], [start_end, boundary, 'http1.headers']]}
        msg = Message(wire, len(wire), info)
        self.assertEqual(len(msg.parts), 2)
        msg.parts[-1].set_bytes(b'changed')
        msg.parts.hold_from(msg.parts[0])
        held = msg.commit(safety=MODE)
        resumed = Message(b'', 0)
        resume_message(resumed, json.loads(json.dumps(held.checkpoint)), {}, [])
        output = self.semantic_result(lambda: resumed.commit(safety=MODE))
        if output is not None:
            self.assertTrue(output.endswith(b'changed'))
        # An Expert hold never silently makes the next callback Expert.
        with self.assertRaises(CommitException):
            resumed.commit()

    def test_expert_then_easy_is_not_sticky(self):
        part = H2.Frame(0xfe, 0, 0, b'x' * 20000)
        self.assertTrue(part.commit(safety=Safety.Expert))
        with self.assertRaises(CommitException):
            part.commit()
        for invalid in (None, 'unsafe', 1, [], {}):
            with self.assertRaises(CommitException):
                MessageSnapshot(request()).commit(safety=invalid)

    def test_translate_keeps_its_state_contract(self):
        connection = Connection()
        msg = connection.message('L', frame(b'abc'))
        msg.parts[0].set_bytes(b'longer')
        with self.assertRaises(CommitException):
            msg.translate(safety=MODE)
        self.assertIsNone(msg._translation.result)

    def test_worker_namespace_and_publication(self):
        script = (f'draft = api.message.snapshot()\ndraft.http1.body = b"changed"\n'
                  f'return draft.commit(safety=Safety.{MODE.title()})')
        result = run(script, event(request(b'Digest: old\r\n')))
        self.assertEqual(result['ok'], MODE == Safety.Expert, result)
        if result['ok']:
            self.assertTrue(base64.b64decode(result['replacement']).endswith(b'changed'))
        else:
            self.assertIsNone(result['replacement'])

    def test_every_schema_member_documents_both_modes(self):
        for name, definition in api_schema()['types'].items():
            for member in definition['fields'] + definition['methods']:
                with self.subTest(type=name, member=member['name']):
                    self.assertTrue(member['easy'].strip())
                    self.assertTrue(member['expert'].strip())


if __name__ == '__main__':
    unittest.main()
