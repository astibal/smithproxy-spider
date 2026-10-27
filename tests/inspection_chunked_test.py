"""Chunked Parts: independent HTTP peer oracle, hold boundaries and draft edits."""
import http.client
import base64
import io
import json
import pathlib
import random
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import Message, PartType, Safety, CommitException
from inspection_hold_test import checkpoint, resume

HEAD = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
WIRE = b'03;hello="world"\r\nabc\r\n2\r\nde\r\n0\r\n\r\n'


def message(data=WIRE, head=HEAD):
    end = head.index(b'\r\n') + 2
    return Message(head + data, len(head + data), {'content_annotations': [
        [0, end, 'http1.start_line'], [end, len(head), 'http1.headers']]})


def peer_body(wire):
    class Socket:
        def makefile(self, *args):
            return io.BytesIO(wire)

    response = http.client.HTTPResponse(Socket())
    response.begin()
    return response.read()


class ChunkedTests(unittest.TestCase):
    def test_noop_and_two_views(self):
        msg = message()
        self.assertEqual([p.type for p in msg.parts], [PartType.Http1.Header, PartType.Http1.Body])
        body = msg.parts[1]
        self.assertEqual(body.get_bytes(), b'abcde')
        self.assertEqual([p.get_bytes() for p in body.chunks], [b'abc', b'de'])
        self.assertEqual(msg.commit(), HEAD + WIRE)

    def test_body_replacements(self):
        for mode in (Safety.Easy, Safety.Expert):
            for data in (b'', b'x', b'longer body', bytes(range(256)) * 200):
                with self.subTest(mode=mode, size=len(data)):
                    msg = message()
                    msg.parts[1].set_bytes(data)
                    result = msg.commit(safety=mode)
                    self.assertEqual(peer_body(result), data)
                    self.assertNotIn(b'Content-Length:', result)
                    self.assertEqual(msg.commit(safety=mode), result)

    def test_chunk_edits_and_no_duplicate_emission(self):
        msg = message()
        body = msg.parts[1]
        body.chunks[1].set_bytes(b'longer')
        self.assertEqual(body.get_bytes(), b'abclonger')
        self.assertIn(b'03;hello="world"\r\nabc', msg.commit())
        self.assertEqual(peer_body(msg.commit()), b'abclonger')
        body.chunks[0].set_bytes(b'')
        self.assertEqual(peer_body(msg.commit()), b'longer')
        msg.parts.append(body.chunks[0])
        with self.assertRaises(CommitException):
            msg.commit()

    def test_conflicting_views(self):
        msg = message()
        msg.parts[1].chunks[0].set_bytes(b'x')
        msg.parts[1].set_bytes(b'y')
        with self.assertRaisesRegex(CommitException, 'combine'):
            msg.commit()

    def test_same_content_with_changed_chunk_boundaries(self):
        msg = message()
        msg.parts[1].chunks[0].set_bytes(b'a')
        msg.parts[1].chunks[1].set_bytes(b'bcde')
        wire = msg.commit()
        self.assertEqual(peer_body(wire), b'abcde')
        self.assertTrue(wire.endswith(b'1\r\na\r\n4\r\nbcde\r\n0\r\n\r\n'))

    def test_header_only_edit_preserves_chunk_extensions_and_trailers(self):
        head = HEAD[:-2] + b'Trailer: X-Test\r\n\r\n'
        wire = WIRE[:-2] + b'X-Test: original\r\n\r\n'
        msg = message(wire, head)
        msg.parts[0].http1.set_header('X-New', 'yes')
        result = msg.commit()
        self.assertIn(b'Trailer: X-Test\r\n', result)
        self.assertTrue(result.endswith(wire))

    def test_ambiguous_or_unsupported_heads_are_opaque(self):
        for extra in (b'Content-Length: 5\r\n', b'Transfer-Encoding: chunked\r\n',
                      b'Trailer: bad name\r\n'):
            msg = message(head=HEAD[:-2] + extra + b'\r\n')
            self.assertEqual(msg.parts[0].type, PartType.Opaque)

    def test_chunk_structure_cannot_be_silently_replaced(self):
        msg = message()
        msg.parts[1].chunks = ()
        with self.assertRaisesRegex(CommitException, 'reordered'):
            msg.commit()

    def test_terminal_extensions_and_empty_body(self):
        wire = b'000;done=yes\r\n\r\n'
        msg = message(wire)
        self.assertEqual(msg.parts[1].get_bytes(), b'')
        self.assertEqual(msg.commit(), HEAD + wire)
        msg.parts[1].set_bytes(b'new')
        self.assertEqual(peer_body(msg.commit()), b'new')
        self.assertTrue(msg.commit().endswith(wire))

    def test_malformed_extensions_and_continuations(self):
        for line in (b'1;=bad', b'1;x="unterminated', b'1;x="\x7f"', b'+1', b' 1'):
            msg = message(line + b'\r\nx\r\n0\r\n\r\n')
            self.assertEqual(msg.parts[0].type, PartType.Opaque)
        msg = message(b'1\r\nx')
        with self.assertRaisesRegex(CommitException, 'CRLF'):
            resume(checkpoint(msg), b'!!')

    def test_easy_and_expert_integrity_metadata(self):
        head = HEAD[:-2] + b'Digest: old\r\n\r\n'
        msg = message(head=head)
        msg.parts[1].set_bytes(b'changed')
        with self.assertRaises(CommitException):
            msg.commit()
        self.assertEqual(peer_body(msg.commit(safety=Safety.Expert)), b'changed')

    def test_output_quota_includes_framing(self):
        msg = message()
        msg.parts[1].set_bytes(b'x' * (1024 * 1024))
        for mode in (Safety.Easy, Safety.Expert):
            with self.assertRaises(CommitException):
                msg.commit(safety=mode)

    def test_every_split_and_trailing_bytes(self):
        for cut in range(len(WIRE)):
            with self.subTest(cut=cut):
                msg = message(WIRE[:cut])
                self.assertFalse(msg.parts[1].content.complete)
                msg = resume(checkpoint(msg), WIRE[cut:] + b'NEXT')
                self.assertTrue(msg.parts[1].content.complete)
                self.assertEqual(msg.parts[1].get_bytes(), b'abcde')
                self.assertEqual(msg.commit(), HEAD + WIRE + b'NEXT')

    def test_bytewise_hold_retains_header_and_chunk_edits(self):
        msg = message(b'')
        msg.parts[0].http1.set_header('X-Held', 'yes')
        for byte in WIRE:
            msg = resume(checkpoint(msg), bytes([byte]))
        msg.parts[1].set_bytes(b'rewritten')
        self.assertIn(b'X-Held: yes', msg.commit())
        self.assertEqual(peer_body(msg.commit()), b'rewritten')

    def test_trailers_complete_only_after_final_crlf(self):
        wire = b'1\r\nx\r\n0\r\nX-Checksum: old\r\n\r\n'
        for cut in range(len(wire)):
            msg = resume(checkpoint(message(wire[:cut])), wire[cut:])
            self.assertEqual(msg.commit(), HEAD + wire)
        msg.parts[1].set_bytes(b'new')
        with self.assertRaisesRegex(CommitException, 'trailers'):
            msg.commit()
        self.assertEqual(peer_body(msg.commit(safety=Safety.Expert)), b'new')
        self.assertIn(b'X-Checksum: old', msg.commit(safety=Safety.Expert))

    def test_incomplete_edits_cannot_emit(self):
        msg = message(b'5\r\nab')
        msg.parts[1].set_bytes(b'replacement')
        with self.assertRaisesRegex(CommitException, 'Incomplete'):
            msg.commit()
        with self.assertRaisesRegex(CommitException, 'already edited'):
            resume(checkpoint(msg), b'cde\r\n0\r\n\r\n')

    def test_bad_framing_stays_opaque(self):
        for wire in (b'z\r\nx\r\n', b'1\r\nx!!', b'0\r\nbad trailer\r\n\r\n', b'ffffffff\r\n'):
            msg = message(wire)
            self.assertEqual(msg.parts[0].type, PartType.Opaque)
            self.assertEqual(msg.commit(), HEAD + wire)

    def test_framing_change_rejected_both_modes(self):
        for mode in (Safety.Easy, Safety.Expert):
            msg = message()
            msg.parts[0].http1.set_header('Content-Length', '5')
            with self.assertRaises(CommitException):
                msg.commit(safety=mode)

    def test_random_fragmentation_and_binary_payloads(self):
        rng = random.Random(9112)
        for case in range(100):
            pieces = [rng.randbytes(rng.randint(1, 128)) for _ in range(rng.randint(1, 8))]
            wire = b''.join(f'{len(p):X}\r\n'.encode() + p + b'\r\n' for p in pieces) + b'0\r\n\r\n'
            msg, offset = message(b''), 0
            while offset < len(wire):
                count = rng.randint(1, 33)
                msg = resume(checkpoint(msg), wire[offset:offset + count])
                offset += count
            self.assertEqual(msg.parts[1].get_bytes(), b''.join(pieces))
            self.assertEqual(msg.commit(), HEAD + wire)
            msg.parts[1].set_bytes(b'changed' * case)
            self.assertEqual(peer_body(msg.commit()), b'changed' * case)

    def test_chunk_edit_survives_hold(self):
        msg = message(b'3\r\nabc\r\n')
        msg.parts[1].chunks[0].set_bytes(b'longer')
        msg = resume(checkpoint(msg), b'2\r\nde\r\n0\r\n\r\n')
        self.assertEqual(peer_body(msg.commit()), b'longerde')

    def test_fresh_workers_hold_then_release_to_peer(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        sources = ('inspection_api.py', 'inspection_h2.py', 'inspection_hold.py',
                   'inspection_chunked.py', 'inspection_translate.py', 'inspection_language.py',
                   'inspection_sandbox.py', 'inspection_worker.py')
        from worker_bootstrap import packed
        worker = packed('\n'.join((root / 'src' / name).read_text() for name in sources))
        script = ('body = api.message.parts[1]\n'
                  'if not body.content.complete:\n'
                  '    api.message.parts.hold_from(api.message.parts[0])\n'
                  '    return api.message.commit()\n'
                  'body.set_bytes(b"changed body")\n'
                  'return api.message.commit()')
        held = None
        for index, data in enumerate((HEAD + WIRE[:6], WIRE[6:-1], WIRE[-1:])):
            info = {'side': 'R', 'content': base64.b64encode(data).decode()}
            if index == 0:
                info['content_annotations'] = [[0, 17, 'http1.start_line'],
                                               [17, len(HEAD), 'http1.headers']]
            request = {'script': script, 'hold_allowed': True, 'held_parts': held,
                       'instance': {'mode': 'flow'}, 'event': {'id': 'chunked', 'details': {'info': info}}}
            run = subprocess.run([sys.executable, '-I', '-c', worker], input=json.dumps(request),
                                 capture_output=True, text=True, check=True, timeout=10)
            result = json.loads(run.stdout)
            self.assertTrue(result['ok'], result)
            held = result['held_parts']
            if index < 2:
                self.assertTrue(result['need_more'])
                self.assertEqual(result['replacement'], '')
        self.assertIsNone(held)
        self.assertEqual(peer_body(base64.b64decode(result['replacement'])), b'changed body')


if __name__ == '__main__':
    unittest.main()
