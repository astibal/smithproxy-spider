"""Lazy Body content coding across H1 framing and H2 DATA; physical views stay raw."""
import base64
import gzip
import hashlib
import json
import unittest
from unittest.mock import patch
import zlib

from inspection_h2_test import message as h2_message, frame, literal, unpack, Oracle
from inspection_chunked_test import message as chunk_message, peer_body
from inspection_hold_test import checkpoint, resume
from inspection_api import Message, CommitException, Safety


def compress(data, coding):
    return gzip.compress(data, mtime=123) if coding == 'gzip' else zlib.compress(data)


def fixture(kind, coding, data=b'hello world', encoded=None):
    encoded = compress(data, coding) if encoded is None else encoded
    if kind == 'h2':
        head = literal(b':status', b'200') + literal(b'content-encoding', coding.encode())
        head += literal(b'content-length', str(len(encoded)).encode())
        split = len(encoded) // 2
        return h2_message(frame(head, 1, 4), frame(encoded[:split], flags=0), frame(encoded[split:]))
    head = b'HTTP/1.1 200 OK\r\nContent-Encoding: ' + coding.encode() + b'\r\n'
    if kind == 'chunked':
        head += b'Transfer-Encoding: chunked\r\n\r\n'
        wire = f'{len(encoded):x}\r\n'.encode() + encoded + b'\r\n0\r\n\r\n'
        return chunk_message(wire, head)
    head += f'Content-Length: {len(encoded)}\r\n\r\n'.encode()
    return Message(head + encoded, len(head + encoded), {'content_annotations': [
        [0, 17, 'http1.start_line'], [17, len(head), 'http1.headers']]})


def coded_output(kind, wire):
    if kind == 'h2':
        frames = unpack(wire)
        data = b''.join(p for t, f, s, p in frames if t == 0)
        assert (b'content-length', str(len(data)).encode()) in Oracle().decode(frames[0][3])
        return data
    return peer_body(wire)


class CompressionTests(unittest.TestCase):
    def test_lazy_noop_cache_and_equal_plaintext(self):
        for kind in ('h1', 'chunked', 'h2'):
            for coding in ('gzip', 'deflate'):
                with self.subTest(kind=kind, coding=coding):
                    msg = fixture(kind, coding)
                    with patch('zlib.decompressobj', side_effect=AssertionError('not lazy')):
                        self.assertEqual(msg.commit(), msg.bytes)
                    body = msg.bodies()[0]
                    self.assertEqual(body.get_bytes(), b'hello world')
                    with patch('zlib.decompressobj', side_effect=AssertionError('cache missed')):
                        self.assertEqual(body.get_bytes(), b'hello world')
                        self.assertEqual(msg.commit(), msg.bytes)
                    body.set_bytes(b'hello world')
                    self.assertEqual(msg.commit(), msg.bytes)

    def test_edits_are_encoded_only_at_commit(self):
        for kind in ('h1', 'chunked', 'h2'):
            for coding in ('gzip', 'deflate'):
                for value in (b'', b'new', bytes(range(256)) * 20):
                    msg = fixture(kind, coding)
                    body = msg.bodies()[0]
                    with patch('zlib.compressobj', side_effect=AssertionError('eager encode')):
                        body.set_bytes(value)
                        self.assertEqual(body.get_bytes(), value)
                    for safety in (Safety.Easy, Safety.Expert):
                        wire = msg.commit(safety=safety)
                        encoded = coded_output(kind, wire)
                        decoded = gzip.decompress(encoded) if coding == 'gzip' else zlib.decompress(encoded)
                        self.assertEqual(decoded, value)
                        self.assertEqual(msg.commit(safety=safety), wire)

    def test_invalid_truncated_trailing_and_multiple_members(self):
        good = compress(b'hello', 'gzip')
        for encoded in (b'garbage', good[:-1], good + b'x', good + good):
            for kind in ('h1', 'chunked', 'h2'):
                msg = fixture(kind, 'gzip', encoded=encoded)
                self.assertEqual(msg.commit(), msg.bytes)
                with self.assertRaises(CommitException):
                    msg.bodies()[0].get_bytes()

    def test_bomb_and_unsupported_coding(self):
        for coding, encoded in (('gzip', compress(b'x' * (1024 * 1024 + 1), 'gzip')),
                                ('br', b'unknown'), ('gzip, deflate', b'unknown'),
                                ('deflate', zlib.compress(b'raw')[2:-4])):
            for kind in ('h1', 'chunked', 'h2'):
                msg = fixture(kind, coding, encoded=encoded)
                self.assertEqual(msg.commit(), msg.bytes)
                with self.assertRaises(CommitException):
                    msg.bodies()[0].get_bytes()

    def test_h1_hold_and_pending_plaintext_checkpoint(self):
        for kind in ('h1', 'chunked'):
            full = fixture(kind, 'gzip')
            cut = full.bytes.index(b'\r\n\r\n') + 5
            head_end = cut - 1
            partial = Message(full.bytes[:cut], cut, {'content_annotations': [
                [0, 17, 'http1.start_line'], [17, head_end, 'http1.headers']]})
            with self.assertRaises(CommitException):
                partial.bodies()[0].get_bytes()
            msg = resume(checkpoint(partial), full.bytes[cut:])
            body = msg.bodies()[0]
            self.assertEqual(body.get_bytes(), b'hello world')
            body.set_bytes(b'after hold')
            msg = resume(checkpoint(msg), b'')
            self.assertEqual(gzip.decompress(coded_output(kind, msg.commit())), b'after hold')

    def test_h2_pending_hold_and_physical_conflict(self):
        msg = fixture('h2', 'gzip')
        body = msg.bodies()[0]
        body.set_bytes(b'after hold')
        msg = resume(checkpoint(msg), b'')
        self.assertEqual(gzip.decompress(coded_output('h2', msg.commit())), b'after hold')
        msg.bodies()[0].chunks[0].set_bytes(b'conflict')
        with self.assertRaises(CommitException):
            msg.commit()

    def test_h2_compressed_frame_fragmentation(self):
        full = fixture('h2', 'gzip')
        head, first, last = [bytes(part._wire) for part in full.parts]
        for cut in range(9, len(last)):
            msg = h2_message(head, first, last[:cut])
            with self.assertRaises(CommitException):
                msg.bodies()[0].get_bytes()
            msg = resume(checkpoint(msg), last[cut:])
            self.assertEqual(msg.bodies()[0].get_bytes(), b'hello world')
            self.assertEqual(msg.commit(), full.bytes)

    def test_exact_decoded_limit_and_cache_not_checkpointed(self):
        for kind in ('h1', 'chunked', 'h2'):
            msg = fixture(kind, 'gzip', b'x' * (1024 * 1024))
            self.assertEqual(len(msg.bodies()[0].get_bytes()), 1024 * 1024)
            held = checkpoint(msg)
            self.assertNotIn('_decoded_body', json.dumps(held))
            self.assertLess(len(json.dumps(held)), 20000)

    def test_translate_rejects_changed_encoded_length_atomically(self):
        from inspection_translate_settings_test import Connection
        connection = Connection()
        original = fixture('h2', 'gzip').bytes
        msg = connection.message('R', original)
        body = msg.bodies()[0]
        body.set_bytes(bytes(range(256)) * 10)
        with self.assertRaises(CommitException):
            connection.publish('R', msg)
        self.assertTrue(all(part._pending is None for part in body.chunks))
        body.set_bytes(b'hello world')
        wire = connection.publish('R', msg)
        self.assertEqual(gzip.decompress(coded_output('h2', wire)), b'hello world')

    def test_h1_digest_covers_encoded_content(self):
        for kind in ('h1', 'chunked'):
            msg = fixture(kind, 'gzip')
            msg.parts[0].http1.set_header('Content-Digest', 'sha-256=:AA==:')
            msg.bodies()[0].set_bytes(b'new content')
            wire = msg.commit()
            expected = base64.b64encode(hashlib.sha256(coded_output(kind, wire)).digest())
            self.assertIn(b'Content-Digest: sha-256=:' + expected + b':', wire)

    def test_limits_and_encoding_changes(self):
        for kind in ('h1', 'chunked', 'h2'):
            msg = fixture(kind, 'gzip')
            with self.assertRaises(CommitException):
                msg.bodies()[0].set_bytes(b'x' * (1024 * 1024 + 1))
            msg.bodies()[0].set_bytes(b'new')
            if kind == 'h2':
                msg.parts[0].headers.set_header(b'content-encoding', b'deflate')
            else:
                msg.parts[0].http1.set_header('Content-Encoding', 'deflate')
            for mode in (Safety.Easy, Safety.Expert):
                with self.assertRaises(CommitException):
                    msg.commit(safety=mode)

    def test_fresh_sandboxed_workers(self):
        from inspection_cookbook_test import run
        for kind in ('h1', 'chunked', 'h2'):
            for coding in ('gzip', 'deflate'):
                msg = fixture(kind, coding)
                if kind == 'h2':
                    annotations, offset = [], 0
                    for part in msg.parts:
                        annotations.append([offset, offset + 9, 'h2.frame.header'])
                        offset += len(part._wire)
                else:
                    head_end = msg.bytes.index(b'\r\n\r\n') + 4
                    annotations = [[0, 17, 'http1.start_line'], [17, head_end, 'http1.headers']]
                event = {'id': 'compressed', 'details': {'info': {
                    'side': 'R', 'content': base64.b64encode(msg.bytes).decode(),
                    'content_annotations': annotations}}}
                script = ('body = api.message.bodies()[0]\n'
                          'assert body.get_bytes() == b"hello world"\n'
                          'body.set_bytes(b"worker replacement")\n'
                          'return api.message.commit()')
                result = run(script, event)
                self.assertTrue(result['ok'], result)
                encoded = coded_output(kind, base64.b64decode(result['replacement']))
                plain = gzip.decompress(encoded) if coding == 'gzip' else zlib.decompress(encoded)
                self.assertEqual(plain, b'worker replacement')


if __name__ == '__main__':
    unittest.main()
