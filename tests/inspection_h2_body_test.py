"""Logical H2 content over physical DATA: no duplicate emission or stream mixing."""
import unittest

from inspection_h2_test import frame, literal, message, unpack, Oracle
from inspection_hold_test import checkpoint, resume
from inspection_api import CommitException, Safety


def head(stream=1, flags=4):
    return frame(literal(b':status', b'200') + literal(b'content-length', b'6'), 1, flags, stream)


class BodyTests(unittest.TestCase):
    def test_views_and_noop(self):
        msg = message(head(), frame(b'abc', flags=0), frame(b'def'))
        body, = msg.bodies()
        self.assertTrue(body.complete)
        self.assertEqual(body.get_bytes(), b'abcdef')
        self.assertIs(body.chunks[0], msg.parts[1])
        self.assertEqual(msg.commit(), msg.bytes)
        body.chunks[0].set_bytes(b'ABC')
        self.assertEqual(body.get_bytes(), b'ABCdef')
        with self.assertRaises(CommitException):
            body.set_bytes(b'new')

    def test_resize_interleaved_streams_both_modes(self):
        for mode in (Safety.Easy, Safety.Expert):
            for replacement in (b'', b'x', b'longer body', b'a' * 40000):
                msg = message(head(), frame(b'abc', flags=0), head(3),
                              frame(b'123456', stream=3), frame(b'def'))
                first, second = msg.bodies()
                first.set_bytes(replacement)
                frames = unpack(msg.commit(safety=mode))
                self.assertEqual(second.get_bytes(), b'123456')
                self.assertEqual(b''.join(p for t, f, s, p in frames if t == 0 and s == 1), replacement)
                self.assertEqual([p for t, f, s, p in frames if t == 0 and s == 3], [b'123456'])
                self.assertEqual(sum(bool(f & 1) for t, f, s, p in frames if t == 0 and s == 1), 1)
                fields = Oracle().decode(frames[0][3])
                self.assertIn((b'content-length', str(len(replacement)).encode()), fields)

    def test_frame_complete_is_not_content_complete(self):
        msg = message(head(), frame(b'abc', flags=0))
        body, = msg.bodies()
        self.assertTrue(body.chunks[0].complete)
        self.assertFalse(body.complete)
        with self.assertRaises(CommitException):
            body.set_bytes(b'new')

    def test_partial_data_every_payload_cut(self):
        tail = frame(b'abcdef')
        for cut in range(9, len(tail)):
            msg = message(head(), tail[:cut])
            body, = msg.bodies()
            self.assertFalse(body.chunks[0].complete)
            self.assertFalse(body.complete)
            with self.assertRaises(CommitException):
                body.get_bytes()
            msg = resume(checkpoint(msg), tail[cut:])
            self.assertTrue(msg.bodies()[0].complete)
            self.assertEqual(msg.bodies()[0].get_bytes(), b'abcdef')

    def test_end_stream_trailers_after_hold(self):
        msg = message(head(), frame(b'abcdef', flags=0))
        trailer = frame(literal(b'x-end', b'yes'), 1, 5)
        msg = resume(checkpoint(msg), trailer, {'content_annotations': [[0, 9, 'h2.frame.header']]})
        body, = msg.bodies()
        self.assertTrue(body.complete)
        body.set_bytes(b'longer body')
        self.assertEqual(unpack(msg.commit())[-1], unpack(trailer)[0])

    def test_incomplete_trailer_block_does_not_complete_content(self):
        block = literal(b'x-trailer', b'value')
        for cut in range(1, len(block)):
            msg = message(head(), frame(b'abcdef', flags=0), frame(block[:cut], 1, 1))
            self.assertFalse(msg.parts[-1].complete)
            self.assertFalse(msg.bodies()[0].complete)
            continuation = frame(block[cut:], 9, 4)
            msg = resume(checkpoint(msg), continuation,
                         {'content_annotations': [[0, 9, 'h2.frame.header']]})
            self.assertTrue(msg.parts[-1].complete)
            self.assertTrue(msg.bodies()[0].complete)

    def test_padded_data_is_logical_and_padding_survives(self):
        msg = message(head(), frame(b'\x02abcdefpp', flags=9))
        body, = msg.bodies()
        self.assertEqual(body.get_bytes(), b'abcdef')
        body.set_bytes(b'ABCDEF')
        self.assertEqual(unpack(msg.commit())[-1][3], b'\x02ABCDEFpp')

    def test_unknown_gap_and_reset_do_not_complete_body(self):
        for gap in (b'unknown', frame(b'\0' * 4, 3, 0)):
            msg = message(head(), frame(b'abc', flags=0), gap, frame(b'def'))
            self.assertFalse(msg.bodies()[0].complete)

    def test_header_only_and_no_duplicate_emission(self):
        msg = message(head(flags=5))
        body, = msg.bodies()
        self.assertTrue(body.complete)
        body.set_bytes(b'')
        with self.assertRaises(CommitException):
            body.set_bytes(b'x')
        msg.parts.append(body)
        with self.assertRaises(CommitException):
            msg.commit()

    def test_translate_keeps_existing_resize_guard(self):
        from inspection_translate_settings_test import Connection
        for replacement in (b'ABCDEF', b'longer content'):
            connection = Connection()
            msg = connection.message('R', head() + frame(b'abc', flags=0) + frame(b'def'))
            msg.bodies()[0].set_bytes(replacement)
            if len(replacement) == 6:
                wire = connection.publish('R', msg)
                self.assertEqual(b''.join(p for t, f, s, p in unpack(wire) if t == 0), replacement)
            else:
                with self.assertRaises(CommitException):
                    connection.publish('R', msg)


if __name__ == '__main__':
    unittest.main()
