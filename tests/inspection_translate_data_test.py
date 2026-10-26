"""Same-length DATA edits preserve transport geometry and held drafts."""
import base64
import re
import unittest
from pathlib import Path

from inspection_translate_settings_test import Connection
from inspection_api import CommitException
from inspection_h2_test import frame, unpack
from inspection_translate_worker_test import event
from inspection_cookbook_test import run


class DataTests(unittest.TestCase):
    def test_padding_flags_streams_and_lengths(self):
        for side in ('L', 'R'):
            for size in (0, 1, 255, 16000):
                for padding in (None, 0, 17):
                    for end_stream in (0, 1):
                        with self.subTest(side=side, size=size, padding=padding, end=end_stream):
                            body = b'a' * size
                            flags = end_stream | (8 if padding is not None else 0)
                            payload = body if padding is None else bytes([padding]) + body + b'p' * padding
                            wire = frame(payload, 0, flags, 7)
                            connection = Connection()
                            message = connection.message(side, wire)
                            message.parts[0].set_bytes(b'b' * size)
                            output = connection.publish(side, message)
                            expected = b'b' * size if padding is None else bytes([padding]) + b'b' * size + b'p' * padding
                            self.assertEqual(output, frame(expected, 0, flags, 7))
                            self.assertEqual(output[:9], wire[:9])

    def test_interleaved_streams_and_control_frames(self):
        connection = Connection()
        wire = (frame(b'aaa', 0, 0, 1) + frame(b'12345678', 6, 0, 0) +
                frame(b'bbb', 0, 1, 3) + frame(b'ccc', 0, 1, 1))
        message = connection.message('L', wire)
        for part in message.parts:
            if part.frame_type == 0 and part.stream_id == 1:
                part.set_bytes(part.get_bytes().upper())
        output = connection.publish('L', message)
        self.assertEqual([data for _, _, _, data in unpack(output)],
                         [b'AAA', b'12345678', b'bbb', b'CCC'])

    def test_invalid_edits_are_atomic_and_retryable(self):
        for attribute, value in [('flags', 1), ('stream_id', 3), ('frame_type', 6),
                                 ('bytes', b''), ('bytes', b'longer')]:
            with self.subTest(attribute=attribute):
                connection = Connection()
                wire = frame(b'abc', 0, 0, 1)
                message = connection.message('L', wire)
                part = message.parts[0]
                if attribute == 'bytes':
                    part.set_bytes(value)
                else:
                    setattr(part, attribute, value)
                with self.assertRaises(CommitException):
                    connection.publish('L', message)
                self.assertIsNone(connection.control)
                self.assertIsNone(message._translation.result)
                part.frame_type, part.flags, part.stream_id = part._initial
                part.set_bytes(b'XYZ')
                self.assertEqual(connection.publish('L', message), frame(b'XYZ', 0, 0, 1))

    def test_complete_held_edit_and_fragmented_tail(self):
        connection = Connection()
        first = frame(b'abc', 0, 0, 1)
        second = frame(b'def', 0, 1, 1)
        message = connection.message('L', first + second[:10])
        message.parts[0].set_bytes(b'ABC')
        message.parts.hold_from(message.parts[0])
        self.assertEqual(connection.publish('L', message), b'')
        message = connection.message('L', second[10:])
        message.parts[1].set_bytes(b'DEF')
        self.assertEqual(connection.publish('L', message), frame(b'ABC', 0, 0, 1) + frame(b'DEF', 0, 1, 1))

    def test_every_fragment_boundary_with_opposite_direction(self):
        wire = frame(b'\x02secretpp', 0, 9, 1)
        for split in range(1, len(wire)):
            with self.subTest(split=split):
                connection = Connection()
                connection.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
                message = connection.message('L', wire[:split])
                message.parts.hold_from(message.parts[0])
                self.assertEqual(connection.publish('L', message), b'')
                reverse = frame(b'other', 0, 1, 3)
                self.assertEqual(connection.feed('R', reverse), reverse)
                message = connection.message('L', wire[split:])
                message.parts[0].set_bytes(b'******')
                self.assertEqual(connection.publish('L', message), frame(b'\x02******pp', 0, 9, 1))

    def test_worker_success_and_length_failure(self):
        wire = frame(b'secret', 0, 1, 1)
        for value, success in [('******', True), ('x', False)]:
            script = f'api.message.parts[0].set_bytes(b"{value}")\nreturn api.message.translate()'
            result = run(script, event(wire), translate_allowed=True)
            self.assertEqual(result['ok'], success, result)
            if success:
                self.assertEqual(base64.b64decode(result['replacement']), frame(b'******', 0, 1, 1))
            else:
                self.assertIsNone(result['replacement'])
                self.assertNotIn('translate_state', result)

    def test_documented_example_in_worker(self):
        documentation = (Path(__file__).resolve().parents[1] / 'docs/H2_TRANSLATE_LIVE.md').read_text()
        script = re.search(r'<!-- translate-example: data-redaction -->\s*```python\n(.*?)```',
                           documentation, re.S).group(1)
        wire = frame(b'secret', 0, 1, 1)
        result = run(script, event(wire), translate_allowed=True, instance={'mode': 'flow'})
        self.assertTrue(result['ok'], result)
        self.assertEqual(base64.b64decode(result['replacement']), frame(b'******', 0, 1, 1))


if __name__ == '__main__':
    unittest.main()
