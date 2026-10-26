"""PUSH_PROMISE uses the same directional HPACK history as HEADERS."""
import base64
import json
import re
import unittest
from pathlib import Path

import hpack
from inspection_translate_settings_test import Connection, settings, ACK
from inspection_api import CommitException, HeldCommit, Safety
from inspection_h2_test import frame, unpack, Oracle
from inspection_cookbook_test import run
from inspection_translate_worker_test import event


FIELDS = [(b':method', b'GET'), (b':scheme', b'https'),
          (b':authority', b'lab.test'), (b':path', b'/asset'), (b'x-lab', b'original')]


def push(block, padding=0, split=None):
    prefix = (b'\x02' if padding else b'') + (2).to_bytes(4, 'big')
    suffix = b'pp' if padding else b''
    flags = 8 if padding else 0
    if split is None:
        return frame(prefix + block + suffix, 5, flags | 4, 1)
    return (frame(prefix + block[:split] + suffix, 5, flags, 1) +
            frame(block[split:], 9, 4, 1))


def header_block(wire):
    frames = unpack(wire)
    first = frames[0][3]
    padded = bool(frames[0][1] & 8)
    pad = first[0] if padded else 0
    start = int(padded) + (4 if frames[0][0] == 5 else 0)
    return first[start:len(first) - pad] + b''.join(f[3] for f in frames[1:])


class ModeConnection(Connection):
    def __init__(self, safety):
        super().__init__()
        self.safety = safety

    def publish(self, side, message):
        result = message.translate(safety=self.safety)
        transaction = message._translation
        self.tables[side] = json.loads(json.dumps(transaction.checkpoint))
        self.control = json.loads(json.dumps(transaction.control_checkpoint))
        self.held[side] = result.checkpoint if isinstance(result, HeldCommit) else None
        return result.prefix if isinstance(result, HeldCommit) else result


class PushTests(unittest.TestCase):
    def test_shared_history_and_padding(self):
        for mode in (Safety.Easy, Safety.Expert):
            for padding in (0, 2):
                sender, receiver = hpack.Encoder(), Oracle()
                connection = ModeConnection(mode)
                message = connection.message('R', push(sender.encode(FIELDS), padding, 3))
                message.parts[0].headers.set_header(b'x-lab', b'changed')
                output = connection.publish('R', message)
                self.assertIn((b'x-lab', b'changed'), receiver.decode(header_block(output)))
                self.assertEqual(unpack(output)[0][3][:5 if padding else 4],
                                 (b'\x02' if padding else b'') + b'\x00\x00\x00\x02')
                # A later indexed HEADERS uses the sender's original value,
                # not the value we inserted into the receiver's table.
                indexed = sender.encode(FIELDS)
                self.assertLess(len(indexed), 10)
                output = connection.feed('R', frame(indexed, 1, 4, 2))
                self.assertEqual(receiver.decode(header_block(output)), FIELDS)

    def test_all_split_boundaries_and_held_draft(self):
        wire = push(hpack.Encoder().encode(FIELDS), 2, 3)
        for mode in (Safety.Easy, Safety.Expert):
            for split in range(1, len(wire)):
                connection = ModeConnection(mode)
                connection.feed('R', settings())
                message = connection.message('R', wire[:split])
                message.parts.hold_from(message.parts[0])
                self.assertEqual(connection.publish('R', message), b'')
                self.assertEqual(connection.feed('L', frame(b'abcdefgh', 6, 0, 0)),
                                 frame(b'abcdefgh', 6, 0, 0))
                message = connection.message('R', wire[split:])
                message.parts[0].headers.set_header(b'x-lab', b'held')
                message.parts.hold_from(message.parts[0])
                self.assertEqual(connection.publish('R', message), b'')
                output = connection.feed('R', b'')
                self.assertIn((b'x-lab', b'held'), Oracle().decode(header_block(output)))

    def test_enable_push_ack_boundary(self):
        connection = Connection()
        connection.feed('L', settings((2, 0)))
        connection.feed('R', push(hpack.Encoder().encode(FIELDS)))
        connection.feed('R', ACK)
        with self.assertRaises(CommitException):
            connection.feed('R', push(hpack.Encoder().encode(FIELDS)))

    def test_emitted_push_prefix_and_held_indexed_headers(self):
        for mode in (Safety.Easy, Safety.Expert):
            sender, receiver = hpack.Encoder(), Oracle()
            connection = ModeConnection(mode)
            wire = push(sender.encode(FIELDS)) + frame(sender.encode(FIELDS), 1, 4, 2)
            message = connection.message('R', wire)
            message.parts[0].headers.set_header(b'x-lab', b'changed')
            message.parts.hold_from(message.parts[1])
            prefix = connection.publish('R', message)
            self.assertIn((b'x-lab', b'changed'), receiver.decode(header_block(prefix)))
            suffix = connection.feed('R', b'')
            self.assertEqual(receiver.decode(header_block(suffix)), FIELDS)

    def test_documented_example(self):
        document = (Path(__file__).resolve().parents[1] / 'docs/H2_TRANSLATE_LIVE.md').read_text()
        section = document.split('## PUSH_PROMISE\n', 1)[1]
        script = re.search(r'```python\n(.*?)```', section, re.S).group(1)
        wire = push(hpack.Encoder().encode(FIELDS))
        result = run(script, event(wire, 'R'), translate_allowed=True)
        self.assertTrue(result['ok'], result)
        output = base64.b64decode(result['replacement'])
        self.assertIn((b'x-lab', b'push-inspected'), Oracle().decode(header_block(output)))

    def test_invalid_envelope_and_continuation(self):
        wire = push(hpack.Encoder().encode(FIELDS))
        for side, invalid in [('L', wire), ('R', frame(b'\0\0\0\0', 5, 4, 1)),
                              ('R', frame(b'\0\0\0\3', 5, 4, 1)),
                              ('R', frame(b'\0\0\0\2', 5, 4, 0)),
                              ('R', frame(b'\0\0\0\2', 5, 0, 1) + frame(b'', 9, 4, 3))]:
            with self.subTest(side=side, invalid=invalid), self.assertRaises(CommitException):
                Connection().feed(side, invalid)

    def test_edits_are_atomic_and_geometry_is_fixed(self):
        for mode in (Safety.Easy, Safety.Expert):
            for attribute, value in [('stream_id', 3), ('flags', 0), ('frame_type', 1)]:
                connection = ModeConnection(mode)
                message = connection.message('R', push(hpack.Encoder().encode(FIELDS)))
                setattr(message.parts[0], attribute, value)
                with self.assertRaises(CommitException):
                    connection.publish('R', message)
                self.assertIsNone(message._translation.result)
                self.assertEqual(connection.tables, {})

    def test_large_output_continuation(self):
        connection = Connection()
        message = connection.message('R', push(hpack.Encoder().encode(FIELDS), 2))
        message.parts[0].headers.set_header(b'x-large', bytes(range(32, 127)) * 400)
        output = connection.publish('R', message)
        frames = unpack(output)
        self.assertGreater(len(frames), 1)
        self.assertEqual(frames[0][0], 5)
        self.assertTrue(all(f[0] == 9 and f[2] == 1 for f in frames[1:]))
        self.assertTrue(frames[-1][1] & 4)
        self.assertEqual(dict(Oracle().decode(header_block(output)))[b'x-large'],
                         bytes(range(32, 127)) * 400)

    def test_fresh_sandbox_workers_share_push_history(self):
        for mode in ('Easy', 'Expert'):
            sender, receiver, state, control = hpack.Encoder(), Oracle(), None, None
            for turn in range(2):
                block = sender.encode(FIELDS)
                wire = push(block) if turn == 0 else frame(block, 1, 4, 2)
                script = ('for part in api.message.parts:\n'
                          '    if part.frame_type == 5:\n'
                          '        part.headers.set_header(b"x-lab", b"changed")\n'
                          f'return api.message.translate(safety=Safety.{mode})')
                result = run(script, event(wire, 'R'), translate_allowed=turn == 0,
                             translate_active=turn != 0, translate_state=state,
                             translate_control=control)
                self.assertTrue(result['ok'], result)
                state, control = result['translate_state'], result['translate_control']
                fields = receiver.decode(header_block(base64.b64decode(result['replacement'])))
                self.assertEqual(dict(fields)[b'x-lab'], b'changed' if turn == 0 else b'original')


if __name__ == '__main__':
    unittest.main()
