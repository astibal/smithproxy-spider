"""Deterministic fragment boundaries, typed drafts and HPACK publication."""
import base64
import json
import re
from pathlib import Path
import sys
import unittest

import hpack

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import Message, HeldCommit, CommitException, PartType, _prepare_translation
from inspection_h2_test import frame, unpack, Oracle
from inspection_translate_worker_test import event
from inspection_cookbook_test import run

PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
DOCUMENT = Path(__file__).resolve().parents[1] / 'docs/H2_TRANSLATE_LIVE.md'
SCRIPT = re.search(r'<!-- translate-example: hold-incomplete -->\s*```python\n(.*?)```',
                   DOCUMENT.read_text(), re.S).group(1)


class Connection:
    def __init__(self):
        self.state = None
        self.held = None

    def message(self, data):
        message = Message(data, len(data), {'content_annotations': [[0, 9, 'h2.frame.header']]})
        _prepare_translation(message, {
            'translate_allowed': self.state is None, 'translate_active': self.state is not None,
            'translate_state': self.state, 'held_parts': self.held,
        })
        return message

    def publish(self, message):
        result = message.translate()
        self.state = json.loads(json.dumps(message._translation.checkpoint))
        self.held = json.loads(json.dumps(result.checkpoint)) if isinstance(result, HeldCommit) else None
        return result.prefix if isinstance(result, HeldCommit) else result

    def feed(self, data):
        message = self.message(data)
        for part in message.parts:
            if not part.complete:
                message.parts.hold_from(part)
                break
            if part.headers is not None:
                part.headers.set_header(b'x-lab', b'changed')
        return self.publish(message)


class TranslateHoldTests(unittest.TestCase):
    def payload(self):
        encoder = hpack.Encoder()
        fields = [(b':method', b'GET'), (b'x-lab', b'original')]
        block = encoder.encode(fields, huffman=False)
        head = frame(block[:4], 1, 1, 1) + frame(block[4:], 9, 4, 1)
        indexed = frame(encoder.encode(fields), 1, 5, 3)
        return PREFACE + frame(b'', 4, 0, 0) + head + indexed

    def check_output(self, output):
        self.assertTrue(output.startswith(PREFACE))
        decoder = Oracle()
        decoded = []
        for typ, flags, stream, data in unpack(output[len(PREFACE):]):
            if typ == 1:
                decoded.append(decoder.decode(data))
        self.assertEqual(decoded, [[(b':method', b'GET'), (b'x-lab', b'changed')]] * 2)

    def test_every_two_piece_boundary_and_single_bytes(self):
        wire = self.payload()
        for split in range(1, len(wire)):
            with self.subTest(split=split):
                connection = Connection()
                output = connection.feed(wire[:split]) + connection.feed(wire[split:])
                self.assertIsNone(connection.held)
                self.check_output(output)

        connection = Connection()
        output = b''.join(connection.feed(bytes([byte])) for byte in wire)
        self.assertIsNone(connection.held)
        self.check_output(output)

    def test_complete_held_draft_does_not_advance_input_table(self):
        connection = Connection()
        connection.feed(PREFACE)
        encoder = hpack.Encoder()
        wire = frame(encoder.encode([(b'x-lab', b'original')]), 1, 4)
        message = connection.message(wire)
        message.parts[0].headers.set_header(b'x-lab', b'held-edit')
        message.parts.hold_from(message.parts[0])
        self.assertEqual(connection.publish(message), b'')
        self.assertEqual(connection.state['input']['entries'], [])

        message = connection.message(frame(encoder.encode([(b'x-lab', b'original')]), 1, 4))
        output = connection.publish(message)
        decoder = Oracle()
        values = [decoder.decode(data) for _, _, _, data in unpack(output)]
        self.assertEqual(values, [[(b'x-lab', b'held-edit')], [(b'x-lab', b'original')]])
        self.assertEqual(len(connection.state['input']['entries']), 1)

    def test_prefix_is_emitted_once_and_tail_requires_explicit_hold(self):
        connection = Connection()
        connection.feed(PREFACE)
        ping = frame(b'12345678', 6, 0, 0)
        wire = frame(b'\x82', 1, 4)
        message = connection.message(ping + wire[:5])
        with self.assertRaisesRegex(CommitException, 'hold_from'):
            message.translate()
        message.parts.hold_from(message.parts[-1])
        self.assertEqual(connection.publish(message), ping)
        output = connection.feed(wire[5:])
        self.assertEqual([entry[0] for entry in unpack(output)], [1])

    def test_prefix_and_held_header_publish_distinct_table_positions(self):
        connection = Connection()
        connection.feed(PREFACE)
        encoder, decoder = hpack.Encoder(), Oracle()
        first = frame(encoder.encode([(b'x', b'a')]), 1, 4, 1)
        second = frame(encoder.encode([(b'x', b'b')]), 1, 4, 3)
        message = connection.message(first + second)
        message.parts[1].headers.set_header(b'x', b'held-b')
        message.parts.hold_from(message.parts[1])
        prefix = connection.publish(message)
        self.assertEqual(decoder.decode(unpack(prefix)[0][3]), [(b'x', b'a')])
        self.assertEqual(len(connection.state['input']['entries']), 1)

        third = frame(encoder.encode([(b'x', b'a')]), 1, 4, 5)
        rest = connection.publish(connection.message(third))
        self.assertEqual([decoder.decode(data) for _, _, _, data in unpack(rest)],
                         [[(b'x', b'held-b')], [(b'x', b'a')]])
        self.assertEqual(len(connection.state['input']['entries']), 2)

    def test_failed_checkpoint_keeps_draft_and_allows_retry(self):
        connection = Connection()
        connection.feed(PREFACE)
        wire = frame(hpack.Encoder().encode([(b'x', b'a')]), 1, 4)
        message = connection.message(wire)
        part = message.parts[0]
        part.headers.set_header(b'x', b'edited')
        headers = part.headers
        part._oversize = b'x' * (1024 * 1024)
        message.parts.hold_from(part)

        with self.assertRaisesRegex(CommitException, 'hold exceeds'):
            message.translate()

        self.assertIs(part.headers, headers)
        self.assertFalse(hasattr(part, '_translate_draft'))
        self.assertIsNone(message._translation.result)
        del part._oversize
        self.assertEqual(connection.publish(message), b'')
        output = connection.publish(connection.message(b''))
        self.assertEqual(Oracle().decode(unpack(output)[0][3]), [(b'x', b'edited')])

    def test_incomplete_edits_are_rejected_before_publishing_prefix(self):
        connection = Connection()
        connection.feed(PREFACE)
        message = connection.message(frame(b'12345678', 6, 0, 0) + b'\0')
        tail = message.parts[-1]
        tail.set_bytes(b'edited')
        message.parts.hold_from(tail)
        with self.assertRaisesRegex(CommitException, 'edited incomplete'):
            message.translate()
        self.assertIsNone(message._translation.result)

    def test_candidate_enrichment_does_not_change_ordinary_rewrite_bytes(self):
        wire = self.payload()
        message = Connection().message(wire)
        self.assertEqual(message.commit(), wire)

    def test_continuation_must_match_stream_and_be_contiguous(self):
        for following in (frame(b'x', 9, 4, 5), frame(b'12345678', 6, 0, 0)):
            connection = Connection()
            connection.feed(PREFACE)
            connection.feed(frame(b'\x82', 1, 0, 3))
            with self.assertRaisesRegex(CommitException, 'CONTINUATION'):
                connection.message(following)

    def test_real_fresh_workers_keep_hold_and_tables_separate(self):
        wire = self.payload()
        cuts = (1, 24, 27, 34, 40, 47, len(wire) - 1, len(wire))
        previous, held, state, output = 0, None, None, b''
        for cut in cuts:
            result = run(SCRIPT, event(wire[previous:cut]),
                         translate_allowed=state is None, translate_active=state is not None,
                         translate_state=state, held_parts=held, hold_allowed=True,
                         instance={'mode': 'flow'})
            self.assertTrue(result['ok'], result)
            state, held = result['translate_state'], result['held_parts']
            output += base64.b64decode(result['replacement'])
            previous = cut
        self.assertIsNone(held)
        self.check_output(output)

        failure = run('return api.message.translate()', event(b'\0'),
                      translate_active=True, translate_state=state,
                      hold_allowed=True, instance={'mode': 'flow'})
        self.assertFalse(failure['ok'])
        self.assertIsNone(failure['replacement'])
        self.assertNotIn('translate_state', failure)


if __name__ == '__main__':
    unittest.main()
