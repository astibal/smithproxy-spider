"""Contract mock: need-more consumes this callback, replace emits only its content.

This does not assert that a deployed Smithproxy supports that contract yet.

Run from the repository root (coverage.py is an optional test dependency):
    python3 -m coverage run --branch --source=inspection_parts tests/inspection_parts_test.py
    python3 -m coverage report --fail-under=100 -m

Matrices and seeded generators deliberately run without third-party test libraries.
Fault injection exercises the final commit validation gate independently of the
snapshot validator. Mock failures retain held data, but are not a production
timeout, disconnect, worker-serialization or deployment-retirement policy.
"""
import pathlib
import sys
import unittest
import itertools
import random
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import CommitException
from inspection_parts import Http1Message, PartType, Replace, assemble


def request(body=b'', length=None, extra=b''):
    length = str(len(body)).encode() if length is None else length
    return (b'POST / HTTP/1.1\r\nHost: example.test\r\n' + extra
            + b'Content-Length: ' + length + b'\r\n\r\n' + body)


class ReplacementTests(unittest.TestCase):
    def test_all_single_ranges_and_sizes(self):
        source = bytes(range(16))

        for start in range(17):
            for size in range(17 - start):
                for replacement in (b'', b'x', b'longer replacement', bytes(range(256))):
                    with self.subTest(start=start, size=size, replacement=len(replacement)):
                        self.assertEqual(assemble(source, [Replace(start, size, replacement)]),
                                         source[:start] + replacement + source[start + size:])

    def test_exhaustive_pair_conflicts(self):
        source = b'abcdef'
        ranges = [(start, size) for start in range(7) for size in range(7 - start)]

        for first, second in itertools.product(ranges, repeat=2):
            changes = [Replace(*first, b'ONE'), Replace(*second, b'TWO')]
            earlier, later = sorted(changes, key=lambda item: item.start + item.length)
            occupied_a = set(range(earlier.start, earlier.start + earlier.length))
            occupied_b = set(range(later.start, later.start + later.length))
            conflict = (bool(occupied_a & occupied_b) or earlier.start == later.start
                        or (not earlier.length and earlier.start in occupied_b)
                        or (not later.length and later.start in occupied_a))
            selected = [later] if conflict else [earlier, later]
            expected = source

            for change in sorted(selected, key=lambda item: item.start, reverse=True):
                expected = (expected[:change.start] + change.data
                            + expected[change.start + change.length:])

            with self.subTest(first=first, second=second):
                self.assertEqual(assemble(source, changes), expected)

    def test_seeded_disjoint_changes(self):
        rng = random.Random(241023)

        for _ in range(1000):
            source = rng.randbytes(100)
            cuts = sorted(rng.sample(range(101), 10))
            changes = [Replace(a, b - a, rng.randbytes(rng.randrange(20)))
                       for a, b in zip(cuts[::2], cuts[1::2])]
            expected = source

            for change in reversed(changes):
                expected = expected[:change.start] + change.data + expected[change.start + change.length:]

            rng.shuffle(changes)
            self.assertEqual(assemble(source, changes), expected)

    def test_invalid_replacements(self):
        for change in (Replace(-1, 1, b'x'), Replace(0, -1, b'x'),
                       Replace(3, 1, b'x'), Replace(0, 1, 'x'), None,
                       Replace('0', 1, b'x'), Replace(0, 0.5, b'x'),
                       Replace(True, 1, b'x'), Replace(0, False, b'x')):
            with self.subTest(change=change), self.assertRaises(CommitException):
                assemble(b'abc', [change])

    def test_empty_and_adjacent(self):
        self.assertEqual(assemble(b'', []), b'')
        self.assertEqual(assemble(b'', [Replace(0, 0, b'x')]), b'x')
        self.assertEqual(assemble(b'ab', [Replace(0, 1, b'X'), Replace(1, 1, b'Y')]), b'XY')


class MessageMatrixTests(unittest.TestCase):
    def test_all_fragmentations(self):
        body = b'a\x00\xff\r\nbcd'

        for mask in range(1 << (len(body) - 1)):
            message = Http1Message(request(length=str(len(body)).encode()))
            identities = tuple(map(id, message.parts))
            previous = 0
            cuts = [i for i in range(1, len(body)) if mask & (1 << (i - 1))] + [len(body)]

            for end in cuts:
                message.feed(body[previous:end])
                previous = end
                self.assertEqual(message.parts[1].get_bytes(), body[:end])
                self.assertEqual(message.content_complete, end == len(body))
                self.assertEqual(tuple(map(id, message.parts)), identities)

            self.assertEqual(message.commit(), request(body))

    def test_length_transitions_and_repeat_commits(self):
        for before, after in itertools.product((0, 1, 9, 10, 99, 100, 999, 1000), repeat=2):
            message = Http1Message(request(b'a' * before))
            header, body = message.parts
            body.set_bytes(b'z' * after)
            result = message.commit()
            self.assertEqual(result, request(b'z' * after))
            self.assertEqual(header.length, body.start)
            self.assertEqual(body.start + body.length, len(result))
            self.assertEqual(message.commit(), result)
            body.set_bytes(b'next')
            self.assertEqual(message.commit(), request(b'next'))

    def test_noop_preserves_leading_zero_length(self):
        original = request(b'abc', length=b'0003')
        self.assertEqual(Http1Message(original).commit(), original)

    def test_part_contract(self):
        message = Http1Message(request(b'ab', length=b'3'))
        header, body = message.parts
        self.assertTrue(header.complete)
        self.assertFalse(body.complete)
        self.assertFalse(header.content_complete)
        self.assertTrue(body.is_a(PartType.Http1.Part))
        self.assertTrue(body.is_a(PartType.Http1.Body))
        self.assertFalse(body.is_a(PartType.Opaque))
        self.assertFalse(body.is_a('http'))
        self.assertEqual(body.stream_id, 1)
        self.assertEqual(body.commit(), ())
        body.set_bytes(b'ab')
        self.assertEqual(body.commit(), ())

        for value in ('abc', bytearray(b'abc'), None, 5):
            with self.assertRaises(TypeError):
                body.set_bytes(value)

        with self.assertRaises(CommitException):
            message.feed(b'c')

        self.assertEqual(message.source, request(b'ab', length=b'3'))

    def test_invalid_heads(self):
        cases = [b'', b'GET / HTTP/1.1\r\n', b'GET / HTTP/1.1\r\n\r\n',
                 request(length=b'-1'), request(length=b'1x'), request(length=b''),
                 request(length=b'9' * 5000), request().replace(b'Content-Length: 0', b'Content-Length'),
                 request(extra=b'Content-Length: 0\r\n'),
                 request(extra=b'Transfer-Encoding: chunked\r\n'),
                 request(extra=b'Bad Header: x\r\n'),
                 request(extra=b'Connection: upgrade\r\n'),
                 request().replace(b'POST / HTTP/1.1', b'not http'),
                 request().replace(b'POST / HTTP/1.1', b'CONNECT host:443 HTTP/1.1')]

        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(CommitException):
                Http1Message(raw)

    def test_failed_feed_preserves_state(self):
        message = Http1Message(request(b'a', length=b'2'))

        with self.assertRaises(CommitException):
            message.feed(b'bc')

        self.assertEqual(message.parts[1].get_bytes(), b'a')
        message.feed(b'b')
        self.assertEqual(message.commit(), request(b'ab'))

    def test_raw_header_edit_rejected(self):
        message = Http1Message(request())
        message.parts[0].set_bytes(b'bad')

        with self.assertRaises(CommitException):
            message.commit()

        self.assertEqual(message.source, request())

    def test_final_validation_failure_is_atomic(self):
        for result in (b'invalid', request(b'x' * 100)):
            message = Http1Message(request(b'a'))
            message.limit = 90
            message.parts[1].set_bytes(b'edited')

            with patch('inspection_parts.assemble', return_value=result):
                with self.assertRaises(CommitException):
                    message.commit()

            self.assertEqual(message.source, request(b'a'))
            self.assertEqual(message.parts[1].get_bytes(), b'edited')

    def test_response_and_integrity(self):
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc'
        message = Http1Message(raw)
        message.parts[1].set_bytes(b'longer')
        self.assertEqual(message.commit(), raw.replace(b'3', b'6').replace(b'abc', b'longer'))

        for name in (b'Digest', b'ETag', b'Content-Range', b'Signature'):
            raw = request(b'a', extra=name + b': something\r\n')
            message = Http1Message(raw)
            self.assertEqual(message.commit(), raw)
            message.parts[1].set_bytes(b'b')

            with self.assertRaises(CommitException):
                message.commit()

            self.assertEqual(message.source, raw)

    def test_exact_quota(self):
        raw = request(b'abc')

        with patch.object(Http1Message, 'limit', len(raw)):
            message = Http1Message(raw)
            self.assertEqual(message.commit(), raw)
            message.parts[1].set_bytes(b'longer')

            with self.assertRaises(CommitException):
                message.commit()

            self.assertEqual(message.source, raw)

        with patch.object(Http1Message, 'limit', len(raw) - 1):
            with self.assertRaises(CommitException):
                Http1Message(raw)

    def test_seeded_binary_body_edits(self):
        rng = random.Random(1234)

        for _ in range(500):
            old = rng.randbytes(rng.randrange(500))
            new = rng.randbytes(rng.randrange(500))
            message = Http1Message(request(old))
            message.parts[1].set_bytes(new)
            self.assertEqual(message.commit(), request(new))

    def test_header_format_matrix(self):
        for name, before, after, digits in itertools.product(
                (b'Content-Length', b'content-length', b'CONTENT-LENGTH'),
                (b'', b' ', b'\t', b' \t '), (b'', b' ', b'\t'), (b'3', b'003')):
            field = name + b':' + before + digits + after
            raw = request(b'abc').replace(b'Content-Length: 3', field)
            message = Http1Message(raw)
            self.assertEqual(message.commit(), raw)
            message.parts[1].set_bytes(b'1234567890')
            expected = raw.replace(field, name + b':' + before + b'10' + after)
            expected = expected[:-3] + b'1234567890'
            self.assertEqual(message.commit(), expected)


class MockWebhook:
    def __init__(self):
        self.held = {}
        self.output = {}

    def callback(self, session, side, data, script):
        key = session, side

        if key not in self.held:
            self.held[key] = Http1Message(data)
        else:
            self.held[key].feed(data)

        message = self.held[key]
        result = script(message)

        if result is None:
            return {'action': 'need-more'}

        self.output[key] = self.output.get(key, b'') + result
        del self.held[key]
        return {'action': 'replace', 'content': result}


class PartsTests(unittest.TestCase):
    head = b'POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length:\t6 \r\n\r\n'

    @staticmethod
    def script(message):
        body = next(p for p in message.parts if p.type == PartType.Http1.Body)

        if not body.content_complete:
            return None

        body.set_bytes(b'Hello world!')
        return message.commit()

    def test_need_more_preserves_parts_and_emits_once(self):
        peer = MockWebhook()
        response = peer.callback('one', 'L', self.head + b'ab', self.script)
        self.assertEqual(response, {'action': 'need-more'})
        self.assertEqual(peer.output, {})
        message = peer.held['one', 'L']
        header, body = message.parts

        for fragment in (b'c', b'd', b'e'):
            peer.callback('one', 'L', fragment, self.script)
            self.assertIs(message.parts[0], header)
            self.assertIs(message.parts[1], body)
            self.assertEqual(peer.output, {})

        response = peer.callback('one', 'L', b'f', self.script)
        expected = self.head.replace(b'\t6 ', b'\t12 ') + b'Hello world!'
        self.assertEqual(response, {'action': 'replace', 'content': expected})
        self.assertEqual(peer.output['one', 'L'], expected)
        self.assertEqual(peer.held, {})
        self.assertIs(message.parts[1], body)
        self.assertEqual(body.get_bytes(), b'Hello world!')
        self.assertEqual(message.commit(), expected)

    def test_sessions_and_directions_are_isolated(self):
        peer = MockWebhook()

        for key in (('a', 'L'), ('a', 'R'), ('b', 'L')):
            peer.callback(*key, self.head + b'a', self.script)

        peer.callback('a', 'R', b'bcdef', self.script)
        self.assertEqual(set(peer.output), {('a', 'R')})
        self.assertEqual(set(peer.held), {('a', 'L'), ('b', 'L')})

    def test_incomplete_commit_and_failed_edit_do_not_publish(self):
        message = Http1Message(self.head + b'ab')

        with self.assertRaises(CommitException):
            message.commit()

        message.feed(b'cdef')
        original = message.source
        message.parts[1].set_bytes(b'x' * message.limit)

        with self.assertRaises(CommitException):
            message.commit()

        self.assertEqual(message.source, original)
        message.parts[1].set_bytes(b'ok')
        self.assertTrue(message.commit().endswith(b'\r\n\r\nok'))

    def test_noop_exact_bytes_and_bounds(self):
        original = self.head + b'abcdef'
        self.assertEqual(Http1Message(original).commit(), original)

        for invalid in (original + b'x', self.head.replace(b'6 ', b'999999999 '),
                        self.head.replace(b'Host:', b'Content-Encoding: gzip\r\nHost:')):
            with self.subTest(invalid=invalid), self.assertRaises(CommitException):
                Http1Message(invalid)

    def test_atomic_replacements_original_coordinates(self):
        self.assertEqual(assemble(b'abcdef', [Replace(0, 1, b'long'),
                                            Replace(4, 2, b'!')]), b'longbcd!')
        self.assertEqual(assemble(b'abcdef', [Replace(0, 4, b'A'),
                                            Replace(2, 3, b'B')]), b'abBf')
        self.assertEqual(assemble(b'abcdef', [Replace(0, 2, b'A'),
                                            Replace(0, 2, b'B')]), b'Bcdef')

    def test_all_mock_fragmentations(self):
        body = b'abcdef'

        for mask in range(1 << (len(body) - 1)):
            peer = MockWebhook()
            peer.callback('session', 'L', self.head, self.script)
            cuts = [i for i in range(1, len(body)) if mask & (1 << (i - 1))] + [len(body)]
            start = 0

            for end in cuts:
                result = peer.callback('session', 'L', body[start:end], self.script)
                start = end

                if end < len(body):
                    self.assertEqual(result, {'action': 'need-more'})
                    self.assertEqual(peer.output, {})
                else:
                    self.assertEqual(result['action'], 'replace')
                    self.assertEqual(peer.output['session', 'L'],
                                     self.head.replace(b'\t6 ', b'\t12 ') + b'Hello world!')

    def test_many_interleaved_sessions(self):
        rng = random.Random(42)
        peer = MockWebhook()
        pending = {(str(i), side): bytearray(b'abcdef')
                   for i in range(50) for side in ('L', 'R')}

        for key in pending:
            peer.callback(*key, self.head, self.script)

        while pending:
            key = rng.choice(list(pending))
            byte = bytes([pending[key].pop(0)])
            response = peer.callback(*key, byte, self.script)

            if pending[key]:
                self.assertEqual(response['action'], 'need-more')
                self.assertNotIn(key, peer.output)
            else:
                self.assertEqual(response['action'], 'replace')
                del pending[key]

        self.assertEqual(peer.held, {})
        self.assertEqual(len(peer.output), 100)
        self.assertEqual(set(peer.output.values()),
                         {self.head.replace(b'\t6 ', b'\t12 ') + b'Hello world!'})

    def test_script_error_after_hold_does_not_leak_bytes(self):
        peer = MockWebhook()
        peer.callback('a', 'L', self.head + b'ab', self.script)

        def failing_script(message):
            message.parts[1].set_bytes(b'pending edit')
            raise RuntimeError('script failed')

        with self.assertRaises(RuntimeError):
            peer.callback('a', 'L', b'cdef', failing_script)

        self.assertEqual(peer.output, {})
        held = peer.held['a', 'L']
        self.assertEqual(held.source, self.head + b'abcdef')
        self.assertEqual(held.parts[1].get_bytes(), b'pending edit')

    def test_consecutive_messages_have_no_stale_hold(self):
        peer = MockWebhook()
        expected = self.head.replace(b'\t6 ', b'\t12 ') + b'Hello world!'

        for i in range(100):
            peer.callback('same', 'R', self.head + b'abc', self.script)
            peer.callback('same', 'R', b'def', self.script)
            self.assertEqual(peer.output['same', 'R'], expected * (i + 1))
            self.assertEqual(peer.held, {})


if __name__ == '__main__':
    unittest.main()
