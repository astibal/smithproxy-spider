"""Deterministic H1 payload corpus through serialized hold/resume boundaries."""
import random
import unittest

from inspection_hold_test import checkpoint, resume
from inspection_api import Message, CommitException


def request(body, response=False):
    start = b'HTTP/1.1 200 OK' if response else b'POST /upload?q=1 HTTP/1.1'
    head = start + b'\r\nHost: example.test\r\nContent-Length: '
    head += str(len(body)).encode() + b'\r\nX-Test: original\r\n\r\n'
    info = {'content_annotations': [
        [0, len(start) + 2, 'http1.start_line'],
        [len(start) + 2, len(head), 'http1.headers'],
    ]}
    return head, info


class H1CorpusTests(unittest.TestCase):
    def test_payload_fragmentation_and_replacement_matrix(self):
        rng = random.Random(4301)
        corpus = [
            b'', b'a', bytes(range(256)), b'\x00\xff\r\n' * 37,
            'Unicode sample λ 日本語 🕷'.encode(),
            b'{"ok":true,"items":[1,2,3]}',
            b'\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n',
            rng.randbytes(8193), b'A' * 65537,
        ]
        for response in (False, True):
            for index, body in enumerate(corpus):
                for replacement in (b'', b'x', b'changed\x00\xff' * 31):
                    with self.subTest(response=response, payload=index, size=len(replacement)):
                        head, info = request(body, response)
                        msg = Message(head, len(head), info)
                        msg.parts[0].http1.set_header('X-Test', 'retained')
                        position = 0

                        while position < len(body):
                            held = checkpoint(msg)
                            width = rng.randint(1, 4096)
                            msg = resume(held, body[position:position + width])
                            position += width

                        self.assertTrue(msg.parts[1].content.complete)
                        self.assertEqual(msg.parts[1].get_bytes(), body)
                        msg.parts[1].set_bytes(replacement)
                        output = msg.commit()
                        output_head, output_body = output.split(b'\r\n\r\n', 1)
                        self.assertEqual(output_body, replacement)
                        self.assertIn(b'X-Test: retained', output_head)
                        lengths = [
                            line.partition(b':')[2].strip()
                            for line in output_head.split(b'\r\n')[1:]
                            if line.partition(b':')[0].lower() == b'content-length'
                        ]
                        self.assertEqual(lengths, [str(len(replacement)).encode()])
                        self.assertEqual(msg.commit(), output)

    def test_every_split_preserves_binary_body_and_trailing_bytes(self):
        body = bytes(range(64)) + b'\r\n\r\n'
        head, info = request(body)

        for cut in range(len(body) + 1):
            with self.subTest(cut=cut):
                data = head + body[:cut]
                msg = Message(data, len(data), info)
                msg = resume(checkpoint(msg), body[cut:] + b'opaque suffix\x00')
                self.assertEqual(msg.commit(), head + body + b'opaque suffix\x00')

    def test_interleaved_checkpoints_remain_independent(self):
        sessions = []

        for index in range(24):
            body = bytes([index]) * (index + 1)
            head, info = request(body)
            msg = Message(head, len(head), info)
            msg.parts[0].http1.set_header('X-Test', str(index))
            sessions.append((checkpoint(msg), body, index))

        for held, body, index in reversed(sessions):
            msg = resume(held, body)
            output = msg.commit()
            self.assertTrue(output.endswith(b'\r\n\r\n' + body))
            self.assertIn(b'X-Test: ' + str(index).encode() + b'\r\n', output)

    def test_failed_header_commit_can_be_repaired_without_losing_body(self):
        body = b'original\x00body'
        head, info = request(body)
        msg = resume(checkpoint(Message(head, len(head), info)), body)
        msg.parts[0].http1.set_header('X-Test', 'bad\r\ninjection')

        with self.assertRaises(CommitException):
            msg.commit()

        msg.parts[0].http1.set_header('X-Test', 'fixed')
        self.assertTrue(msg.commit().endswith(b'\r\n\r\n' + body))


if __name__ == '__main__':
    unittest.main()
