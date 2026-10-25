"""REWRITE contract tests with an independent libnghttp2 HPACK oracle."""
import base64
import ctypes as c
import ctypes.util
import json
import pathlib
import random
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from inspection_api import Message, CommitException, PartType, Http2, _hpack_fields

H2 = Http2(False, (), ())


def frame(data, typ=0, flags=1, stream=1):
    return len(data).to_bytes(3, 'big') + bytes([typ, flags]) + stream.to_bytes(4, 'big') + data


def unpack(data):
    result = []
    while data:
        assert len(data) >= 9
        size = int.from_bytes(data[:3], 'big')
        assert len(data) >= 9 + size
        result.append((data[3], data[4], int.from_bytes(data[5:9], 'big'), data[9:9 + size]))
        data = data[9 + size:]
    return result


def message(*frames, decoded=None):
    annotations, offset = [], 0
    for item in frames:
        annotations.append([offset, offset + 9, 'h2.frame.header'])
        offset += len(item)
    enrichments = []
    if decoded is not None:
        enrichments = [{'metadata': {'operation': 'hpack.decode', 'context': 'complete',
            'source': {'payload_offset': 0, 'stream_id': 1}, 'headers': decoded}}]
    data = b''.join(frames)
    return Message(data, len(data), {'content_annotations': annotations}, enrichments)


def literal(name, value, indexing='without'):
    return H2.Header(name, value, indexing)._encode()


class Oracle:
    class NV(c.Structure):
        _fields_ = [('name', c.POINTER(c.c_ubyte)), ('value', c.POINTER(c.c_ubyte)),
                    ('namelen', c.c_size_t), ('valuelen', c.c_size_t), ('flags', c.c_ubyte)]

    def __init__(self):
        self.lib = c.CDLL(ctypes.util.find_library('nghttp2'))
        self.ptr = c.c_void_p()
        self.lib.nghttp2_hd_inflate_new.argtypes = [c.POINTER(c.c_void_p)]
        self.lib.nghttp2_hd_inflate_del.argtypes = [c.c_void_p]
        self.lib.nghttp2_hd_inflate_end_headers.argtypes = [c.c_void_p]
        self.lib.nghttp2_hd_inflate_hd2.argtypes = [c.c_void_p, c.POINTER(self.NV),
            c.POINTER(c.c_int), c.c_void_p, c.c_size_t, c.c_int]
        self.lib.nghttp2_hd_inflate_hd2.restype = c.c_ssize_t
        assert self.lib.nghttp2_hd_inflate_new(c.byref(self.ptr)) == 0

    def decode(self, data):
        fields = []
        while True:
            nv, flags = self.NV(), c.c_int()
            used = self.lib.nghttp2_hd_inflate_hd2(self.ptr, c.byref(nv), c.byref(flags), data, len(data), 1)
            if used < 0:
                raise ValueError(f'nghttp2 rejected HPACK: {used}')
            data = data[used:]
            if flags.value & 2:
                fields.append((c.string_at(nv.name, nv.namelen), c.string_at(nv.value, nv.valuelen)))
            if flags.value & 1:
                break
            if not used and not flags.value:
                raise ValueError('Incomplete HPACK output')
        self.lib.nghttp2_hd_inflate_end_headers(self.ptr)
        return fields

    def __del__(self):
        if getattr(self, 'ptr', None):
            self.lib.nghttp2_hd_inflate_del(self.ptr)


class RewriteTests(unittest.TestCase):
    def test_opaque_not_guessed(self):
        raw = frame(b'abc')
        msg = Message(raw, len(raw))
        self.assertEqual(msg.parts[0].type, PartType.Opaque)
        self.assertEqual(msg.commit(), raw)
        msg.parts[0].set_bytes(b'opaque')
        self.assertEqual(msg.commit(), b'opaque')

    def test_lazy_data_and_opaque(self):
        raw = frame(b'x' * 16000)
        for msg in (message(raw), Message(raw, len(raw))):
            part = msg.parts[0]
            self.assertIsInstance(part._data, memoryview)
            self.assertIs(part._data.obj, msg.bytes)
            self.assertEqual(msg.commit(), raw)
            self.assertIsInstance(part._data, memoryview)
            first = part.get_bytes()
            self.assertIsInstance(first, bytes)
            self.assertIs(first, part.get_bytes())
            self.assertEqual(msg.commit(), raw)

    def test_noop_random_and_partial(self):
        rng = random.Random(71)
        for _ in range(200):
            raw = frame(rng.randbytes(rng.randrange(100)), rng.randrange(256), rng.randrange(256))
            msg = message(raw)
            self.assertEqual(msg.commit(), raw)
            partial = message(raw[:9] + raw[9:-1])
            self.assertEqual(partial.commit(), partial.bytes)
            if raw[9:]:
                partial.parts[0].set_bytes(b'changed')
                with self.assertRaises(CommitException):
                    partial.commit()

    def test_huffman_and_indexed_edit(self):
        # RFC 7541 C.4.1 request, decoded metadata from the input decoder.
        raw = bytes.fromhex('828684418cf1e3c2e5f23a6ba0ab90f4ff')
        decoded = [{'name': n, 'value': v} for n, v in
                   [(':method', 'GET'), (':scheme', 'http'), (':path', '/'), (':authority', 'www.example.com')]]
        msg = message(frame(raw, 1, 5), decoded=decoded)
        self.assertEqual(msg.commit(), msg.bytes)
        msg.parts[0].headers.entries[0].value = b'POST'
        msg.parts[0].headers.set_header(b':authority', b'another.example')
        result = Oracle().decode(unpack(msg.commit())[0][3])
        self.assertEqual(result[0], (b':method', b'POST'))
        self.assertEqual(result[-1], (b':authority', b'another.example'))

    def test_explicit_indices_and_table_updates(self):
        msg = message(frame(b'\x82', 1, 5))
        entries = msg.parts[0].headers.entries
        entries[:] = [H2.TableSize(4096), H2.HeaderIndex(2), H2.Header(b'x', b'v', 'incremental'), H2.HeaderIndex(62)]
        result = Oracle().decode(unpack(msg.commit())[0][3])
        self.assertEqual(result, [(b':method', b'GET'), (b'x', b'v'), (b'x', b'v')])
        entries.append(H2.HeaderIndex(999))  # REWRITE deliberately permits divergent state.
        self.assertTrue(msg.commit())
        entries[-1].index = 0
        with self.assertRaises(CommitException): msg.commit()
        entries[-1] = H2.TableSize(0)
        with self.assertRaises(CommitException): msg.commit()

    def test_padding_priority_continuation(self):
        block = literal(b'x', b'old')
        prefix, padding = b'\x02\x00\x00\x00\x00\x10', b'\0\0'
        first = frame(prefix + block[:3] + padding, 1, 0x29)
        second = frame(block[3:], 9, 4)
        msg = message(first, second)
        self.assertEqual(len(msg.parts), 1)
        self.assertEqual(msg.commit(), first + second)
        msg.parts[0].headers.entries[0].value = b'v' * 40000
        frames = unpack(msg.commit())
        self.assertEqual([f[0] for f in frames], [1, 9, 9])
        self.assertTrue(all(len(f[3]) <= 16384 for f in frames))
        self.assertEqual(frames[0][3][:6], prefix)
        self.assertEqual(frames[0][3][-2:], padding)
        self.assertEqual(frames[-1][1], 4)
        encoded = frames[0][3][6:-2] + b''.join(f[3] for f in frames[1:])
        self.assertEqual(Oracle().decode(encoded), [(b'x', b'v' * 40000)])

    def test_data_split_and_content_length(self):
        head = literal(b':status', b'200') + literal(b'content-length', b'3')
        msg = message(frame(head, 1, 4), frame(b'\x02abc\0\0', 0, 9))
        self.assertTrue(msg.parts[0].content.complete)
        msg.parts[1].set_bytes(b'z' * 33000)
        frames = unpack(msg.commit())
        self.assertEqual(Oracle().decode(frames[0][3])[-1], (b'content-length', b'33000'))
        self.assertEqual([f[1] for f in frames[1:]], [8, 0, 1])
        self.assertEqual(msg.commit(), msg.commit())
        self.assertEqual(msg.parts[0].headers.entries[-1].value, b'3')
        msg.parts.pop()
        msg.parts[0].flags |= 1
        self.assertEqual(Oracle().decode(unpack(msg.commit())[0][3])[-1], (b'content-length', b'0'))

    def test_incomplete_body_requires_explicit_override(self):
        head = literal(b':status', b'200') + literal(b'content-length', b'100')
        msg = message(frame(head, 1, 4), frame(b'abc', 0, 0))
        self.assertTrue(msg.parts[1].complete)
        self.assertFalse(msg.parts[1].content.complete)
        msg.parts[1].set_bytes(b'more')
        with self.assertRaises(CommitException): msg.commit()
        self.assertEqual(unpack(msg.commit(False))[-1][3], b'more')

    def test_interleaved_streams_and_atomic_retry(self):
        a = frame(literal(b':status', b'200'), 1, 4)
        b = frame(literal(b':status', b'404'), 1, 5, 3)
        msg = message(a, b, frame(b'body'))
        msg.parts[0].headers.set_header(b'x', b'v')
        msg.parts[2].stream_id = -1
        with self.assertRaises(CommitException): msg.commit()
        self.assertEqual(msg.bytes, a + b + frame(b'body'))
        msg.parts[2].stream_id = 1
        self.assertEqual(unpack(msg.commit())[1], unpack(b)[0])
        msg.parts.append(H2.Ping())
        self.assertEqual(unpack(msg.commit())[-1], (6, 0, 0, b'12345678'))

    def test_raw_hpack_conflict_and_push(self):
        block = literal(b'x', b'v')
        msg = message(frame(b'\0\0\0\x02' + block, 5, 4))
        part = msg.parts[0]
        part.headers.set_header(b'x', b'new')
        self.assertEqual(unpack(msg.commit())[0][3][:4], b'\0\0\0\x02')
        part.set_bytes(block)
        with self.assertRaises(CommitException): msg.commit()

    def test_binary_enrichment_and_gap(self):
        block = literal(b'x', b'\xff\\')
        msg = message(frame(block, 1, 5), decoded=[{'name': 'x', 'value': '\\xff\\x5c', 'value_encoding': 'escaped-bytes'}])
        self.assertEqual(msg.parts[0].headers.entries[0].value, b'\xff\\')
        self.assertEqual(msg.commit(), msg.bytes)
        head = frame(literal(b':status', b'200'), 1, 4)
        tail = frame(b'end')
        data = head + b'unknown' + tail
        msg = Message(data, len(data), {'content_annotations': [[0, 9, 'h2.frame.header'],
            [len(head) + 7, len(head) + 16, 'h2.frame.header']]})
        self.assertIsNone(msg.parts[0].content.complete)
        self.assertEqual(msg.commit(), data)

    def test_worker_explicit_publish(self):
        source = '\n'.join((ROOT / 'src' / name).read_text() for name in
            ('inspection_api.py', 'inspection_h2.py', 'inspection_hold.py', 'inspection_language.py', 'inspection_sandbox.py', 'inspection_worker.py'))
        data = frame(literal(b'x', b'v'), 1, 5)
        request = {'event': {'details': {'info': {'content': base64.b64encode(data).decode(),
            'content_annotations': [[0, 9, 'h2.frame.header']]}}}}
        for publish in (True, False):
            request['script'] = ('for part in api.message.parts:\n'
                '    if part.is_a(PartType.Http2.Part) and part.headers is not None:\n'
                '        part.headers.set_header(b"x", b"changed")\n'
                + ('return api.message.commit()' if publish else 'api.message.commit()\nreturn None'))
            run = subprocess.run([sys.executable, '-I', '-c', source], input=json.dumps(request),
                                 text=True, capture_output=True, timeout=10, check=True)
            result = json.loads(run.stdout)
            self.assertTrue(result['ok'], result)
            if publish:
                wire = base64.b64decode(result['replacement'])
                self.assertEqual(Oracle().decode(unpack(wire)[0][3]), [(b'x', b'changed')])
            else:
                self.assertIsNone(result['replacement'])

    def test_size_boundaries_and_flags(self):
        for size in (0, 1, 255, 16383, 16384, 16385, 32768, 65535):
            with self.subTest(size=size):
                part = H2.Frame(0, 1, 7, b'original')
                part.set_bytes(b'a' * size)
                result = unpack(part.commit())
                self.assertEqual(b''.join(f[3] for f in result), b'a' * size)
                self.assertTrue(all(len(f[3]) <= 16384 for f in result))
                self.assertTrue(all(f[2] == 7 for f in result))
                self.assertEqual([f[1] for f in result], [0] * (len(result) - 1) + [1])

    def test_validation_and_retry(self):
        msg = message(frame(b'original'))
        part = msg.parts[0]
        part.set_bytes(b'edited')
        for attr, bad, good in [('stream_id', -1, 1), ('flags', 256, 1),
                                ('max_frame_size', 0, 16384), ('frame_type', 3, 0)]:
            setattr(part, attr, bad)
            with self.subTest(attr=attr), self.assertRaises(CommitException):
                msg.commit()
            setattr(part, attr, good)
            self.assertEqual(unpack(msg.commit())[0][3], b'edited')
        with self.assertRaises(CommitException): part.set_bytes('text')
        with self.assertRaises(CommitException): part.set_bytes(b'x' * (1024 * 1024 + 1))
        with self.assertRaises(CommitException): H2.Ping(b'short')
        with self.assertRaises(CommitException): msg.commit('false')
        msg.parts.append(part)
        with self.assertRaises(CommitException): msg.commit()
        msg.parts[-1] = None
        with self.assertRaises(CommitException): msg.commit()

    def test_wrong_enrichment_anchor_is_not_used(self):
        data = frame(b'\x82', 1, 5)
        enrichments = [{'metadata': {'operation': 'hpack.decode', 'context': 'complete',
            'source': {'stream_id': 1, 'payload_offset': 9},
            'headers': [{'name': 'wrong', 'value': 'wrong'}]}}]
        msg = Message(data, len(data), {'content_annotations': [[0, 9, 'h2.frame.header']]}, enrichments)
        self.assertIsNone(msg.parts[0].headers.entries[0].name)
        with self.assertRaises(CommitException): msg.parts[0].headers.set_header(b'x', b'v')
        self.assertEqual(msg.commit(), data)

    def test_appended_body_and_rst(self):
        head = frame(literal(b':status', b'200') + literal(b'content-length', b'0'), 1, 5)
        msg = message(head)
        msg.parts[0].flags &= ~1
        msg.parts.append(H2.Frame(0, 1, 1, b'added'))
        self.assertEqual(Oracle().decode(unpack(msg.commit())[0][3])[-1], (b'content-length', b'5'))
        interrupted = message(frame(literal(b':status', b'200'), 1, 4), frame(b'\0' * 4, 3, 0))
        self.assertIsNone(interrupted.parts[0].content.complete)

    def test_hpack_random_literals(self):
        rng = random.Random(714)
        for _ in range(100):
            # Independent decoder verifies binary values and every literal mode.
            fields = [(b'x-' + str(i).encode(), rng.randbytes(rng.randrange(300))) for i in range(5)]
            part = H2.Frame(1, 5, 1, b'')
            part.headers.entries[:] = [H2.Header(n, v, rng.choice(['without', 'incremental', 'never'])) for n, v in fields]
            self.assertEqual(Oracle().decode(unpack(part.commit())[0][3]), fields)


if __name__ == '__main__':
    unittest.main()
