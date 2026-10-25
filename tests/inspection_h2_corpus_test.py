"""Seeded H2 rewrite matrices, checked with an independent HPACK decoder."""
import random
import unittest

from inspection_h2_test import frame, message, literal, unpack, Oracle
from inspection_hold_test import checkpoint, resume


class H2CorpusTests(unittest.TestCase):
    def test_data_sizes_stream_ids_and_fragmentation(self):
        rng = random.Random(6202)

        for size in (0, 1, 255, 16383, 16384, 16385, 32769, 65536):
            for stream in (1, 3, 127, 65535, 0x7fffffff):
                with self.subTest(size=size, stream=stream):
                    original = frame(b'old', stream=stream)
                    msg = message(original)
                    data = rng.randbytes(size)
                    msg.parts[0].set_bytes(data)
                    output = msg.commit()
                    frames = unpack(output)
                    self.assertEqual(b''.join(f[3] for f in frames), data)
                    self.assertTrue(all(f[0] == 0 and f[2] == stream for f in frames))
                    self.assertTrue(all(len(f[3]) <= 16384 for f in frames))
                    self.assertTrue(frames[-1][1] & 1)
                    self.assertTrue(all(not f[1] & 1 for f in frames[:-1]))
                    self.assertEqual(msg.commit(), output)

    def test_header_literal_lengths_and_indexing_modes(self):
        for mode in ('without', 'never', 'incremental'):
            for size in (0, 1, 126, 127, 128, 255, 16383, 16384, 20000):
                with self.subTest(mode=mode, size=size):
                    msg = message(frame(literal(b'x-test', b'old'), 1, 4))
                    field = msg.parts[0].headers.entries[0]
                    field.value = b'v' * size
                    field.indexing = mode
                    frames = unpack(msg.commit())
                    self.assertEqual(frames[0][0], 1)
                    self.assertTrue(all(f[0] == 9 for f in frames[1:]))
                    self.assertTrue(frames[-1][1] & 4)
                    self.assertTrue(all(not f[1] & 4 for f in frames[:-1]))
                    block = b''.join(f[3] for f in frames)
                    self.assertEqual(Oracle().decode(block), [(b'x-test', b'v' * size)])

    def test_many_interleaved_streams_repair_only_their_own_lengths(self):
        inputs = []
        streams = list(range(1, 32, 2))

        for stream in streams:
            block = literal(b':status', b'200') + literal(b'content-length', b'3')
            inputs.append(frame(block, 1, 4, stream))

        for stream in reversed(streams):
            inputs.append(frame(b'old', stream=stream))

        msg = message(*inputs)

        for part in msg.parts:
            if part.frame_type == 0:
                part.set_bytes(bytes([part.stream_id]) * part.stream_id)

        for typ, flags, stream, data in unpack(msg.commit()):
            if typ == 1:
                self.assertEqual(Oracle().decode(data)[-1], (b'content-length', str(stream).encode()))
            else:
                self.assertEqual(data, bytes([stream]) * stream)

    def test_every_partial_data_boundary_survives_multiple_checkpoints(self):
        data = bytes(range(128))
        wire = frame(data, stream=7)

        for cut in range(9, len(wire)):
            with self.subTest(cut=cut):
                msg = message(wire[:cut])
                msg = resume(checkpoint(msg), b'')
                msg = resume(checkpoint(msg), wire[cut:])
                self.assertEqual(msg.commit(), wire)
                msg.parts[0].set_bytes(b'new')
                self.assertEqual(msg.commit(), frame(b'new', stream=7))

    def test_seeded_unknown_frames_are_byte_exact_without_edits(self):
        rng = random.Random(894)

        for case in range(100):
            with self.subTest(case=case):
                wire = frame(rng.randbytes(rng.randrange(1024)), rng.randrange(10, 256),
                             rng.randrange(256), rng.randrange(1 << 31))
                self.assertEqual(message(wire).commit(), wire)


if __name__ == '__main__':
    unittest.main()
