"""Stateful translate POC, with libnghttp2 as the independent receiving peer."""
import pathlib
import random
import sys
import unittest

import hpack

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
from h2_translate_poc import TranslateConnection, TranslateError
from inspection_h2_test import frame, unpack, Oracle


def callback(connection, wire, script=lambda api: api.message.translate(), side='L'):
    annotations, offset = [], 0
    for _, _, _, data in unpack(wire):
        annotations.append([offset, offset + 9, 'h2.frame.header'])
        offset += len(data) + 9
    return connection.run(side, wire, annotations, script)


def block(wire):
    return b''.join(data for typ, _, _, data in unpack(wire) if typ in (1, 5, 9))


class TranslateTests(unittest.TestCase):
    def test_changed_insertion_then_original_index_on_another_stream(self):
        sender, receiver = hpack.Encoder(), Oracle()
        connection = TranslateConnection()
        fields = [(b':method', b'GET'), (b'x-lab', b'original')]

        def edit(api):
            api.message.parts[0].headers.set_header(b'x-lab', b'changed')
            return api.message.translate()

        first = callback(connection, frame(sender.encode(fields), 1, 4, 1), edit)
        self.assertEqual(receiver.decode(block(first))[-1], (b'x-lab', b'changed'))
        indexed = sender.encode(fields)
        self.assertEqual(len(indexed), 2)  # Both fields are indexed now.
        # Negative control: rewriting just the first block silently changes the
        # meaning of the untouched next index, even though both blocks decode.
        naive_peer = Oracle()
        naive_peer.decode(hpack.Encoder().encode([(b':method', b'GET'), (b'x-lab', b'changed')]))
        self.assertNotEqual(naive_peer.decode(indexed), fields)
        second = callback(connection, frame(indexed, 1, 4, 3))
        self.assertEqual(receiver.decode(block(second)), fields)
        self.assertNotEqual(block(second), indexed)

    def test_multiple_blocks_in_same_callback(self):
        sender, receiver = hpack.Encoder(), Oracle()
        connection = TranslateConnection()
        fields = [(b'x-test', b'first')]
        wire = frame(sender.encode(fields), 1, 4, 1) + frame(sender.encode(fields), 1, 4, 3)

        def edit(api):
            api.message.parts[0].headers.set_header(b'x-test', b'edited')
            return api.message.translate()

        output = unpack(callback(connection, wire, edit))
        self.assertEqual(receiver.decode(output[0][3]), [(b'x-test', b'edited')])
        self.assertEqual(receiver.decode(output[1][3]), fields)

    def test_directions_and_connections_have_separate_tables(self):
        for connection in (TranslateConnection(), TranslateConnection()):
            peers = {side: (hpack.Encoder(), Oracle()) for side in ('L', 'R')}
            for turn in range(8):
                for side, (sender, receiver) in peers.items():
                    fields = [(b'x-side', side.encode())]
                    wire = frame(sender.encode(fields), 1, 4, 1 + turn * 2)
                    output = callback(connection, wire, side=side)
                    self.assertEqual(receiver.decode(block(output)), fields)

    def test_seeded_eviction_and_repeated_indices(self):
        rng = random.Random(642)
        sender, receiver = hpack.Encoder(), Oracle()
        connection = TranslateConnection()
        for turn in range(200):
            fields = [(b'x-key', str(rng.randrange(20)).encode()),
                      (b'x-value', bytes([65 + turn % 26]) * (30 + turn % 100))]
            desired = [(name, value + b'-edited') for name, value in fields] if turn % 3 == 0 else fields

            def edit(api):
                for name, value in desired:
                    api.message.parts[0].headers.set_header(name, value)
                return api.message.translate()

            output = callback(connection, frame(sender.encode(fields), 1, 4, 1 + turn * 2), edit)
            self.assertEqual(receiver.decode(block(output)), desired)

    def test_continuation_and_large_output(self):
        sender, receiver = hpack.Encoder(), Oracle()
        connection = TranslateConnection()
        encoded = sender.encode([(b'x', b'original')])
        wire = frame(encoded[:2], 1, 0, 3) + frame(encoded[2:], 9, 4, 3)
        value = bytes(range(32, 127)) * 300

        def edit(api):
            api.message.parts[0].headers.set_header(b'x', value)
            return api.message.translate()

        output = callback(connection, wire, edit)
        self.assertGreater(len(unpack(output)), 1)
        self.assertEqual(receiver.decode(block(output)), [(b'x', value)])

    def test_data_and_ping_stay_byte_exact(self):
        sender = hpack.Encoder()
        head = frame(sender.encode([(b':status', b'200'), (b'content-length', b'3')]), 1, 4, 1)
        suffix = frame(b'abc') + frame(b'12345678', 6, 0, 0)
        self.assertTrue(callback(TranslateConnection(), head + suffix).endswith(suffix))

    def test_explicit_call_required_and_failure_is_terminal(self):
        wire = frame(b'\x82', 1, 4)
        scripts = [lambda api: None, lambda api: api.message.commit(),
                   lambda api: (api.message.translate(), None)[1]]
        for script in scripts:
            connection = TranslateConnection()
            with self.subTest(script=script), self.assertRaises(TranslateError):
                callback(connection, wire, script)
            with self.assertRaises(TranslateError):
                callback(connection, wire)

    def test_exception_after_translate_does_not_publish_tables(self):
        connection = TranslateConnection()
        previous = connection._directions['L']

        def fail(api):
            api.message.translate()
            raise RuntimeError('script failed after preparing output')

        with self.assertRaises(RuntimeError):
            callback(connection, frame(b'\x82', 1, 4), fail)
        self.assertIs(connection._directions['L'], previous)
        self.assertTrue(connection.failed)

    def test_unsupported_instancing_settings_and_incomplete_input(self):
        for mode in ('message', 'endpoint'):
            with self.assertRaises(TranslateError):
                TranslateConnection(mode)
        for wire in (frame(b'', 4, 0, 0), frame(b'\x82', 1, 0), frame(b'x', 9, 4)):
            with self.assertRaises(TranslateError):
                callback(TranslateConnection(), wire)

    def test_invalid_index_fails_before_script_runs(self):
        called = []
        with self.assertRaises(hpack.HPACKDecodingError):
            callback(TranslateConnection(), frame(b'\xbe', 1, 4), lambda api: called.append(True))
        self.assertEqual(called, [])

    def test_unsupported_edits_and_duplicate_translation_are_rejected(self):
        from inspection_api import HpackField

        def raw(api):
            api.message.parts[0].set_bytes(b'\x82')

        def index(api):
            api.message.parts[0].headers.entries.append(HpackField(None, None, 'indexed', 62, 0))

        edits = [raw, index,
                 lambda api: api.message.parts.append(api.message.parts[0]),
                 lambda api: api.message.parts.hold_from(api.message.parts[0]),
                 lambda api: api.message.translate()]
        for edit in edits:
            def script(api):
                edit(api)
                return api.message.translate()
            with self.subTest(edit=edit), self.assertRaises(TranslateError):
                callback(TranslateConnection(), frame(b'\x82', 1, 4), script)

        def edit_body(api):
            api.message.parts[0].set_bytes(b'new')
            return api.message.translate()

        with self.assertRaises(TranslateError):
            callback(TranslateConnection(), frame(b'old'), edit_body)

    def test_never_indexed_stays_never_indexed(self):
        sender = hpack.Encoder()
        source = sender.encode([(b'authorization', b'lab-secret', True)])
        output = callback(TranslateConnection(), frame(source, 1, 4))
        decoded = hpack.Decoder().decode(block(output), raw=True)
        self.assertFalse(decoded[0].indexable)
        self.assertEqual(Oracle().decode(block(output)), [(b'authorization', b'lab-secret')])

    def test_truncated_frame_and_unannotated_bytes_are_rejected(self):
        for data, annotations in ((frame(b'abc')[:-1], [[0, 9, 'h2.frame.header']]),
                                  (b'opaque', [])):
            with self.subTest(data=data), self.assertRaises(TranslateError):
                TranslateConnection().run('L', data, annotations, lambda api: api.message.translate())


if __name__ == '__main__':
    unittest.main()
