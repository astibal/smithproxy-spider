"""Logical hold boundary and independent H2 stream-opening prerequisites.

The buffer bridge is internal: these tests do not claim that a live worker can
already suspend/resume streams. They protect the native storage/encoding split
that the publication coordinator will use.
"""

from pathlib import Path
import sys
import unittest
from unittest import mock

import hpack
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived
from h2.exceptions import StreamIDTooLowError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import inspection_api as api
from inspection_h2_test import frame, message


REQUEST = [
    (b':method', b'POST'), (b':scheme', b'https'),
    (b':authority', b'example.test'), (b':path', b'/'),
]


def translated(*frames):
    draft = message(*frames)
    api._prepare_translation(draft, {'translate_allowed': True})
    if not hasattr(draft, '_translation'):
        raise AssertionError(getattr(draft, '_translation_error', 'No translator'))
    return draft


def fields(part):
    return [(field.name, field.value) for field in part.headers.entries]


class LogicalPartBufferTests(unittest.TestCase):
    def test_indexed_headers_become_detached_logical_drafts(self):
        source = hpack.Encoder()
        headers = REQUEST + [(b'x-shared', b'source value')]
        first = source.encode(headers)
        indexed = source.encode(headers)
        draft = translated(frame(first, 1, 5, 1), frame(indexed, 1, 5, 3))
        original = draft.parts[1]
        original.headers.set_header(b'x-shared', b'held edit')
        original.headers.set_header(b'authorization', b'secret', indexing='never')
        original_headers = original.headers
        transaction = draft._translation
        before_input = api._translate_table_dump(transaction.decoder)
        before_output = api._translate_table_dump(transaction.encoder)
        buffers = api._PartHoldBuffers()

        transaction._retain_stream_parts(buffers, 3)
        restored, _ = buffers.release(3)[0]
        saved = restored[0]

        self.assertIs(original.headers, original_headers)
        self.assertFalse(hasattr(original, '_translate_draft'))
        self.assertTrue(saved._translate_draft)
        self.assertIn((b'x-shared', b'held edit'), fields(saved))
        self.assertEqual(bytes(saved._wire), bytes(original._wire))
        self.assertEqual(api._translate_table_dump(transaction.decoder), before_input)
        self.assertEqual(api._translate_table_dump(transaction.encoder), before_output)
        for field in saved.headers.entries:
            self.assertEqual((field.index, field.name_index), (0, 0))
        authorization = next(field for field in saved.headers.entries
                             if field.name == b'authorization')
        self.assertEqual(authorization.indexing, 'never')

    def test_retained_headers_can_use_a_later_output_table(self):
        source = hpack.Encoder()
        headers = REQUEST + [(b'x-shared', b'original')]
        draft = translated(
            frame(source.encode(headers), 1, 5, 1),
            frame(source.encode(headers), 1, 5, 3),
        )
        buffers = api._PartHoldBuffers()
        draft._translation._retain_stream_parts(buffers, 3)
        parts, _ = buffers.release(3)[0]

        # A separate receiver conversation has evolved while these Parts were
        # parked. Only logical fields, not the saved source indices, can be
        # encoded against its current table. No input decoder is replayed here.
        output = hpack.Encoder()
        receiver = hpack.Decoder()
        receiver.decode(output.encode([(b'x-shared', b'unrelated output')]))
        logical = [(field.name, field.value, field.indexing == 'never')
                   for field in parts[0].headers.entries]
        self.assertEqual(receiver.decode(output.encode(logical), raw=True), headers)

    def test_retention_selects_application_parts_not_control_frames(self):
        source = hpack.Encoder()
        draft = translated(
            frame(source.encode(REQUEST), 1, 4, 1),
            frame(b'first', 0, 0, 1),
            frame(b'12345678', 6, 0, 0),
            frame(source.encode(REQUEST), 1, 5, 3),
            frame(b'last', 0, 1, 1),
        )
        buffers = api._PartHoldBuffers()
        draft._translation._retain_stream_parts(buffers, 1)
        parts, _ = buffers.release(1)[0]
        self.assertEqual([part.frame_type for part in parts], [1, 0, 0])
        self.assertEqual([part.stream_id for part in parts], [1, 1, 1])
        self.assertEqual([part.get_bytes() for part in parts[1:]], [b'first', b'last'])

    def test_incomplete_or_absent_stream_is_not_partially_retained(self):
        source = hpack.Encoder()
        draft = translated(
            frame(source.encode(REQUEST), 1, 4, 1),
            frame(b'unfinished', 0, 1, 1)[:-2],
        )
        buffers = api._PartHoldBuffers()
        for stream in (0, 1, 3, True):
            with self.subTest(stream=stream):
                with self.assertRaises(api.CommitException):
                    draft._translation._retain_stream_parts(buffers, stream)
                self.assertEqual(buffers.stream_ids, ())

    def test_cancelled_drafts_are_not_retained_again(self):
        draft = translated(frame(hpack.Encoder().encode(REQUEST), 1, 5, 1))
        draft.parts[0]._translate_cancelled = True
        buffers = api._PartHoldBuffers()
        with self.assertRaisesRegex(api.CommitException, 'cancelled'):
            draft._translation._retain_stream_parts(buffers, 1)
        self.assertEqual(buffers.stream_ids, ())

    def test_already_published_parts_cannot_be_retained(self):
        draft = translated(frame(hpack.Encoder().encode(REQUEST), 1, 5, 1))
        draft.translate()
        buffers = api._PartHoldBuffers()
        with self.assertRaisesRegex(api.CommitException, 'after Translate publication'):
            draft._translation._retain_stream_parts(buffers, 1)
        self.assertEqual(buffers.stream_ids, ())

    def test_reordered_or_retargeted_parts_cannot_change_buffer_ownership(self):
        for mutation in ('reverse', 'stream', 'frame'):
            with self.subTest(mutation=mutation):
                source = hpack.Encoder()
                draft = translated(
                    frame(source.encode(REQUEST), 1, 5, 1),
                    frame(source.encode(REQUEST), 1, 5, 3),
                )
                if mutation == 'reverse':
                    draft.parts.reverse()
                elif mutation == 'stream':
                    draft.parts[0].stream_id = 3
                else:
                    draft.parts[0].frame_type = 6
                buffers = api._PartHoldBuffers()
                with self.assertRaises(api.CommitException):
                    draft._translation._retain_stream_parts(buffers, 1)
                self.assertEqual(buffers.stream_ids, ())

    def test_failed_admission_does_not_change_live_headers_or_tables(self):
        draft = translated(frame(hpack.Encoder().encode(REQUEST), 1, 5, 1))
        part = draft.parts[0]
        headers = part.headers
        transaction = draft._translation
        before = api._translate_table_dump(transaction.encoder)
        buffers = api._PartHoldBuffers(max_bytes=1)
        with self.assertRaisesRegex(api.CommitException, 'byte limit'):
            transaction._retain_stream_parts(buffers, 1)
        self.assertIs(part.headers, headers)
        self.assertFalse(hasattr(part, '_translate_draft'))
        self.assertEqual(api._translate_table_dump(transaction.encoder), before)
        self.assertIsNone(transaction.result)

    def test_raw_hpack_edits_cannot_enter_logical_buffer(self):
        draft = translated(frame(hpack.Encoder().encode(REQUEST), 1, 5, 1))
        draft.parts[0].set_bytes(b'raw HPACK')
        buffers = api._PartHoldBuffers()
        with self.assertRaisesRegex(api.CommitException, 'logical headers'):
            draft._translation._retain_stream_parts(buffers, 1)
        self.assertEqual(buffers.stream_ids, ())

    def test_existing_suffix_hold_never_temporarily_mutates_live_headers(self):
        source = hpack.Encoder()
        draft = translated(
            frame(source.encode(REQUEST), 1, 5, 1),
            frame(source.encode(REQUEST), 1, 5, 3),
        )
        part = draft.parts[1]
        original_headers = part.headers
        draft.parts.hold_from(part)
        checkpoint = api._checkpoint

        def inspect_checkpoint(parts, body_sizes):
            self.assertIs(part.headers, original_headers)
            self.assertFalse(hasattr(part, '_translate_draft'))
            return checkpoint(parts, body_sizes)

        with mock.patch('inspection_api._checkpoint', side_effect=inspect_checkpoint):
            result = draft.translate()
        self.assertIsInstance(result, api.HeldCommit)

    def test_failed_suffix_serialization_leaves_publication_retryable(self):
        draft = translated(frame(hpack.Encoder().encode(REQUEST), 1, 5, 1))
        part = draft.parts[0]
        original_headers = part.headers
        draft.parts.hold_from(part)
        transaction = draft._translation
        with mock.patch.object(transaction, '_checkpoint_held_parts',
                               side_effect=api.CommitException('injected failure')):
            with self.assertRaisesRegex(api.CommitException, 'injected failure'):
                draft.translate()
        self.assertIs(part.headers, original_headers)
        self.assertIsNone(transaction.result)
        self.assertIsNone(transaction.checkpoint)
        self.assertIsInstance(draft.translate(), api.HeldCommit)

    def test_flow_control_suffix_preserves_original_body_baseline(self):
        from inspection_translate_windows_test import Peers

        peers = Peers()
        client = peers.peers['L']
        client.send_headers(1, REQUEST)
        client.send_data(1, b'original', end_stream=True)
        draft = peers.bridge.message('L', client.data_to_send())
        header = draft.parts[0]
        baseline = draft._body_sizes[id(header)]
        draft.parts[1].set_bytes(b'edited body')
        draft.parts.hold_from(header)
        result = draft.translate()
        parts, sizes = api._restore(result.checkpoint)
        self.assertEqual(sizes[id(parts[0])], baseline)
        self.assertEqual(parts[1].get_bytes(), b'edited body')


class StreamOpeningPrerequisites(unittest.TestCase):
    def receiver(self):
        client = H2Connection(H2Configuration(client_side=True))
        server = H2Connection(H2Configuration(client_side=False))
        client.initiate_connection()
        server.initiate_connection()
        server.receive_data(client.data_to_send())
        return server

    def test_later_new_stream_cannot_overtake_suspended_initial_headers(self):
        server = self.receiver()
        encoder = hpack.Encoder()
        server.receive_data(frame(encoder.encode(REQUEST), 1, 5, 3))
        with self.assertRaises(StreamIDTooLowError):
            server.receive_data(frame(encoder.encode(REQUEST), 1, 5, 1))

    def test_open_stream_data_can_continue_while_a_sibling_waits(self):
        server = self.receiver()
        encoder = hpack.Encoder()
        for stream in (1, 3):
            server.receive_data(frame(encoder.encode(REQUEST), 1, 4, stream))
        events = server.receive_data(frame(b'sibling', 0, 1, 3))
        events += server.receive_data(frame(b'resumed', 0, 1, 1))
        self.assertEqual([(event.stream_id, event.data) for event in events
                          if isinstance(event, DataReceived)],
                         [(3, b'sibling'), (1, b'resumed')])


if __name__ == '__main__':
    unittest.main()
