"""Native Parts storage: isolation, FIFO ordering, admission and rollback.

These tests cover the buffer primitive, not live suspend/resume publication.
Translate integration must additionally prove HPACK and window accounting.
"""

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import CommitException, Message, RewritePart, _PartHoldBuffers
from inspection_h2_test import frame, literal, message


def opaque(data):
    return Message(data, len(data), {})


def retain(buffers, stream, draft):
    buffers.hold(stream, draft.parts, draft._body_sizes)


def payloads(batches):
    return [part.get_bytes() for parts, _ in batches for part in parts]


class PartBufferTests(unittest.TestCase):
    def test_checkpoint_round_trip_preserves_edits_and_queue_order(self):
        import json
        buffers = _PartHoldBuffers()
        first = opaque(b'original')
        first.parts[0].set_bytes(b'edited')
        retain(buffers, 1, first)
        retain(buffers, 1, opaque(b'next'))
        restored = _PartHoldBuffers.from_checkpoint(json.loads(json.dumps(buffers.checkpoint())))
        self.assertEqual(payloads(restored.release(1)), [b'edited', b'next'])
        self.assertEqual(payloads(buffers.release(1)), [b'edited', b'next'])

    def test_checkpoint_restore_reapplies_limits(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 1, opaque(b'first'))
        retain(buffers, 1, opaque(b'second'))
        with self.assertRaisesRegex(CommitException, 'batch limit'):
            _PartHoldBuffers.from_checkpoint(buffers.checkpoint(), max_batches=1)
        self.assertEqual(payloads(buffers.release(1)), [b'first', b'second'])

    def test_invalid_checkpoint_stream_records_are_rejected(self):
        records = [None, {}, {'id': 1, 'batches': 'bad'}, {'id': True, 'batches': [{}]}]
        for record in records:
            with self.subTest(record=record):
                with self.assertRaises(CommitException):
                    _PartHoldBuffers.from_checkpoint({'version': 1, 'streams': [record]})

    def test_interleaved_streams_keep_independent_fifo_queues(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 1, opaque(b'first'))
        retain(buffers, 3, opaque(b'sibling'))
        retain(buffers, 1, opaque(b'second'))

        self.assertEqual(buffers.stream_ids, (1, 3))
        self.assertEqual(payloads(buffers.release(1)), [b'first', b'second'])
        self.assertEqual(buffers.stream_ids, (3,))
        self.assertEqual(buffers.batches_held, 1)
        self.assertEqual(buffers.parts_held, 1)
        self.assertEqual(payloads(buffers.release(3)), [b'sibling'])
        self.assertEqual(buffers.bytes_held, 0)
        self.assertEqual(buffers.batches_held, 0)
        self.assertEqual(buffers.parts_held, 0)

    def test_callback_mutations_cannot_change_retained_snapshot(self):
        buffers = _PartHoldBuffers()
        draft = opaque(b'original')
        draft.parts[0].set_bytes(b'held edit')
        retain(buffers, 0, draft)
        draft.parts[0].set_bytes(b'later edit')
        draft.parts.clear()

        self.assertEqual(payloads(buffers.release(0)), [b'held edit'])

    def test_candidate_release_and_mutation_leave_original_untouched(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 1, opaque(b'held'))
        retained_bytes = buffers.bytes_held
        candidate = buffers.fork()
        released = candidate.release(1)
        released[0][0][0].set_bytes(b'resumed edit')
        retain(candidate, 5, opaque(b'new stream'))

        # A failed publication discards the candidate, not the original store.
        self.assertEqual(buffers.stream_ids, (1,))
        self.assertEqual(buffers.bytes_held, retained_bytes)
        self.assertEqual(payloads(buffers.release(1)), [b'held'])
        self.assertEqual(candidate.stream_ids, (5,))

    def test_candidate_append_and_discard_do_not_mutate_original_queues(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 1, opaque(b'one'))
        retain(buffers, 3, opaque(b'three'))
        candidate = buffers.fork()
        retain(candidate, 1, opaque(b'two'))
        candidate.discard(3)

        self.assertEqual(payloads(candidate.release(1)), [b'one', b'two'])
        self.assertEqual(payloads(buffers.release(1)), [b'one'])
        self.assertEqual(payloads(buffers.release(3)), [b'three'])

    def test_fork_keeps_all_admission_limits(self):
        buffers = _PartHoldBuffers(max_batches=1)
        retain(buffers, 1, opaque(b'held'))
        candidate = buffers.fork()
        with self.assertRaisesRegex(CommitException, 'batch limit'):
            retain(candidate, 1, opaque(b'too many'))
        self.assertEqual(payloads(candidate.release(1)), [b'held'])
        self.assertEqual(payloads(buffers.release(1)), [b'held'])

    def test_same_stream_number_in_different_connections_is_independent(self):
        first = _PartHoldBuffers()
        second = _PartHoldBuffers()
        retain(first, 1, opaque(b'first connection'))
        retain(second, 1, opaque(b'second connection'))
        first.discard(1)
        self.assertEqual(payloads(second.release(1)), [b'second connection'])

    def test_release_and_discard_are_single_use(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 7, opaque(b'held'))
        self.assertTrue(buffers.discard(7))
        self.assertFalse(buffers.discard(7))
        self.assertEqual(buffers.release(7), [])
        self.assertEqual(buffers.bytes_held, 0)

    def test_discard_does_not_restore_or_publish_parts(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 7, opaque(b'held'))
        with mock.patch('inspection_api._restore') as restore:
            self.assertTrue(buffers.discard(7))
        restore.assert_not_called()

    def test_retention_and_release_never_run_the_wire_assembler(self):
        buffers = _PartHoldBuffers()
        draft = message(frame(literal(b'x-test', b'value'), 1, 5, 1))
        with mock.patch.object(RewritePart, 'commit') as commit:
            retain(buffers, 1, draft)
            buffers.release(1)
        commit.assert_not_called()

    def test_failed_restore_keeps_every_batch_and_counter(self):
        buffers = _PartHoldBuffers()
        retain(buffers, 1, opaque(b'one'))
        retain(buffers, 1, opaque(b'two'))
        retained_bytes = buffers.bytes_held
        with mock.patch('inspection_api._restore', side_effect=[([], {}), MemoryError()]):
            with self.assertRaises(MemoryError):
                buffers.release(1)

        self.assertEqual(buffers.bytes_held, retained_bytes)
        self.assertEqual(buffers.batches_held, 2)
        self.assertEqual(buffers.parts_held, 2)
        self.assertEqual(payloads(buffers.release(1)), [b'one', b'two'])

    def test_byte_limit_charges_serialized_drafts_and_is_exact(self):
        draft = opaque(b'one')
        draft.parts[0].set_bytes(b'changed')
        probe = _PartHoldBuffers()
        retain(probe, 1, draft)
        size = probe.bytes_held
        self.assertGreater(size, len(b'onechanged'))

        for limit, fits in ((size - 1, False), (size, True)):
            with self.subTest(limit=limit):
                buffers = _PartHoldBuffers(max_bytes=limit)
                if fits:
                    retain(buffers, 1, draft)
                    self.assertEqual(buffers.bytes_held, size)
                    with self.assertRaisesRegex(CommitException, 'byte limit'):
                        retain(buffers, 3, draft)
                    self.assertEqual(payloads(buffers.release(1)), [b'changed'])
                else:
                    with self.assertRaisesRegex(CommitException, 'byte limit'):
                        retain(buffers, 1, draft)
                self.assertEqual(buffers.stream_ids, ())
                self.assertEqual(buffers.bytes_held, 0)

    def test_each_metadata_limit_rejects_without_partial_admission(self):
        cases = (
            ({'max_streams': 1}, 3, 'stream'),
            ({'max_batches': 1}, 1, 'batch'),
            ({'max_parts': 1}, 1, 'part'),
        )
        for limits, stream, kind in cases:
            with self.subTest(kind=kind):
                buffers = _PartHoldBuffers(**limits)
                retain(buffers, 1, opaque(b'original'))
                retained_bytes = buffers.bytes_held
                with self.assertRaisesRegex(CommitException, kind + ' limit'):
                    retain(buffers, stream, opaque(b'rejected'))
                self.assertEqual(buffers.stream_ids, (1,))
                self.assertEqual(buffers.bytes_held, retained_bytes)
                self.assertEqual(buffers.parts_held, 1)
                self.assertEqual(buffers.batches_held, 1)
                self.assertEqual(payloads(buffers.release(1)), [b'original'])

    def test_released_capacity_can_be_reused_without_counter_drift(self):
        buffers = _PartHoldBuffers(max_streams=1, max_batches=1, max_parts=1)
        for stream in range(100):
            retain(buffers, stream, opaque(b'held'))
            if stream % 2:
                buffers.release(stream)
            else:
                buffers.discard(stream)
            self.assertEqual(buffers.bytes_held, 0)
            self.assertEqual(buffers.batches_held, 0)
            self.assertEqual(buffers.parts_held, 0)

    def test_invalid_stream_ids_fail_consistently(self):
        buffers = _PartHoldBuffers()
        for stream in (-1, True, 1.0, '1', None):
            with self.subTest(stream=stream):
                with self.assertRaises(CommitException):
                    retain(buffers, stream, opaque(b'held'))
                with self.assertRaises(CommitException):
                    buffers.release(stream)
                with self.assertRaises(CommitException):
                    buffers.discard(stream)
        self.assertEqual(buffers.stream_ids, ())

    def test_invalid_limits_are_rejected(self):
        for name in ('max_bytes', 'max_streams', 'max_batches', 'max_parts'):
            for value in (0, -1, True, 1.5, None):
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError):
                        _PartHoldBuffers(**{name: value})

    def test_failed_checkpoint_does_not_create_an_empty_queue(self):
        buffers = _PartHoldBuffers()
        draft = opaque(b'held')
        draft.parts[0].unsupported = object()
        with self.assertRaisesRegex(CommitException, 'Unsupported value'):
            retain(buffers, 1, draft)
        self.assertEqual(buffers.stream_ids, ())
        self.assertEqual(buffers.bytes_held, 0)

    def test_non_parts_empty_batches_and_duplicates_are_rejected(self):
        buffers = _PartHoldBuffers()
        part = opaque(b'held').parts[0]
        for parts in ([], [object()], [part, part], iter([part])):
            with self.subTest(parts=type(parts)):
                with self.assertRaises(CommitException):
                    buffers.hold(1, parts, {})
        self.assertEqual(buffers.stream_ids, ())

    def test_h1_shared_group_and_body_edits_survive_snapshot(self):
        head = b'POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\n'
        data = head + b'old'
        info = {'content_annotations': [
            [0, 17, 'http1.start_line'], [17, len(head), 'http1.headers'],
        ]}
        draft = Message(data, len(data), info)
        draft.parts[1].set_bytes(b'new body')
        buffers = _PartHoldBuffers()
        retain(buffers, 0, draft)
        parts, _ = buffers.release(0)[0]

        self.assertIs(parts[0].group, parts[1].group)
        self.assertIsNot(parts[0].group, draft.parts[0].group)
        self.assertEqual(parts[1].get_bytes(), b'new body')

    def test_h2_header_edits_and_body_baselines_survive_snapshot(self):
        header = frame(literal(b':method', b'POST'), 1, 4, 7)
        draft = message(header, frame(b'old', 0, 1, 7))
        draft.parts[0].headers.set_header(b'x-test', b'held')
        draft.parts[1].set_bytes(b'longer body')
        buffers = _PartHoldBuffers()
        retain(buffers, 7, draft)
        parts, sizes = buffers.release(7)[0]

        self.assertIn((b'x-test', b'held'), [
            (field.name, field.value) for field in parts[0].headers.entries
        ])
        self.assertEqual(parts[1].get_bytes(), b'longer body')
        self.assertEqual(sizes[id(parts[0])], draft._body_sizes[id(draft.parts[0])])
        self.assertNotIn(id(draft.parts[0]), sizes)


if __name__ == '__main__':
    unittest.main()
