"""Local state consumes native Parts, without a proxy or compatibility runtime."""

from dataclasses import FrozenInstanceError
import copy
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import HpackField, Message, make_views
from inspection_protocol_state import H1StateTable, H2StateTable


class H1StateTests(unittest.TestCase):
    @staticmethod
    def parts(wire):
        line = wire.index(b'\r\n') + 2
        end = wire.index(b'\r\n\r\n') + 4
        info = {'content_annotations': [
            [0, line, 'http1.start_line'], [line, end, 'http1.headers'],
        ]}
        return Message(wire, len(wire), info).parts

    def test_message_can_be_complete_and_suspended(self):
        table = H1StateTable()
        table.observe('L', self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'))
        table.suspend('L', 1)
        state, = table.snapshot()
        self.assertTrue(state.content_complete)
        self.assertTrue(state.suspended)
        self.assertFalse(state.published)
        with self.assertRaises(ValueError):
            table.publish('L', 1)
        table.resume('L', 1)
        table.publish('L', 1)
        self.assertTrue(table.snapshot()[0].published)

    def test_incomplete_body_cannot_be_published(self):
        table = H1StateTable()
        table.observe('L', self.parts(
            b'POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\na'))
        self.assertFalse(table.snapshot()[0].content_complete)
        with self.assertRaises(ValueError):
            table.publish('L', 1)

    def test_informational_response_keeps_its_own_identity(self):
        table = H1StateTable()
        table.observe('R', self.parts(b'HTTP/1.1 103 Early Hints\r\n\r\n'))
        table.observe('R', self.parts(b'HTTP/1.1 204 No Content\r\n\r\n'))
        first, final = table.snapshot()
        self.assertTrue(first.informational)
        self.assertFalse(final.informational)
        self.assertEqual((first.sequence, final.sequence), (1, 2))

    def test_failed_batch_preserves_sequence_and_snapshots(self):
        table = H1StateTable(max_messages=1)
        parts = self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
        with self.assertRaises(ValueError):
            table.observe('L', [*parts, *parts])
        self.assertEqual(table.snapshot(), ())
        table.observe('L', parts)
        before = table.snapshot()
        table.retire('L', 1)
        table.observe('L', parts)
        self.assertEqual(table.snapshot()[0].sequence, 2)
        self.assertEqual(before[0].sequence, 1)

    def test_request_and_response_processing_are_independent(self):
        table = H1StateTable()
        table.observe('L', self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'))
        table.observe('R', self.parts(b'HTTP/1.1 204 No Content\r\n\r\n'))
        candidate = table.fork()
        candidate.suspend('L', 1)
        candidate.publish('R', 1)
        request, response = candidate.snapshot()
        self.assertTrue(request.suspended)
        self.assertTrue(response.published)
        self.assertFalse(table.snapshot()[0].suspended)

    def test_checkpoint_restores_in_a_fresh_table_and_keeps_sequence(self):
        table = H1StateTable()
        parts = self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
        table.observe('L', parts)
        table.suspend('L', 1)
        restored = H1StateTable.from_checkpoint(json.loads(json.dumps(table.checkpoint())))
        self.assertEqual(restored.snapshot(), table.snapshot())
        restored.resume('L', 1)
        restored.publish('L', 1)
        restored.retire('L', 1)
        restored.observe('L', parts)
        self.assertEqual(restored.snapshot()[0].sequence, 2)
        self.assertTrue(table.snapshot()[0].suspended)

    def test_checkpoint_rejects_duplicate_out_of_range_and_invalid_flags(self):
        table = H1StateTable()
        table.observe('L', self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'))
        valid = table.checkpoint()
        for field, value in [('sequence', 2), ('sequence', True), ('side', 'X'),
                             ('headers_complete', False), ('suspended', 'yes')]:
            bad = copy.deepcopy(valid)
            bad['messages'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                H1StateTable.from_checkpoint(bad)
        duplicate = copy.deepcopy(valid)
        duplicate['messages'].append(duplicate['messages'][0])
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            H1StateTable.from_checkpoint(duplicate)

    def test_retirement_does_not_reset_sequence_checkpoint(self):
        table = H1StateTable()
        parts = self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
        table.observe('L', parts)
        table.retire('L', 1)
        restored = H1StateTable.from_checkpoint(table.checkpoint())
        restored.observe('L', parts)
        self.assertEqual(restored.snapshot()[0].sequence, 2)

    def test_native_hold_reassembly_keeps_message_identity(self):
        from inspection_hold_test import HEAD, INFO, checkpoint, resume

        table = H1StateTable()
        wire = HEAD + b'ab'
        message = Message(wire, len(wire), INFO)
        table.observe('L', message.parts)
        held = checkpoint(message)

        # Recreate both state and Parts, as a fresh worker does. The retained
        # head must keep sequence 1 while the body gains newly received bytes.
        restored = H1StateTable.from_checkpoint(table.checkpoint())
        continued = resume(held, b'cdef')
        restored.observe('L', continued.parts, restored=True)

        state, = restored.snapshot()
        self.assertEqual(state.sequence, 1)
        self.assertTrue(state.content_complete)
        self.assertFalse(table.snapshot()[0].content_complete)

    def test_native_hold_can_precede_a_new_message_in_the_same_callback(self):
        from inspection_hold_test import checkpoint, resume

        first = b'GET /one HTTP/1.1\r\nHost: test\r\n\r\n'
        second = b'GET /two HTTP/1.1\r\nHost: test\r\n\r\n'
        table = H1StateTable()
        message = Message(first, len(first))
        message.parts[:] = self.parts(first)
        table.observe('L', message.parts)
        held = checkpoint(message)

        line = second.index(b'\r\n') + 2
        info = {'content_annotations': [
            [0, line, 'http1.start_line'], [line, len(second), 'http1.headers'],
        ]}
        continued = resume(held, second, info)
        table.observe('L', continued.parts, restored=True)

        self.assertEqual([state.sequence for state in table.snapshot()], [1, 2])

    def test_restored_parts_cannot_enter_a_different_direction_or_empty_table(self):
        parts = self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
        table = H1StateTable()
        table.observe('L', parts)

        with self.assertRaisesRegex(ValueError, 'direction'):
            table.observe('R', parts, restored=True)

        with self.assertRaisesRegex(ValueError, 'missing'):
            H1StateTable().observe('L', parts, restored=True)

    def test_failed_observation_does_not_mark_parts_as_received(self):
        parts = self.parts(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
        other = self.parts(b'GET /next HTTP/1.1\r\nHost: test\r\n\r\n')
        table = H1StateTable(max_messages=1)

        with self.assertRaises(ValueError):
            table.observe('L', [*parts, *other])

        for part in parts:
            self.assertFalse(hasattr(part, '_inspection_h1_sequence'))


class H2StateTests(unittest.TestCase):
    def setUp(self):
        self.table = H2StateTable()
        self.http2 = make_views({}, b'', ()).http2

    def headers(self, stream=1, *, response=False, end=False, status=b'200'):
        part = self.http2.Frame(1, 4 | int(end), stream, b'')
        name, value = (b':status', status) if response else (b':method', b'POST')
        part.headers.entries.append(HpackField(name, value, 'without', 0, 0))
        return part

    def test_headers_can_be_suspended_before_body_completion(self):
        self.table.observe('L', [self.headers()])
        self.table.suspend(1, 'L')
        state = self.table.stream(1)
        self.assertTrue(state.request.headers_complete)
        self.assertFalse(state.request.content_complete)
        self.assertTrue(state.request.suspended)
        self.assertIsNone(state.response.content_complete)

    def test_receiving_complete_body_does_not_resume_or_publish(self):
        self.table.observe('L', [self.headers()])
        self.table.suspend(1, 'L')
        self.table.observe('L', [self.http2.Frame(0, 1, 1, b'body')])
        state = self.table.stream(1).request
        self.assertTrue(state.content_complete)
        self.assertTrue(state.suspended)
        self.assertFalse(state.published)
        with self.assertRaisesRegex(ValueError, 'suspended'):
            self.table.publish(1, 'L')
        self.table.resume(1, 'L')
        self.table.publish(1, 'L')
        self.assertTrue(self.table.stream(1).request.published)

    def test_directions_and_siblings_are_independent(self):
        self.table.observe('L', [self.headers(), self.headers(3, end=True)])
        self.table.suspend(1, 'L')
        self.table.publish(3, 'L')
        self.table.observe('R', [self.headers(response=True, end=True)])
        self.assertTrue(self.table.stream(1).request.suspended)
        self.assertFalse(self.table.stream(1).response.suspended)
        self.assertTrue(self.table.stream(3).request.published)

    def test_informational_headers_do_not_complete_response(self):
        self.table.observe('L', [self.headers(end=True)])
        self.table.observe('R', [self.headers(response=True, status=b'103')])
        self.assertFalse(self.table.stream(1).response.headers_complete)
        self.assertIsNone(self.table.stream(1).response.content_complete)
        self.table.observe('R', [self.headers(response=True, end=True)])
        self.assertTrue(self.table.stream(1).response.content_complete)

    def test_reset_releases_processing_without_claiming_publication(self):
        self.table.observe('L', [self.headers()])
        self.table.suspend(1, 'L')
        self.table.observe('R', [self.http2.Frame(3, 0, 1, b'\x00\x00\x00\x08')])
        self.assertTrue(self.table.stream(1).reset)
        self.assertFalse(self.table.stream(1).request.suspended)
        self.assertFalse(self.table.stream(1).request.published)
        with self.assertRaises(ValueError):
            self.table.resume(1, 'L')

    def test_snapshots_and_candidate_are_independent(self):
        self.table.observe('L', [self.headers()])
        before = self.table.snapshot()
        candidate = self.table.fork()
        candidate.suspend(1, 'L')
        self.assertFalse(before[0].request.suspended)
        self.assertFalse(self.table.stream(1).request.suspended)
        with self.assertRaises(FrozenInstanceError):
            before[0].request.suspended = True

    def test_failed_batch_does_not_partially_advance_table(self):
        table = H2StateTable(max_streams=1)
        with self.assertRaisesRegex(ValueError, 'limit'):
            table.observe('L', [self.headers(), self.headers(3)])
        self.assertEqual(table.snapshot(), ())

    def test_incomplete_parts_and_opaque_bytes_are_not_parsed(self):
        header = self.headers()
        header.complete = False
        self.table.observe('L', [header, *Message(b'not a frame', 11).parts])
        self.assertEqual(self.table.snapshot(), ())

    def test_data_without_observed_head_preserves_missing_evidence(self):
        self.table.observe('R', [self.http2.Frame(0, 1, 1, b'last')])
        state = self.table.stream(1).response
        self.assertFalse(state.headers_complete)
        self.assertTrue(state.content_complete)
        with self.assertRaisesRegex(ValueError, 'headers'):
            self.table.publish(1, 'R')

    def test_retirement_does_not_change_old_snapshots(self):
        self.table.observe('L', [self.headers(end=True)])
        before = self.table.snapshot()
        self.table.retire(1)
        self.assertEqual(self.table.snapshot(), ())
        self.assertTrue(before[0].request.content_complete)

    def test_control_frames_do_not_create_message_state(self):
        self.table.observe('L', [self.http2.Ping()])
        self.assertEqual(self.table.snapshot(), ())

    def test_split_batches_match_coalesced_parts(self):
        parts = [self.headers(), self.http2.Frame(0, 0, 1, b'a'),
                 self.http2.Frame(0, 1, 1, b'b')]
        self.table.observe('L', parts)
        split = H2StateTable()
        for part in parts:
            split.observe('L', [part])
        self.assertEqual(split.snapshot(), self.table.snapshot())

    def test_checkpoint_roundtrip_preserves_suspended_complete_message(self):
        self.table.observe('L', [self.headers(end=True)])
        self.table.suspend(1, 'L')
        saved = json.loads(json.dumps(self.table.checkpoint()))
        restored = H2StateTable.from_checkpoint(saved)
        restored.resume(1, 'L')
        restored.publish(1, 'L')
        self.assertTrue(restored.stream(1).request.published)
        self.assertTrue(self.table.stream(1).request.suspended)
        self.assertTrue(saved['streams'][0]['request']['suspended'])

    def test_checkpoint_does_not_share_mutable_input_or_output(self):
        self.table.observe('L', [self.headers(end=True)])
        saved = self.table.checkpoint()
        restored = H2StateTable.from_checkpoint(saved)
        saved['streams'][0]['request']['headers_complete'] = False
        self.assertTrue(restored.stream(1).request.headers_complete)
        self.assertTrue(self.table.stream(1).request.headers_complete)

    def test_invalid_checkpoint_is_rejected_before_exposing_state(self):
        self.table.observe('L', [self.headers()])
        valid = self.table.checkpoint()
        for field, value in [('content_complete', 1), ('suspended', 'yes'),
                             ('published', True), ('unexpected', False)]:
            bad = copy.deepcopy(valid)
            bad['streams'][0]['request'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                H2StateTable.from_checkpoint(bad)
        for value in (0, True, -1, 2**31):
            bad = copy.deepcopy(valid)
            bad['streams'][0]['stream_id'] = value
            with self.subTest(stream=value), self.assertRaises(ValueError):
                H2StateTable.from_checkpoint(bad)

    def test_restore_enforces_current_limit_and_unique_streams(self):
        self.table.observe('L', [self.headers(), self.headers(3)])
        saved = self.table.checkpoint()
        with self.assertRaises(ValueError):
            H2StateTable.from_checkpoint(saved, max_streams=1)
        saved['streams'][1] = saved['streams'][0]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            H2StateTable.from_checkpoint(saved)

    def test_reset_checkpoint_cannot_restore_a_suspended_stream(self):
        self.table.observe('L', [self.headers()])
        self.table.suspend(1, 'L')
        saved = self.table.checkpoint()
        saved['streams'][0]['reset'] = True
        with self.assertRaisesRegex(ValueError, 'Reset'):
            H2StateTable.from_checkpoint(saved)

    def test_replayed_head_does_not_reopen_a_reset_stream(self):
        head = self.headers()
        self.table.observe('L', [head])
        self.table.observe('R', [self.http2.Frame(3, 0, 1, b'\x00\x00\x00\x08')])

        self.table.observe('L', [head], restored=True)

        self.assertTrue(self.table.stream(1).reset)
        self.assertFalse(self.table.stream(1).request.content_complete)

    def test_native_fragment_reassembly_observes_header_only_when_complete(self):
        from inspection_hold_test import checkpoint, resume
        from inspection_h2_test import frame, literal

        wire = frame(literal(b':method', b'POST'), 1, 4, 1)
        info = {'content_annotations': [[0, 9, 'h2.frame.header']]}
        first = Message(wire[:10], 10, info)
        self.table.observe('L', first.parts)
        self.assertEqual(self.table.snapshot(), ())
        held = checkpoint(first)

        continued = resume(held, wire[10:])
        self.table.observe('L', continued.parts, restored=True)

        self.assertTrue(self.table.stream(1).request.headers_complete)
        self.assertFalse(self.table.stream(1).request.content_complete)

    def test_native_checkpoint_preserves_observed_unit_marker(self):
        from inspection_api import _checkpoint, _restore

        head = self.headers(end=True)
        self.table.observe('L', [head])
        parts, _ = _restore(json.loads(json.dumps(_checkpoint([head], {}))))
        restored = H2StateTable.from_checkpoint(self.table.checkpoint())
        restored.observe('L', parts, restored=True)

        self.assertEqual(restored.snapshot(), self.table.snapshot())

        with self.assertRaisesRegex(ValueError, 'direction'):
            restored.observe('R', parts, restored=True)

        with self.assertRaisesRegex(ValueError, 'missing'):
            H2StateTable().observe('L', parts, restored=True)


if __name__ == '__main__':
    unittest.main()
