"""SETTINGS publication follows emitted bytes, not speculative parsing."""
import json
import sys
import unittest
from pathlib import Path

import hpack

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import Message, HeldCommit, CommitException, _prepare_translation, Connection as ApiConnection, Mode
from inspection_h2_test import frame, unpack


def settings(*pairs):
    return frame(b''.join(key.to_bytes(2, 'big') + value.to_bytes(4, 'big')
                          for key, value in pairs), 4, 0, 0)


ACK = frame(b'', 4, 1, 0)


class Connection:
    def __init__(self):
        self.tables = {}
        self.held = {}
        self.control = None

    def message(self, side, wire):
        message = Message(wire, len(wire), {'content_annotations': [[0, 9, 'h2.frame.header']]})
        _prepare_translation(message, {
            'event': {'details': {'info': {'side': side}}},
            'translate_allowed': self.control is None,
            'translate_active': self.control is not None,
            'translate_state': self.tables.get(side),
            'translate_control': self.control,
            'held_parts': self.held.get(side),
        })
        return message

    def publish(self, side, message):
        result = message.translate()
        transaction = message._translation
        self.tables[side] = json.loads(json.dumps(transaction.checkpoint))
        self.control = json.loads(json.dumps(transaction.control_checkpoint))
        self.held[side] = result.checkpoint if isinstance(result, HeldCommit) else None
        return result.prefix if isinstance(result, HeldCommit) else result

    def feed(self, side, wire):
        return self.publish(side, self.message(side, wire))


class SettingsTests(unittest.TestCase):
    def policy(self, message, limit=0):
        api = ApiConnection(message, instance_mode='flow')
        api.set_mode(Mode.Translate)
        api.http2.enforce_header_table_limit(limit)
        return api

    def test_policy_changes_settings_without_adding_an_ack(self):
        connection = Connection()
        message = connection.message('L', settings((1, 8192)))
        self.policy(message)
        self.assertEqual(connection.publish('L', message), settings((1, 0)))
        self.assertEqual(connection.feed('R', ACK), ACK)
        self.assertEqual(connection.control['R']['table'], 0)
        # A later increase is clamped too; the policy persists without a setter.
        self.assertEqual(connection.feed('L', settings((1, 16384))), settings((1, 0)))

    def test_synthetic_ack_is_consumed_and_policy_is_idempotent(self):
        connection = Connection()
        connection.feed('L', settings())
        connection.feed('R', settings() + ACK)
        connection.feed('L', ACK)
        message = connection.message('L', b'')
        self.policy(message)
        self.assertEqual(connection.publish('L', message), settings((1, 0)))
        # R's ACK belongs to us. This callback also applies the policy toward L.
        self.assertEqual(connection.feed('R', ACK), settings((1, 0)))
        self.assertEqual(connection.feed('L', ACK), b'')
        for side in ('L', 'R'):
            message = connection.message(side, b'')
            self.policy(message)
            self.assertEqual(connection.publish(side, message), b'')
            self.assertEqual(connection.control[side]['pending'], [])

    def test_policy_never_increases_advertised_limit(self):
        connection = Connection()
        message = connection.message('L', settings((1, 128)))
        self.policy(message, 4096)
        self.assertEqual(connection.publish('L', message), settings((1, 128)))

    def test_original_and_synthetic_ack_fifo_with_hold(self):
        connection = Connection()
        connection.feed('L', settings() + settings((1, 1024)))
        message = connection.message('L', b'')
        self.policy(message)
        self.assertEqual(connection.publish('L', message), settings((1, 0)))
        # Two original requests precede the synthetic request in the same queue.
        self.assertEqual(connection.feed('R', ACK + ACK), ACK + ACK)
        message = connection.message('R', ACK)
        message.parts.hold_from(message.parts[0])
        self.assertEqual(connection.publish('R', message), b'')
        self.assertEqual(len(connection.control['R']['pending']), 1)
        self.assertEqual(connection.feed('R', b''), b'')
        self.assertEqual(connection.control['R']['pending'], [])

    def test_policy_change_emits_once_and_preserves_peer_cap(self):
        connection = Connection()
        message = connection.message('L', settings((1, 128)))
        self.policy(message, 0)
        connection.publish('L', message)
        connection.feed('R', ACK)
        message = connection.message('L', b'')
        self.policy(message, 8192)
        self.assertEqual(connection.publish('L', message), settings((1, 128)))
        self.assertEqual(connection.feed('L', b''), b'')

    def test_policy_waits_for_initial_settings_and_hold(self):
        connection = Connection()
        message = connection.message('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        self.policy(message)
        self.assertEqual(connection.publish('L', message), message.bytes)
        message = connection.message('L', settings())
        message.parts.hold_from(message.parts[0])
        self.assertEqual(connection.publish('L', message), b'')
        self.assertEqual(connection.control['R']['pending'], [])
        self.assertEqual(connection.feed('L', b''), settings((1, 0)))

    def test_policy_setters_validate_mode_value_and_commit_order(self):
        connection = Connection()
        message = connection.message('L', settings())
        api = ApiConnection(message, instance_mode='flow')
        with self.assertRaises(CommitException):
            api.http2.enforce_header_table_limit(0)
        api.set_mode(Mode.Translate)
        for invalid in (-1, 2**32, True, '0'):
            with self.assertRaises(CommitException):
                api.http2.enforce_header_table_limit(invalid)
        with self.assertRaises(CommitException):
            api.set_mode(Mode.Rewrite)
        connection.publish('L', message)
        with self.assertRaises(CommitException):
            api.http2.enforce_header_table_limit(0)

    def test_direction_and_fifo_ack(self):
        connection = Connection()
        connection.feed('R', settings((1, 128), (5, 32768)))
        self.assertEqual(connection.control['L']['table'], 4096)
        connection.feed('R', settings((1, 256)))
        connection.feed('L', ACK)
        self.assertEqual(connection.control['L']['table'], 128)
        self.assertEqual(connection.control['L']['frame'], 32768)
        self.assertEqual(connection.control['R']['table'], 4096)
        connection.feed('L', ACK)
        self.assertEqual(connection.control['L']['table'], 256)
        with self.assertRaises(CommitException):
            connection.feed('L', ACK)

    def test_shrink_grow_updates_survive_callback_checkpoint(self):
        for side, peer in [('L', 'R'), ('R', 'L')]:
            with self.subTest(side=side):
                connection = Connection()
                sender, receiver = hpack.Encoder(), hpack.Decoder()
                fields = [(b'x-test', b'value')]
                connection.feed(peer, settings())
                connection.feed(side, ACK)
                output = connection.feed(side, frame(sender.encode(fields), 1, 4))
                self.assertEqual(receiver.decode(unpack(output)[0][3], raw=True), fields)

                connection.feed(peer, settings((1, 0)))
                # Before ACK, the old indexed block remains valid.
                output = connection.feed(side, frame(sender.encode(fields), 1, 4))
                self.assertEqual(receiver.decode(unpack(output)[0][3], raw=True), fields)
                connection.feed(side, ACK)
                sender.header_table_size = 0
                connection.feed(peer, settings((1, 128)))
                connection.feed(side, ACK)
                sender.header_table_size = 128
                receiver.max_allowed_table_size = 128
                output = connection.feed(side, frame(sender.encode(fields), 1, 4))
                block = unpack(output)[0][3]
                self.assertEqual(block[0], 0x20)  # Minimum zero precedes final 128.
                self.assertEqual(receiver.decode(block, raw=True), fields)

    def test_missing_required_table_update_is_rejected(self):
        connection = Connection()
        connection.feed('R', settings((1, 0)))
        connection.feed('L', ACK)
        with self.assertRaises(CommitException):
            connection.feed('L', frame(b'\x82', 1, 4))

    def test_frame_limit_changes_inside_callback(self):
        connection = Connection()
        connection.feed('R', settings((5, 32768)))
        large = frame(b'x' * 20000, 0, 0)
        with self.assertRaises(CommitException):
            connection.feed('L', large)
        self.assertEqual(connection.feed('L', ACK + large), ACK + large)

    def test_held_settings_and_ack_publish_once(self):
        connection = Connection()
        message = connection.message('R', settings((1, 0)))
        message.parts.hold_from(message.parts[0])
        self.assertEqual(connection.publish('R', message), b'')
        self.assertEqual(connection.control['L']['pending'], [])
        connection.feed('R', b'')
        self.assertEqual(len(connection.control['L']['pending']), 1)

        message = connection.message('L', ACK)
        message.parts.hold_from(message.parts[0])
        self.assertEqual(connection.publish('L', message), b'')
        self.assertEqual(connection.control['L']['table'], 4096)
        self.assertEqual(connection.feed('L', b''), ACK)
        self.assertEqual(connection.control['L']['table'], 0)
        self.assertEqual(connection.control['L']['pending'], [])

    def test_large_headers_are_fragmented_to_acknowledged_limit(self):
        connection = Connection()
        connection.feed('R', settings((5, 32768)))
        sender = hpack.Encoder()
        fields = [(b'x-large', bytes(range(256)) * 100)]
        block = sender.encode(fields, huffman=False)
        output = connection.feed('L', ACK + frame(block, 1, 4))
        frames = unpack(output)[1:]
        self.assertGreater(len(frames), 1)
        self.assertEqual(frames[0][0], 1)
        self.assertTrue(all(len(data) <= 32768 for _, _, _, data in frames))
        self.assertTrue(all(typ == 9 for typ, _, _, _ in frames[1:]))
        decoded = hpack.Decoder().decode(b''.join(data for _, _, _, data in frames), raw=True)
        self.assertEqual(decoded, fields)

    def test_invalid_settings_and_atomic_failure(self):
        for pairs in [((5, 16383),), ((5, 0x1000000),), ((2, 2),), ((4, 0x80000000),)]:
            with self.subTest(pairs=pairs):
                connection = Connection()
                connection.feed('L', settings())
                before = json.dumps(connection.control)
                with self.assertRaises(CommitException):
                    connection.feed('R', settings(*pairs))
                self.assertEqual(json.dumps(connection.control), before)

    def test_duplicate_table_settings_preserve_smallest_size(self):
        connection = Connection()
        connection.feed('R', settings((1, 0), (1, 256)))
        connection.feed('L', ACK)
        sender = hpack.Encoder()
        sender.header_table_size = 0
        sender.header_table_size = 256
        fields = [(b'x', b'value')]
        output = connection.feed('L', frame(sender.encode(fields), 1, 4))
        block = unpack(output)[0][3]
        self.assertEqual(block[0], 0x20)
        self.assertEqual(hpack.Decoder().decode(block, raw=True), fields)

    def test_unknown_settings_and_pending_quota(self):
        connection = Connection()
        for _ in range(64):
            connection.feed('L', settings((99, 123)))
        with self.assertRaises(CommitException):
            connection.feed('L', settings())
        connection.feed('R', ACK)
        connection.feed('L', settings())


if __name__ == '__main__':
    unittest.main()
