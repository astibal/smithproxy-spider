"""Independent wire-level prerequisites for length-changing Translate.

These are design probes, not a claim that Spider already translates windows.
Real hyper-h2 peers enforce windows. The test bridge deliberately changes DATA
without compensation, then demonstrates the additional transport operations.
No Spider frame parser or flow-control implementation is used as the oracle.
"""
import gzip
import unittest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived
from h2.exceptions import FlowControlError
from h2.settings import SettingCodes


def frame(kind, stream, payload, flags=0):
    return (len(payload).to_bytes(3, 'big') + bytes((kind, flags)) +
            stream.to_bytes(4, 'big') + payload)


def data_frames(stream, payload):
    return b''.join(frame(0, stream, payload[start:start + 16384])
                    for start in range(0, len(payload), 16384))


def window_update(stream, increment):
    return frame(8, stream, increment.to_bytes(4, 'big'))


class Peers:
    def __init__(self, reverse=False):
        self.client = H2Connection(H2Configuration(client_side=True))
        self.server = H2Connection(H2Configuration(client_side=False))
        self.client.initiate_connection()
        self.server.initiate_connection()
        self.server.receive_data(self.client.data_to_send())
        self.client.receive_data(self.server.data_to_send())
        self.server.receive_data(self.client.data_to_send())
        self.reverse = reverse
        self.sender = self.server if reverse else self.client
        self.receiver = self.client if reverse else self.server

    def open(self, stream=1):
        self.client.send_headers(stream, [
            (':method', 'POST'), (':scheme', 'https'),
            (':authority', 'example.test'), (':path', '/upload'),
        ], end_stream=self.reverse)
        self.server.receive_data(self.client.data_to_send())

        if self.reverse:
            self.server.send_headers(stream, [(':status', '200')])
            self.client.receive_data(self.server.data_to_send())

    def replace(self, original, replacement, stream=1):
        for start in range(0, len(original), 16384):
            self.sender.send_data(stream, original[start:start + 16384])

        self.sender.data_to_send()  # The bridge replaces these bytes.
        events = self.receiver.receive_data(data_frames(stream, replacement))
        return b''.join(event.data for event in events if isinstance(event, DataReceived))

    def replenish(self, amount, stream=1):
        self.receiver.increment_flow_control_window(amount)
        self.receiver.increment_flow_control_window(amount, stream)
        return self.receiver.data_to_send()


class FlowControlPrerequisites(unittest.TestCase):
    def test_same_length_needs_no_compensation(self):
        for reverse in (False, True):
            peers = Peers(reverse)
            peers.open()
            self.assertEqual(peers.replace(b'a' * 1000, b'b' * 1000), b'b' * 1000)
            peers.sender.receive_data(peers.replenish(1000))
            self.assertEqual(peers.sender.local_flow_control_window(1), 65535)
            self.assertEqual(peers.receiver.remote_flow_control_window(1), 65535)

    def test_expansion_can_exceed_window_before_any_reply(self):
        for reverse in (False, True):
            peers = Peers(reverse)
            peers.open()

            with self.assertRaises(FlowControlError):
                peers.replace(b'a', b'b' * 65536)

    def test_shrinking_to_zero_can_stall_without_reverse_traffic(self):
        for reverse in (False, True):
            peers = Peers(reverse)
            peers.open()
            self.assertEqual(peers.replace(b'a' * 65535, b''), b'')
            self.assertEqual(peers.sender.local_flow_control_window(1), 0)
            self.assertEqual(peers.receiver.remote_flow_control_window(1), 65535)
            self.assertEqual(peers.receiver.data_to_send(), b'')

            with self.assertRaises(FlowControlError):
                peers.sender.send_data(1, b'next')

    def test_reverse_injection_unblocks_shrinking(self):
        peers = Peers()
        peers.open()
        peers.replace(b'a' * 65535, b'')
        # These bytes must reach the sender, not the current DATA recipient.
        peers.sender.receive_data(window_update(0, 65535) + window_update(1, 65535))
        self.assertEqual(peers.replace(b'next', b'next'), b'next')
        self.assertEqual(peers.sender.local_flow_control_window(1), 65531)
        self.assertEqual(peers.receiver.remote_flow_control_window(1), 65531)

    def test_unmodified_updates_after_expansion_overcredit_sender(self):
        peers = Peers()
        peers.open()
        peers.replace(b'a' * 10, b'b' * 20)
        peers.sender.receive_data(peers.replenish(20))
        self.assertEqual(peers.sender.local_flow_control_window(1), 65545)
        self.assertEqual(peers.receiver.remote_flow_control_window(1), 65535)

    def test_adjusted_updates_restore_both_windows(self):
        peers = Peers()
        peers.open()
        peers.replace(b'a' * 10, b'b' * 20)
        peers.replenish(20)  # Consume the recipient's original updates.
        peers.sender.receive_data(window_update(0, 10) + window_update(1, 10))
        self.assertEqual(peers.sender.local_flow_control_window(1), 65535)
        self.assertEqual(peers.receiver.remote_flow_control_window(1), 65535)

    def test_expansion_resumes_from_reverse_update_without_new_source_data(self):
        peers = Peers()
        peers.open()
        self.assertEqual(peers.replace(b'a', b'b' * 65535), b'b' * 65535)
        # The bridge has one output byte left. Only a reverse callback arrives.
        updates = peers.replenish(1)
        self.assertTrue(updates)
        events = peers.receiver.receive_data(data_frames(1, b'b'))
        self.assertEqual([event.data for event in events if isinstance(event, DataReceived)], [b'b'])
        self.assertEqual(peers.receiver.remote_flow_control_window(1), 0)
        # It would be wrong to return that DATA as a replacement of the reverse
        # WINDOW_UPDATE: the client, rather than the server, would receive it.
        self.assertEqual(peers.sender.local_flow_control_window(1), 65534)

    def test_zero_update_must_be_suppressed_not_serialized(self):
        from h2.exceptions import ProtocolError

        peers = Peers()
        peers.open()

        with self.assertRaises(ProtocolError):
            peers.sender.receive_data(window_update(0, 0))

    def test_connection_credit_does_not_restore_stream_credit(self):
        peers = Peers()
        peers.open(1)
        peers.open(3)
        peers.replace(b'a' * 65535, b'', stream=1)
        peers.sender.receive_data(window_update(0, 65535))
        self.assertEqual(peers.sender.local_flow_control_window(1), 0)
        self.assertEqual(peers.sender.local_flow_control_window(3), 65535)
        self.assertEqual(peers.replace(b'other', b'other', stream=3), b'other')

    def test_padding_consumes_credit_but_frame_header_does_not(self):
        peers = Peers()
        peers.open()
        peers.sender.send_data(1, b'abc', pad_length=7)
        events = peers.receiver.receive_data(peers.sender.data_to_send())
        received = [event for event in events if isinstance(event, DataReceived)]
        self.assertEqual(received[0].flow_controlled_length, 11)
        self.assertEqual(received[0].data, b'abc')
        self.assertEqual(peers.sender.local_flow_control_window(1), 65524)

    def test_initial_window_reduction_can_make_stream_window_negative(self):
        peers = Peers()
        peers.open()
        peers.replace(b'a' * 100, b'a' * 100)
        peers.receiver.update_settings({SettingCodes.INITIAL_WINDOW_SIZE: 0})
        peers.sender.receive_data(peers.receiver.data_to_send())
        self.assertEqual(peers.sender.local_flow_control_window(1), -100)
        self.assertEqual(peers.sender.outbound_flow_control_window, 65435)
        peers.sender.receive_data(window_update(1, 101))
        self.assertEqual(peers.sender.local_flow_control_window(1), 1)

    def test_compressed_wire_size_is_the_flow_control_unit(self):
        peers = Peers()
        peers.open()
        original = gzip.compress(b'a' * 1000, mtime=0)
        replacement = gzip.compress(b'b' * 2000, mtime=0)
        self.assertEqual(peers.replace(original, replacement), replacement)
        self.assertEqual(peers.sender.local_flow_control_window(1), 65535 - len(original))
        self.assertEqual(peers.receiver.remote_flow_control_window(1), 65535 - len(replacement))


if __name__ == '__main__':
    unittest.main()
