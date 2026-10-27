"""Production translator exercised against independent hyper-h2 peers."""
import base64
import collections
import json
import sys
import unittest
import gzip
import hpack
from pathlib import Path

import h2.config
import h2.connection
import h2.events

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from inspection_api import Message, HeldCommit, CommitException, Connection, _prepare_translation
from inspection_h2_test import frame, unpack


class Bridge:
    def __init__(self, safety='easy'):
        self.safety = safety
        self.tables, self.held = {}, {}
        self.control = None
        self.reverse = b''
        self.reserved = False

    def message(self, side, wire):
        message = Message(wire, len(wire), {})
        _prepare_translation(message, {
            'event': {'details': {'info': {'side': side, 'webhook_control': {'content-reverse': True}}}},
            'translate_allowed': self.control is None,
            'translate_active': self.control is not None,
            'translate_state': self.tables.get(side), 'translate_control': self.control,
            'held_parts': self.held.get(side),
            'peer_held_parts': self.held.get('R' if side == 'L' else 'L'),
            'hold_credit_available': True, 'hold_credit_reserved': self.reserved,
        })
        return message

    def publish(self, side, message):
        result = message.translate(safety=self.safety)
        transaction = message._translation
        self.tables[side] = json.loads(json.dumps(transaction.checkpoint))
        self.control = json.loads(json.dumps(transaction.control_checkpoint))
        self.reserved = bool(self.control.get('flow', {}).get('hold_reserved'))
        self.held[side] = result.checkpoint if isinstance(result, HeldCommit) else None
        if transaction.peer_hold_changed:
            self.held['R' if side == 'L' else 'L'] = transaction.peer_hold_result
        self.reverse = transaction.reverse_output
        return result.prefix if isinstance(result, HeldCommit) else result

    def feed(self, side, wire, edit=None):
        message = self.message(side, wire)
        for part in message.parts:
            if not part.complete:
                message.parts.hold_from(part)
                break
        if edit:
            edit(message)
        return self.publish(side, message), self.reverse


class Peers:
    def __init__(self, safety='easy'):
        self.bridge = Bridge(safety)
        self.peers = {side: h2.connection.H2Connection(h2.config.H2Configuration(client_side=side == 'L'))
                      for side in ('L', 'R')}
        self.received = {'L': [], 'R': []}
        self.ended = {'L': [], 'R': []}
        for peer in self.peers.values():
            peer.initiate_connection()
        self.pump('L', self.peers['L'].data_to_send())
        self.pump('R', self.peers['R'].data_to_send())

    def deliver(self, side, wire, queue):
        if not wire:
            return
        peer = self.peers[side]
        for event in peer.receive_data(wire):
            if isinstance(event, h2.events.DataReceived):
                self.received[side].append(event.data)
                peer.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if isinstance(event, h2.events.StreamEnded):
                self.ended[side].append(event.stream_id)
        reply = peer.data_to_send()
        if reply:
            queue.append((side, reply, None))

    def pump(self, side, wire, edit=None):
        queue = collections.deque([(side, wire, edit)])
        count = 0
        while queue:
            count += 1
            assert count < 100, 'Flow-control feedback loop'
            source, data, change = queue.popleft()
            forward, reverse = self.bridge.feed(source, data, change)
            self.deliver('R' if source == 'L' else 'L', forward, queue)
            self.deliver(source, reverse, queue)

    def open(self, reverse=False, stream=1, content_length=None):
        headers = [(b':method', b'POST'), (b':scheme', b'https'),
                   (b':authority', b'example.test'), (b':path', b'/')]
        self.peers['L'].send_headers(stream, headers, end_stream=reverse)
        self.pump('L', self.peers['L'].data_to_send())
        if reverse:
            self.peers['R'].send_headers(stream, [(b':status', b'200')])
            self.pump('R', self.peers['R'].data_to_send())

    def data(self, side, value, replacement, end=False, padding=None, stream=1):
        self.peers[side].send_data(stream, value, end_stream=end, pad_length=padding)
        def edit(message):
            for part in message.parts:
                if part.frame_type == 0:
                    part.set_bytes(replacement)
        self.pump(side, self.peers[side].data_to_send(), edit)


class WindowsTests(unittest.TestCase):
    safety = 'easy'

    def make_bridge(self):
        return Bridge(self.safety)

    def make_peers(self):
        return Peers(self.safety)

    def input_bridge(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        return bridge

    def test_partial_input_reserves_once_and_release_refunds_once(self):
        for side in ('L', 'R'):
            bridge = self.input_bridge()
            wire = frame(b'\x03abc\0\0\0', 0, 8, 1)
            for byte in wire[:9]:
                bridge.feed(side, bytes([byte]))
            state = bridge.control['flow'][side]['input']
            self.assertEqual(state['window'], 65535 - 7)
            self.assertEqual(state['remaining'], 7)
            for byte in wire[9:]:
                bridge.feed(side, bytes([byte]), lambda m: m.parts.hold_from(m.parts[0]))
            self.assertEqual(bridge.control['flow'][side]['input']['window'], 65535 - 7)
            self.assertEqual(bridge.reverse, b'')
            output, reverse = bridge.feed(side, b'')
            self.assertEqual(output, wire)
            self.assertEqual([int.from_bytes(item[3], 'big') for item in unpack(reverse)], [7, 7])
            self.assertEqual(bridge.control['flow'][side]['input']['window'], 65535)
            self.assertEqual(bridge.feed(side, b''), (b'', b''))

    def test_input_connection_oversend_is_atomic_at_partial_header(self):
        for side in ('L', 'R'):
            bridge = self.input_bridge()
            wire = b''.join(frame(b'x' * size, 0, 0, 1) for size in (16384, 16384, 16384, 16383))
            bridge.feed(side, wire, lambda m: m.parts.hold_from(m.parts[0]))
            self.assertEqual(bridge.control['flow'][side]['input']['window'], 0)
            before = json.dumps(bridge.control)
            with self.assertRaisesRegex(CommitException, 'input connection window'):
                bridge.feed(side, frame(b'x', 0, 0, 3)[:9])
            self.assertEqual(json.dumps(bridge.control), before)

    def test_input_stream_shrink_allows_inflight_only_before_ack(self):
        for side in ('L', 'R'):
            peer = 'R' if side == 'L' else 'L'
            bridge = self.input_bridge()
            bridge.feed(side, frame(b'a', 0, 0, 1))
            bridge.feed(peer, frame(b'\x00\x04\x00\x00\x00\x00', 4, 0, 0))
            bridge.feed(side, frame(b'b', 0, 0, 1))
            self.assertEqual(bridge.control['flow'][side]['input']['streams']['1']['window'], -1)
            bridge.feed(side, frame(b'', 4, 1, 0))
            before = json.dumps(bridge.control)
            for stream in (1, 3):
                with self.assertRaisesRegex(CommitException, 'input stream window'):
                    bridge.feed(side, frame(b'c', 0, 0, stream))
                self.assertEqual(json.dumps(bridge.control), before)

    def test_held_settings_do_not_change_input_windows(self):
        bridge = self.input_bridge()
        bridge.feed('L', frame(b'a', 0, 0, 1))
        bridge.feed('R', frame(b'\x00\x04\x00\x00\x00\x00', 4, 0, 0),
                    lambda m: m.parts.hold_from(m.parts[0]))
        self.assertEqual(bridge.control['flow']['L']['input']['initial'], 65535)
        self.assertEqual(bridge.control['flow']['L']['input']['pending'], [])
        bridge.feed('R', b'')
        self.assertEqual(bridge.control['flow']['L']['input']['initial'], 0)
        self.assertEqual(bridge.control['flow']['L']['input']['pending'], [0])

    def test_input_end_stream_is_enforced_while_held(self):
        bridge = self.input_bridge()
        bridge.feed('L', frame(b'x', 0, 1, 1), lambda m: m.parts.hold_from(m.parts[0]))
        with self.assertRaisesRegex(CommitException, 'stream termination'):
            bridge.feed('L', frame(b'y', 0, 0, 1))

    def test_missing_input_checkpoint_requires_reconnect(self):
        bridge = self.input_bridge()
        bridge.feed('L', frame(b'a', 0, 0, 1))
        del bridge.control['flow']['L']['input']
        with self.assertRaisesRegex(CommitException, 'checkpoint missing; reconnect'):
            bridge.feed('L', frame(b'b', 0, 0, 1))

    def test_reset_during_hold_keeps_only_connection_input_accounting(self):
        bridge = self.input_bridge()
        bridge.feed('L', frame(b'a', 0, 0, 1))
        reset = frame(b'\0\0\0\x08', 3, 0, 1)
        bridge.feed('R', reset, lambda m: m.parts.hold_from(m.parts[0]))
        self.assertEqual(bridge.control['flow']['L']['input']['streams'], {})
        # The peer may have sent these bytes before receiving the reset.
        bridge.feed('L', frame(b'late', 0, 0, 1))
        self.assertEqual(bridge.control['flow']['L']['input']['streams'], {})
        self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)
        bridge.feed('R', b'')
        forward, reverse = bridge.feed('L', frame(b'later', 0, 0, 1))
        self.assertEqual(forward, b'')
        self.assertEqual(unpack(reverse), [(8, 0, 0, (5).to_bytes(4, 'big'))])

    def test_fragmented_input_checkpoint_survives_fresh_workers(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event
        script = ('for part in api.message.parts:\n'
                  '    if not part.complete:\n'
                  '        api.message.parts.hold_from(part)\n        break\n'
                  f'return api.message.translate(safety=Safety.{self.safety.title()})')
        control, table, held = None, None, None
        wire = frame(b'hello', 0, 0, 1)
        for chunk in (wire[:9], wire[9:11], wire[11:]):
            request = event(chunk, 'L')
            request['details']['info']['webhook_control'] = {'content-reverse': True}
            result = run(script, request, translate_allowed=control is None, translate_active=control is not None,
                         translate_state=table, translate_control=control, held_parts=held,
                         hold_allowed=True, instance={'mode': 'flow'})
            self.assertTrue(result['ok'], result)
            control, table, held = result['translate_control'], result['translate_state'], result.get('held_parts')
        self.assertEqual(base64.b64decode(result['replacement']), wire)
        self.assertEqual(control['flow']['L']['input']['window'], 65535)

    def test_reserved_body_crosses_windows_and_repays_credit(self):
        for side in ('L', 'R'):
            for body_size, output_size in ((100000, 0), (100000, 100000), (100000, 160000), (262144, 0)):
                with self.subTest(side=side, body_size=body_size, output_size=output_size):
                    peers = self.make_peers()
                    if side == 'R':
                        peers.open(reverse=True)
                        # open() emitted response headers, so use a new stream
                        # whose initial response header can still be retained.
                        peers.peers['L'].send_headers(3, [(b':method', b'GET'), (b':scheme', b'https'),
                                                       (b':authority', b'example.test'), (b':path', b'/')], end_stream=True)
                        peers.pump('L', peers.peers['L'].data_to_send())
                    stream = 3 if side == 'R' else 1
                    fields = ([(b':status', b'200')] if side == 'R' else
                              [(b':method', b'POST'), (b':scheme', b'https'),
                               (b':authority', b'example.test'), (b':path', b'/')])
                    fields.append((b'content-length', str(body_size).encode()))
                    sender = peers.peers[side]
                    sender.send_headers(stream, fields)

                    def retain(message):
                        header = next(part for part in message.parts if part.frame_type == 1)
                        if not header.content.complete:
                            message.parts.hold_from(header)
                            Connection(message).http2.reserve_body(header, max(128 * 1024, body_size))
                        else:
                            message.bodies()[0].set_bytes(b'z' * output_size)

                    peers.pump(side, sender.data_to_send(), retain)
                    sent = 0
                    while sent < body_size:
                        count = min(16000, body_size - sent, sender.local_flow_control_window(stream))
                        self.assertGreater(count, 0, 'Reserved hold stalled the peer')
                        sent += count
                        sender.send_data(stream, b'x' * count, end_stream=sent == body_size)
                        peers.pump(side, sender.data_to_send(), retain)
                    target = 'R' if side == 'L' else 'L'
                    self.assertEqual(b''.join(peers.received[target]), b'z' * output_size)
                    self.assertEqual(sender.outbound_flow_control_window, 65535)
                    direction = peers.bridge.control['flow'][side]
                    self.assertEqual(direction['input']['owned'], 0)
                    self.assertEqual(direction['advance_due'], 0)
                    self.assertFalse(direction.get('bodies'))
                    self.assertFalse(peers.bridge.reserved)

    def pending_reserved_bridge(self, side):
        bridge = self.input_bridge()
        def retain(message):
            header = message.parts[0]
            message.parts.hold_from(header)
            Connection(message).http2.reserve_body(header, 128 * 1024)
        fields = [(b':method', b'POST')] if side == 'L' else [(b':status', b'200')]
        bridge.feed(side, frame(hpack.Encoder().encode(fields), 1, 4, 1), retain)
        for _ in range(6):
            bridge.feed(side, frame(b'x' * 16000, 0, 0, 1), retain)
        bridge.feed(side, frame(b'x' * 4000, 0, 1, 1))
        direction = bridge.control['flow'][side]
        self.assertTrue(direction['queue'])
        self.assertTrue(direction['bodies']['1']['released'])
        self.assertEqual(direction['bodies']['1']['stream_due'], 0)
        self.assertEqual(direction['input']['owned'], 100000)
        return bridge

    def test_cancel_reserved_pending_output_preserves_connection_and_credit(self):
        for side in ('L', 'R'):
            peer = 'R' if side == 'L' else 'L'
            for terminal in ('reset', 'goaway'):
                # GOAWAY sent by the server excludes client-initiated streams
                # in either DATA direction.
                source = peer if terminal == 'reset' else 'R'
                bridge = self.pending_reserved_bridge(side)
                cancel = (frame(b'\0\0\0\x08', 3, 0, 1) if terminal == 'reset'
                          else frame(b'\0' * 8, 7, 0, 0))
                forward, reverse = bridge.feed(source, cancel)
                self.assertFalse(any(kind == 0 for kind, _, _, _ in unpack(forward + reverse)))
                direction = bridge.control['flow'][side]
                self.assertEqual(direction['queue'], [])
                self.assertEqual(direction['input']['owned'], 0)
                self.assertEqual(direction['input']['window'], 65535)
                self.assertEqual(direction['advance_due'], 0)
                self.assertFalse(direction.get('bodies'))
                self.assertFalse(bridge.reserved)
                # Repeated cancellation must not refund bytes twice.
                forward, reverse = bridge.feed(source, cancel)
                self.assertFalse(any(kind == 8 for kind, _, _, _ in unpack(forward + reverse)))
                ping = frame(b'abcdefgh', 6, 0, 0)
                self.assertEqual(bridge.feed(side, ping), (ping, b''))
                if terminal == 'reset':
                    header = frame(hpack.Encoder().encode([(b':method', b'POST')]), 1, 4, 3)
                    def retain(message):
                        message.parts.hold_from(message.parts[0])
                        Connection(message).http2.reserve_body(message.parts[0], 128 * 1024)
                    bridge.feed('L', header, retain)
                    bridge.feed('L', frame(b'new body', 0, 1, 3),
                                lambda m: m.bodies()[0].set_bytes(b''))
                    self.assertFalse(bridge.control['flow']['L'].get('bodies'))

    def test_terminal_control_bypasses_body_hold(self):
        bridge = self.pending_reserved_bridge('L')
        cancel = frame(b'\0\0\0\x08', 3, 0, 1)
        forward, reverse = bridge.feed('R', cancel, lambda m: m.parts.hold_from(m.parts[0]))
        self.assertEqual(unpack(forward)[0][0], 3)
        self.assertEqual(reverse, b'')
        self.assertFalse(bridge.control['flow']['L']['queue'])
        bridge.feed('R', b'')
        self.assertFalse(bridge.control['flow']['L'].get('bodies'))
        self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)

    def test_complete_reserved_body_with_retained_data_cancels(self):
        bridge, _ = self.reserved_bridge()
        bridge.feed('L', frame(b'abc', 0, 1, 1), lambda m: m.parts.hold_from(m.parts[1]))
        self.assertFalse(bridge.control['flow']['L']['bodies']['1'].get('released'))
        bridge.feed('R', frame(b'\0\0\0\x08', 3, 0, 1))
        self.assertFalse(bridge.control['flow']['L'].get('bodies'))
        self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)
        self.assertIsNone(bridge.held['L'])

    def test_reservation_admission_retry_limits_and_lost_owner(self):
        bridge = self.input_bridge()
        header = frame(hpack.Encoder().encode([(b':method', b'POST'), (b'content-length', b'100000')]), 1, 4, 1)
        message = bridge.message('L', header)
        part = message.parts[0]
        # A draft edit cannot hide an oversized original Content-Length.
        part.headers.set_header(b'content-length', b'1')
        message.parts.hold_from(part)
        connection = Connection(message)
        before = json.dumps(bridge.control)
        connection.http2.reserve_body(part, 65535)
        with self.assertRaisesRegex(CommitException, 'Content-Length exceeds'):
            bridge.publish('L', message)
        self.assertEqual(json.dumps(bridge.control), before)
        self.assertIsNone(message._translation.result)
        connection.http2.reserve_body(part, 128 * 1024)
        bridge.publish('L', message)
        bridge.reserved = False
        with self.assertRaisesRegex(CommitException, 'owner lost'):
            bridge.feed('L', frame(b'x', 0, 0, 1))

    def test_cancel_partial_reserved_data_and_preserve_hpack_dependency(self):
        for side in ('L', 'R'):
            peer = 'R' if side == 'L' else 'L'
            bridge = self.input_bridge()
            encoder = hpack.Encoder()
            fields = [(b':method', b'POST')] if side == 'L' else [(b':status', b'200')]
            fields.append((b'x-dependency', b'saved in a cancelled header'))
            def retain(message):
                for part in message.parts:
                    if part.frame_type == 1 and part.content.complete is False:
                        message.parts.hold_from(part)
                        Connection(message).http2.reserve_body(part, 128 * 1024)
                        break
            bridge.feed(side, frame(encoder.encode(fields), 1, 4, 1), retain)
            data = frame(b'x' * 12000, 0, 0, 1)
            bridge.feed(side, data[:12], retain)
            bridge.feed(peer, frame(b'\0\0\0\x08', 3, 0, 1))
            direction = bridge.control['flow'][side]
            self.assertEqual(direction['discard_bytes'], 11997)
            self.assertEqual(direction['input']['owned'], 0)
            self.assertEqual(direction['input']['window'], 65535)
            for chunk in (data[12:1000], data[1000:-1]):
                def inspect_then_retain(message):
                    self.assertEqual(message.bodies(), ())
                    retain(message)
                self.assertEqual(bridge.feed(side, chunk, inspect_then_retain), (b'', b''))
            wire = data[-1:] + frame(encoder.encode(fields), 1, 5, 3)
            forward, reverse = bridge.feed(side, wire, retain)
            frames = unpack(forward)
            self.assertEqual([(kind, stream) for kind, _, stream, _ in frames], [(1, 3)])
            self.assertEqual(hpack.Decoder().decode(frames[0][3], raw=True), fields)
            self.assertEqual(reverse, b'')
            self.assertEqual(bridge.control['flow'][side]['input']['remaining'], 0)

    def test_cancel_one_retained_stream_preserves_other_draft_and_credit(self):
        bridge = self.input_bridge()
        encoder = hpack.Encoder()
        fields = [(b':method', b'POST'), (b'x-shared', b'compression history')]
        def retain(message):
            message.parts.hold_from(message.parts[0])
            Connection(message).http2.reserve_body(message.parts[0], 128 * 1024)
        bridge.feed('L', frame(encoder.encode(fields), 1, 4, 1), retain)
        bridge.feed('L', frame(b'a' * 100, 0, 0, 1), retain)
        message = bridge.message('L', frame(encoder.encode(fields), 1, 4, 3) + frame(b'b' * 50, 0, 0, 3))
        retain(message)
        next(part for part in message.parts if part.frame_type == 1 and part.stream_id == 3).headers.set_header(b'x-draft', b'preserved')
        bridge.publish('L', message)
        bridge.feed('R', frame(b'\0\0\0\x08', 3, 0, 1))
        direction = bridge.control['flow']['L']
        self.assertEqual(direction['input']['owned'], 50)
        self.assertEqual(direction['advance_due'], 50)
        forward, _ = bridge.feed('L', frame(b'c', 0, 1, 3))
        frames = unpack(forward)
        self.assertTrue(all(stream == 3 for _, _, stream, _ in frames))
        self.assertIn((b'x-draft', b'preserved'), hpack.Decoder().decode(frames[0][3], raw=True))
        self.assertEqual(b''.join(data for kind, _, _, data in frames if kind == 0), b'b' * 50 + b'c')
        self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)
        self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)

    def test_cancellation_at_data_header_boundaries(self):
        for cut in (1, 8, 9, 10, 24):
            bridge, retain = self.reserved_bridge()
            data = frame(b'x' * 16, 0, 0, 1)
            bridge.feed('L', data[:cut], retain)
            bridge.feed('R', frame(b'\0\0\0\x08', 3, 0, 1))
            ping = frame(b'boundary', 6, 0, 0)
            forward, _ = bridge.feed('L', data[cut:] + ping)
            self.assertEqual(forward, ping)
            self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)
            self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)
            self.assertFalse(bridge.reserved)

    def test_cancel_fragmented_trailer_keeps_source_dynamic_table(self):
        bridge = self.input_bridge()
        encoder = hpack.Encoder()
        def retain(message):
            message.parts.hold_from(message.parts[0])
            Connection(message).http2.reserve_body(message.parts[0], 128 * 1024)
        bridge.feed('L', frame(encoder.encode([(b':method', b'POST')]), 1, 4, 1), retain)
        bridge.feed('L', frame(b'abc', 0, 0, 1), retain)
        fields = [(b'x-history', b'from a cancelled fragmented trailer')]
        block = encoder.encode(fields)
        bridge.feed('L', frame(block[:3], 1, 1, 1), retain)
        bridge.feed('R', frame(b'\0\0\0\x08', 3, 0, 1))
        forward, _ = bridge.feed('L', frame(block[3:], 9, 4, 1) +
                                frame(encoder.encode([(b':method', b'GET')] + fields), 1, 5, 3))
        frames = unpack(forward)
        self.assertEqual([(kind, stream) for kind, _, stream, _ in frames], [(1, 3)])
        self.assertEqual(hpack.Decoder().decode(frames[0][3], raw=True), [(b':method', b'GET')] + fields)
        self.assertFalse(bridge.reserved)

    def test_sender_reset_during_reserved_hold_does_not_reset_idle_recipient(self):
        bridge, retain = self.reserved_bridge()
        bridge.feed('L', frame(b'abc', 0, 0, 1), retain)
        forward, reverse = bridge.feed('L', frame(b'\0\0\0\x08', 3, 0, 1), retain)
        self.assertEqual(forward, b'')
        self.assertEqual(reverse, b'')  # All three input bytes were already credited.
        self.assertFalse(bridge.control['flow']['L'].get('bodies'))
        self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)
        self.assertEqual(bridge.feed('L', b''), (b'', b''))

    def test_reset_and_new_reservation_in_same_callback(self):
        bridge, retain = self.reserved_bridge()
        bridge.feed('L', frame(b'old body', 0, 0, 1), retain)
        header = frame(hpack.Encoder().encode([(b':method', b'POST')]), 1, 4, 3)
        wire = frame(b'\0\0\0\x08', 3, 0, 1) + header + frame(b'new', 0, 0, 3)
        def reserve_next(message):
            part = next(p for p in message.parts if p.frame_type == 1 and p.stream_id == 3)
            message.parts.hold_from(part)
            Connection(message).http2.reserve_body(part, 128 * 1024)
        forward, _ = bridge.feed('L', wire, reserve_next)
        self.assertEqual(forward, b'')
        direction = bridge.control['flow']['L']
        self.assertEqual(direction['bodies']['3']['stream'], 3)
        self.assertEqual(direction['bodies']['3']['stream_due'], 3)
        self.assertEqual(direction['input']['owned'], 3)
        forward, _ = bridge.feed('L', frame(b' body', 0, 1, 3))
        self.assertEqual(b''.join(data for kind, _, _, data in unpack(forward) if kind == 0), b'new body')
        self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)
        self.assertFalse(bridge.reserved)

    def test_reserved_trailers_complete_and_cancel_pending_output(self):
        for side in ('L', 'R'):
            bridge = self.input_bridge()
            encoder, decoder = hpack.Encoder(), hpack.Decoder()
            fields = [(b':method', b'POST')] if side == 'L' else [(b':status', b'200')]
            fields.append((b'content-length', b'100000'))
            def retain(message):
                message.parts.hold_from(message.parts[0])
                Connection(message).http2.reserve_body(message.parts[0], 128 * 1024)
            bridge.feed(side, frame(encoder.encode(fields), 1, 4, 1), retain)
            for amount in [16000] * 6 + [4000]:
                bridge.feed(side, frame(b'x' * amount, 0, 0, 1), retain)
            trailer = frame(encoder.encode([(b'x-trailer', b'complete')]), 1, 5, 1)
            forward, _ = bridge.feed(side, trailer, lambda m: m.bodies()[0].set_bytes(b'z' * 160000))
            self.assertIn((b'content-length', b'160000'), decoder.decode(unpack(forward)[0][3], raw=True))
            self.assertTrue(bridge.control['flow'][side]['bodies']['1']['released'])
            peer = 'R' if side == 'L' else 'L'
            _, reverse = bridge.feed(peer, frame(b'\0\0\0\x08', 3, 0, 1))
            headers = [data for kind, _, _, data in unpack(reverse) if kind == 1]
            self.assertEqual(decoder.decode(headers[0], raw=True), [(b'x-trailer', b'complete')])
            self.assertEqual(bridge.control['flow'][side]['input']['owned'], 0)
            self.assertFalse(bridge.control['flow'][side].get('bodies'))

    def reserved_bridge(self, limit=128 * 1024):
        bridge = self.input_bridge()
        header = frame(hpack.Encoder().encode([(b':method', b'POST')]), 1, 4, 1)
        def retain(message):
            part = message.parts[0]
            message.parts.hold_from(part)
            Connection(message).http2.reserve_body(part, limit)
        bridge.feed('L', header, retain)
        return bridge, retain

    def test_reserved_unknown_length_partial_padding_and_cancellation(self):
        for terminal in ('reset', 'goaway'):
            bridge, retain = self.reserved_bridge()
            wire = frame(b'\x03abc\0\0\0', 0, 8, 1)
            bridge.feed('L', wire[:9], retain)
            self.assertEqual(bridge.control['flow']['L']['input']['owned'], 7)
            self.assertEqual([int.from_bytes(item[3], 'big') for item in unpack(bridge.reverse)], [7, 7])
            for byte in wire[9:]:
                bridge.feed('L', bytes([byte]), retain)
                self.assertEqual(bridge.reverse, b'')
            cancel = frame(b'\0\0\0\x08', 3, 0, 1) if terminal == 'reset' else frame(b'\0' * 8, 7, 0, 0)
            bridge.feed('R', cancel)
            self.assertFalse(bridge.control['flow']['L'].get('bodies'))
            self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)
            self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)
            self.assertEqual(bridge.feed('L', b''), (b'', b''))
        for amount in (8, 9):
            bridge, retain = self.reserved_bridge(limit=8)
            with self.assertRaisesRegex(CommitException, 'body.*limit'):
                bridge.feed('L', frame(b'x' * amount, 0, 0, 1)[:9], retain)

    def test_failed_hold_serialization_does_not_publish_early_credit(self):
        bridge, retain = self.reserved_bridge()
        message = bridge.message('L', frame(b'abc', 0, 0, 1))
        retain(message)
        header = message.parts[0]
        original = list(header.headers.entries)
        header.headers.set_header(b'x-huge', b'x' * 900000)
        before = json.dumps(bridge.control)
        with self.assertRaisesRegex(CommitException, 'exceed'):
            bridge.publish('L', message)
        self.assertEqual(json.dumps(bridge.control), before)
        self.assertIsNone(message._translation.result)
        header.headers.entries = original
        self.assertEqual(bridge.publish('L', message), b'')
        self.assertEqual([int.from_bytes(item[3], 'big') for item in unpack(bridge.reverse)], [3, 3])
        bridge.feed('L', frame(b'z', 0, 1, 1))
        self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)
        self.assertEqual(bridge.control['flow']['L']['advance_due'], 0)

    def test_reservation_accepts_second_body_and_rejects_incomplete_release(self):
        bridge, retain = self.reserved_bridge()
        with self.assertRaisesRegex(CommitException, 'remain held'):
            bridge.feed('L', b'')
        message = bridge.message('L', frame(hpack.Encoder().encode([(b':method', b'POST')]), 1, 4, 3))
        message.parts.hold_from(message.parts[0])
        Connection(message).http2.reserve_body(message.parts[-1], 128 * 1024)
        bridge.publish('L', message)
        self.assertEqual(set(bridge.control['flow']['L']['bodies']), {'1', '3'})

    def test_reserved_holds_in_both_directions_release_without_double_grants(self):
        bridge = self.input_bridge()
        def retain(message):
            message.parts.hold_from(message.parts[0])
            Connection(message).http2.reserve_body(message.parts[0], 128 * 1024)
        for side, fields in (('L', [(b':method', b'POST')]), ('R', [(b':status', b'200')])):
            bridge.feed(side, frame(hpack.Encoder().encode(fields), 1, 4, 1), retain)
        for _ in range(6):
            for side in ('L', 'R'):
                bridge.feed(side, frame(b'x' * 16000, 0, 0, 1), retain)
        for side in ('L', 'R'):
            def release(message):
                message.bodies()[0].set_bytes(b'')
            bridge.feed(side, frame(b'x' * 4000, 0, 1, 1), release)
            state = bridge.control['flow'][side]
            self.assertEqual(state['input']['owned'], 0)
            self.assertEqual(state['input']['window'], 65535)
            self.assertEqual(state['advance_due'], 0)
            self.assertFalse(state.get('bodies'))

    def test_multiplexed_reserved_bodies_finish_and_cancel_independently(self):
        for side in ('L', 'R'):
            bridge = self.input_bridge()
            fields = [(b':method', b'POST')] if side == 'L' else [(b':status', b'200')]
            encoder = hpack.Encoder()
            headers = b''.join(frame(encoder.encode(fields), 1, 4, stream) for stream in (1, 3))
            def retain(message):
                message.parts.hold_from(message.parts[0])
                for part in message.parts:
                    if part.frame_type == 1 and part.content.complete is False:
                        Connection(message).http2.reserve_body(part, 128 * 1024)
            bridge.feed(side, headers, retain)
            for _ in range(6):
                bridge.feed(side, frame(b'a' * 16000, 0, 0, 1) + frame(b'b' * 16000, 0, 0, 3), retain)
            state = bridge.control['flow'][side]
            self.assertEqual(set(state['bodies']), {'1', '3'})
            self.assertEqual(state['input']['owned'], 192000)
            self.assertEqual(state['advance_due'], 192000)
            peer = 'R' if side == 'L' else 'L'
            bridge.feed(peer, frame(b'\0\0\0\x08', 3, 0, 1))
            state = bridge.control['flow'][side]
            self.assertEqual(set(state['bodies']), {'3'})
            self.assertEqual(state['input']['owned'], 96000)
            def shrink(message):
                bodies = message.bodies()
                self.assertEqual(len(bodies), 1)
                bodies[0].set_bytes(b'done')
            output, _ = bridge.feed(side, frame(b'b' * 4000, 0, 1, 3), shrink)
            self.assertEqual(b''.join(data for kind, _, _, data in unpack(output) if kind == 0), b'done')
            self.assertFalse(bridge.reserved)
            self.assertEqual(bridge.control['flow'][side]['input']['window'], 65535)

    def test_multi_reservation_aggregate_and_stream_count_are_atomic(self):
        for count, limit in ((3, 100000), (33, 1)):
            bridge = self.input_bridge()
            encoder = hpack.Encoder()
            wire = b''.join(frame(encoder.encode([(b':method', b'POST')]), 1, 4, stream)
                            for stream in range(1, count * 2, 2))
            message = bridge.message('L', wire)
            message.parts.hold_from(message.parts[0])
            for part in message.parts:
                Connection(message).http2.reserve_body(part, limit)
            before = json.dumps(bridge.control)
            with self.assertRaisesRegex(CommitException, 'aggregate'):
                bridge.publish('L', message)
            self.assertEqual(json.dumps(bridge.control), before)
            self.assertIsNone(message._translation.result)

    def test_smaller_reservation_checkpoint_limit_and_legacy_upgrade(self):
        bridge, retain = self.reserved_bridge(limit=1024)
        self.assertEqual(bridge.control['flow']['L']['hold_capacity'], 320 * 1024)
        message = bridge.message('L', frame(b'abc', 0, 0, 1))
        retain(message)
        message.parts[0].headers.set_header(b'x-large', b'x' * 350000)
        before = json.dumps(bridge.control)
        with self.assertRaisesRegex(CommitException, 'checkpoint exceeds admitted'):
            bridge.publish('L', message)
        self.assertEqual(json.dumps(bridge.control), before)
        direction = bridge.control['flow']['L']
        direction['body'] = direction.pop('bodies')['1']
        direction.pop('hold_capacity')
        bridge.feed('L', frame(b'abc', 0, 0, 1), retain)
        self.assertEqual(bridge.control['flow']['L']['hold_capacity'], 1024 * 1024)
        bridge.feed('L', frame(b'def', 0, 1, 1))
        self.assertFalse(bridge.reserved)

    def test_small_reservation_bounds_credit_for_competing_held_data(self):
        bridge, retain = self.reserved_bridge(limit=1024)
        for _ in range(4):
            bridge.feed('L', frame(b'x' * 16000, 0, 0, 3), retain)
            direction = bridge.control['flow']['L']
            self.assertLessEqual(direction['input']['owned'] + direction['input']['window'], 65535 + 1024)
        self.assertEqual(direction['advance_due'], 1024)
        self.assertEqual(direction['hold_capacity'], 320 * 1024)

    def test_blocked_stream_does_not_block_other_stream_or_trailers_order(self):
        bridge = self.input_bridge()
        # Receiver constrains stream 1 only; connection credit remains available.
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'a' * 65536))
        bridge.feed('R', frame((100000).to_bytes(4, 'big'), 8, 0, 0))
        encoder = hpack.Encoder()
        output, _ = bridge.feed('L', frame(encoder.encode([(b':method', b'POST')]), 1, 4, 3) +
                               frame(b'other', 0, 1, 3))
        self.assertEqual([item[2] for item in unpack(output)], [3, 3])
        # A trailer on the blocked stream must stay behind that stream's DATA.
        output, _ = bridge.feed('L', frame(encoder.encode([(b'x-end', b'yes')]), 1, 5, 1))
        self.assertEqual(output, b'')
        _, reverse = bridge.feed('R', frame((1).to_bytes(4, 'big'), 8, 0, 1))
        self.assertEqual([item[0] for item in unpack(reverse)], [0, 1])

    def test_ready_output_streams_share_connection_credit_round_robin(self):
        bridge = self.input_bridge()
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'a' * 65535))
        bridge.feed('R', frame((100000).to_bytes(4, 'big'), 8, 0, 1))
        for stream in (1, 3, 5):
            bridge.feed('L', frame(b'x', 0, 0, stream), lambda m: m.parts[-1].set_bytes(b'z' * 50000))
        _, output = bridge.feed('R', frame((49152).to_bytes(4, 'big'), 8, 0, 0))
        ids = [stream for kind, _, stream, _ in unpack(output) if kind == 0]
        self.assertEqual(set(ids), {1, 3, 5})
        self.assertEqual(len(ids), 3)

    def test_streaming_multimegabyte_data_never_reserves_whole_body(self):
        for side in ('L', 'R'):
            peers = self.make_peers()
            peers.open(reverse=side == 'R')
            for index in range(128):
                peers.data(side, b'x' * 16384, b'xy' * 16384, end=index == 127)
                self.assertFalse(peers.bridge.reserved)
                self.assertLess(len(json.dumps(peers.bridge.control)), 16384)
                self.assertFalse(peers.bridge.held.get(side))
            target = 'R' if side == 'L' else 'L'
            self.assertEqual(b''.join(peers.received[target]), b'xy' * (2 * 1024 * 1024))
            self.assertIn(1, peers.ended[target])

    def test_padding_only_data_can_finish_without_output_credit(self):
        bridge = self.input_bridge()
        bridge.feed('R', frame(b'\x00\x04\x00\x00\x00\x00', 4, 0, 0))
        # In-flight pre-ACK input is legal; reframing removes padding and the
        # zero-byte END_STREAM does not need receiver DATA credit.
        output, _ = bridge.feed('L', frame(b'\x03\0\0\0', 0, 9, 1))
        self.assertEqual(output, frame(b'', 0, 1, 1))

    def test_blocked_trailer_preserves_global_hpack_and_settings_ack_order(self):
        bridge = self.input_bridge()
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        encoder, decoder = hpack.Encoder(), hpack.Decoder()
        trailer = [(b'x-shared', b'kept')]
        headers = [(b':method', b'GET'), (b'x-shared', b'kept')]
        output, _ = bridge.feed('L', frame(encoder.encode(trailer), 1, 5, 1) +
                               frame(encoder.encode(headers), 1, 5, 3))
        self.assertEqual(output, b'')
        bridge.feed('R', frame(b'\x00\x01\x00\x00\x00\x00', 4, 0, 0))
        self.assertEqual(bridge.feed('L', frame(b'', 4, 1, 0))[0], b'')
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, reverse = bridge.feed('R', updates)
        parts = unpack(reverse)
        self.assertEqual([part[0] for part in parts], [0, 1, 1, 4])
        self.assertEqual(decoder.decode(parts[1][3], raw=True), trailer)
        self.assertEqual(decoder.decode(parts[2][3], raw=True), headers)

    def test_reserved_gzip_uses_encoded_capacity_and_repairs_length(self):
        import random
        body = gzip.compress(random.Random(7).randbytes(100000), mtime=0)
        bridge = self.input_bridge()
        fields = [(b':method', b'POST'), (b'content-length', str(len(body)).encode()),
                  (b'content-encoding', b'gzip')]
        def edit(message):
            header = message.parts[0]
            if not header.content.complete:
                message.parts.hold_from(header)
                Connection(message).http2.reserve_body(header, 128 * 1024)
            else:
                self.assertEqual(len(message.bodies()[0].get_bytes()), 100000)
                message.bodies()[0].set_bytes(b'z' * 200000)
        bridge.feed('L', frame(hpack.Encoder().encode(fields), 1, 4, 1), edit)
        for offset in range(0, len(body), 16000):
            chunk = body[offset:offset + 16000]
            output, _ = bridge.feed('L', frame(chunk, 0, int(offset + len(chunk) == len(body)), 1), edit)
        frames = unpack(output)
        encoded = b''.join(item[3] for item in frames if item[0] == 0)
        self.assertEqual(gzip.decompress(encoded), b'z' * 200000)
        self.assertIn((b'content-length', str(len(encoded)).encode()), hpack.Decoder().decode(frames[0][3], raw=True))
        self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)

    def test_reserved_body_shares_connection_credit_with_other_retained_stream(self):
        peers = self.make_peers()
        sender = peers.peers['L']
        fields = [(b':method', b'POST'), (b':scheme', b'https'),
                  (b':authority', b'example.test'), (b':path', b'/')]
        for stream in (1, 3):
            sender.send_headers(stream, fields)
        def retain(message):
            first = message.parts[0]
            if first.content.complete is False:
                message.parts.hold_from(first)
                Connection(message).http2.reserve_body(first, 128 * 1024)
        peers.pump('L', sender.data_to_send(), retain)
        sender.send_data(3, b'y' * 10000, end_stream=True)
        peers.pump('L', sender.data_to_send(), retain)
        sent = 0
        while sent < 100000:
            count = min(16000, 100000 - sent, sender.local_flow_control_window(1))
            self.assertGreater(count, 0)
            sent += count
            sender.send_data(1, b'x' * count, end_stream=sent == 100000)
            peers.pump('L', sender.data_to_send(), retain)
        received = b''.join(peers.received['R'])
        self.assertEqual(received.count(b'x'), 100000)
        self.assertEqual(received.count(b'y'), 10000)
        self.assertEqual(sender.outbound_flow_control_window, 65535)
        self.assertEqual(peers.bridge.control['flow']['L']['advance_due'], 0)

    def test_reserved_credit_survives_fresh_workers(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event
        script = ('for part in api.message.parts:\n'
                  '    if part.type == PartType.Http2.Header and part.content.complete is False:\n'
                  '        api.message.parts.hold_from(part)\n'
                  '        api.connection.http2.reserve_body(part, 128 * 1024)\n        break\n'
                  f'return api.message.translate(safety=Safety.{self.safety.title()})')
        control, table, held = None, None, None
        header = frame(hpack.Encoder().encode([(b':method', b'POST')]), 1, 4, 1)
        wires = [header] + [frame(b'x' * 16000, 0, 0, 1)] * 6 + [frame(b'x' * 4000, 0, 1, 1)]
        refunded = 0
        for wire in wires:
            request = event(wire, 'L')
            request['details']['info']['webhook_control'] = {'content-reverse': True}
            result = run(script, request, translate_allowed=control is None, translate_active=control is not None,
                         translate_state=table, translate_control=control, held_parts=held, hold_allowed=True,
                         hold_credit_available=True, hold_credit_reserved=control is not None,
                         instance={'mode': 'flow'})
            self.assertTrue(result['ok'], result)
            control, table, held = result['translate_control'], result['translate_state'], result.get('held_parts')
            reverse = base64.b64decode(result.get('replacement_reverse', ''))
            refunded += sum(int.from_bytes(payload, 'big') for kind, _, stream, payload in unpack(reverse)
                            if kind == 8 and stream == 0)
        # The original receiver has granted no more output credit: the retained
        # body is now a pending output obligation, still backed by the reservation.
        self.assertTrue(control['flow']['L']['queue'])
        self.assertTrue(control['flow']['hold_reserved'])
        self.assertLess(refunded, 100000)
        self.assertIsNone(held)
        request = event(frame(b'\0\0\0\x08', 3, 0, 1), 'R')
        request['details']['info']['webhook_control'] = {'content-reverse': True}
        result = run(script, request, translate_active=True, translate_control=control,
                     hold_allowed=True, hold_credit_available=True, hold_credit_reserved=True,
                     instance={'mode': 'flow'})
        self.assertTrue(result['ok'], result)
        direction = result['translate_control']['flow']['L']
        self.assertEqual(direction['input']['owned'], 0)
        self.assertEqual(direction['input']['window'], 65535)
        self.assertFalse(direction.get('bodies'))

    def test_collecting_cancel_survives_fresh_workers_and_peer_hold_publication(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event
        script = ('for part in api.message.parts:\n'
                  '    if part.type == PartType.Http2.Header and part.content.complete is False:\n'
                  '        api.message.parts.hold_from(part)\n'
                  '        api.connection.http2.reserve_body(part, 128 * 1024)\n        break\n'
                  f'return api.message.translate(safety=Safety.{self.safety.title()})')
        control, tables, holds = None, {}, {}
        encoder = hpack.Encoder()
        fields = [(b':method', b'POST'), (b'x-index', b'preserved source state')]
        data = frame(b'x' * 1000, 0, 0, 1)
        steps = [('L', frame(encoder.encode(fields), 1, 4, 1)), ('L', data[:20]),
                 ('R', frame(b'\0\0\0\x08', 3, 0, 1)),
                 ('L', data[20:] + frame(encoder.encode(fields), 1, 5, 3))]
        for side, wire in steps:
            peer = 'R' if side == 'L' else 'L'
            request = event(wire, side)
            request['details']['info']['webhook_control'] = {'content-reverse': True}
            result = run(script, request, translate_allowed=control is None, translate_active=control is not None,
                         translate_state=tables.get(side), translate_control=control, held_parts=holds.get(side),
                         peer_held_parts=holds.get(peer), hold_allowed=True, hold_credit_available=True,
                         hold_credit_reserved=bool(control and control['flow'].get('hold_reserved')),
                         instance={'mode': 'flow'})
            self.assertTrue(result['ok'], result)
            control, tables[side], holds[side] = result['translate_control'], result['translate_state'], result.get('held_parts')
            if 'peer_held_parts' in result:
                holds[peer] = result['peer_held_parts']
            if side == 'R':
                self.assertIn('peer_held_parts', result)
                self.assertFalse(result['hold_credit_reservation'])
                self.assertEqual(control['flow']['L']['input']['owned'], 0)
        frames = unpack(base64.b64decode(result['replacement']))
        self.assertEqual([(kind, stream) for kind, _, stream, _ in frames], [(1, 3)])
        self.assertEqual(hpack.Decoder().decode(frames[0][3], raw=True), fields)

    def test_reserved_cancellation_churn_reclaims_capacity_and_keeps_ranges_bounded(self):
        bridge = self.input_bridge()
        encoder = hpack.Encoder()
        def retain(message):
            for part in message.parts:
                if part.frame_type == 1 and part.content.complete is False:
                    message.parts.hold_from(part)
                    Connection(message).http2.reserve_body(part, 128 * 1024)
                    break
        for stream in range(1, 2401, 2):
            fields = [(b':method', b'POST'), (b'x-iteration', str(stream).encode())]
            bridge.feed('L', frame(encoder.encode(fields), 1, 4, stream), retain)
            bridge.feed('L', frame(b'x' * (stream % 97 + 1), 0, 0, stream), retain)
            self.assertTrue(bridge.reserved)
            bridge.feed('R', frame(b'\0\0\0\x08', 3, 0, stream))
            self.assertFalse(bridge.reserved)
            self.assertEqual(bridge.control['flow']['L']['input']['window'], 65535)
            self.assertEqual(bridge.control['flow']['L']['input']['owned'], 0)
            self.assertLess(len(json.dumps(bridge.control)), 8192)
        self.assertEqual(bridge.feed('L', b''), (b'', b''))

    def test_retained_content_length_and_lazy_gzip_body(self):
        for compressed in (False, True):
            bridge = self.make_bridge()
            bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            body = gzip.compress(b'abc', mtime=0) if compressed else b'abc'
            fields = [(b':method', b'POST'), (b'content-length', str(len(body)).encode())]
            if compressed:
                fields.append((b'content-encoding', b'gzip'))
            header = frame(hpack.Encoder().encode(fields), 1, 4, 1)
            bridge.feed('L', header + frame(body, 0, 1, 1)[:10],
                        lambda m: m.parts.hold_from(m.parts[0]))
            message = bridge.message('L', frame(body, 0, 1, 1)[10:])
            message.bodies()[0].set_bytes(b'changed body')
            output = bridge.publish('L', message)
            frames = unpack(output)
            headers = hpack.Decoder().decode(frames[0][3], raw=True)
            encoded = b''.join(item[3] for item in frames if item[0] == 0)
            self.assertIn((b'content-length', str(len(encoded)).encode()), headers)
            self.assertEqual(gzip.decompress(encoded) if compressed else encoded, b'changed body')

    def test_emitted_content_length_cannot_be_repaired(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        header = frame(hpack.Encoder().encode([(b':method', b'POST'), (b'content-length', b'3')]), 1, 4, 1)
        bridge.feed('L', header)
        message = bridge.message('L', frame(b'abc', 0, 1, 1))
        message.parts[0].set_bytes(b'longer')
        with self.assertRaisesRegex(CommitException, 'after emitting Content-Length'):
            bridge.publish('L', message)

    def test_negative_initial_window_and_independent_streams(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'a' * 100, 0, 0, 1))
        bridge.feed('R', frame(b'\x00\x04\x00\x00\x00\x00', 4, 0, 0))
        self.assertEqual(bridge.control['flow']['L']['streams']['1']['output'], -100)
        # DATA sent before the SETTINGS ACK may still use the earlier window.
        output, _ = bridge.feed('L', frame(b'x', 0, 0, 1) + frame(b'y', 0, 0, 3))
        self.assertEqual(output, b'')
        bridge.feed('L', frame(b'', 4, 1, 0))
        _, reverse = bridge.feed('R', frame((101).to_bytes(4, 'big'), 8, 0, 1))
        self.assertEqual(reverse, frame(b'x', 0, 0, 1))
        _, reverse = bridge.feed('R', frame((1).to_bytes(4, 'big'), 8, 0, 3))
        self.assertEqual(reverse, frame(b'y', 0, 0, 3) + frame(b'', 4, 1, 0))

    def test_reset_discards_pending_data_and_refunds_connection(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'z' * 70000))
        forward, reverse = bridge.feed('R', frame(b'\x00\x00\x00\x08', 3, 0, 1))
        self.assertEqual(bridge.control['flow']['L']['queue'], [])
        self.assertEqual(reverse, b'')
        self.assertEqual([item[0] for item in unpack(forward)], [3, 8])

    def test_fresh_workers_restore_both_directional_output_and_state(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event
        states, control = {}, None
        script = ('for part in api.message.parts:\n'
                  '    if part.frame_type == 0:\n        part.set_bytes(b"z" * 65536)\n'
                  f'return api.message.translate(safety=Safety.{self.safety.title()})')
        for side, wire in [('L', frame(b'x', 0, 1, 1)),
                           ('R', frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1))]:
            request = event(wire, side)
            request['details']['info']['webhook_control'] = {'content-reverse': True}
            result = run(script, request, translate_allowed=control is None, translate_active=control is not None,
                         translate_state=states.get(side), translate_control=control, instance={'mode': 'flow'})
            self.assertTrue(result['ok'], result)
            states[side] = result['translate_state']
            control = result['translate_control']
        self.assertEqual(base64.b64decode(result['replacement_reverse']), frame(b'z', 0, 1, 1))

    def test_settings_ack_stays_after_previously_encoded_headers(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        block = hpack.Encoder().encode([(b':method', b'GET')])
        headers, _ = bridge.feed('L', frame(block, 1, 5, 3))
        self.assertEqual([item[0] for item in unpack(headers)], [1])
        bridge.feed('R', frame(b'\x00\x01\x00\x00\x00\x00', 4, 0, 0))
        forward, _ = bridge.feed('L', frame(b'', 4, 1, 0))
        self.assertEqual(forward, b'')
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, reverse = bridge.feed('R', updates)
        self.assertEqual([item[0] for item in unpack(reverse)], [0, 4])

    def test_capability_loss_is_not_silently_downgraded(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        message = Message(b'', 0, {})
        with self.assertRaisesRegex(CommitException, 'lost content-reverse'):
            _prepare_translation(message, {'translate_active': True, 'translate_control': bridge.control})

    def test_reset_preserves_queued_hpack_and_later_indexed_headers(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        encoder, decoder = hpack.Encoder(), hpack.Decoder()
        fields = [(b':method', b'GET'), (b'x-state', b'must survive reset')]
        headers, _ = bridge.feed('L', frame(encoder.encode(fields), 1, 5, 3))
        self.assertEqual(decoder.decode(unpack(headers)[0][3], raw=True), fields)
        bridge.feed('R', frame(b'\x00\x00\x00\x08', 3, 0, 3))
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, reverse = bridge.feed('R', updates)
        self.assertEqual([item[0] for item in unpack(reverse)], [0])
        output, _ = bridge.feed('L', frame(encoder.encode(fields), 1, 5, 5))
        self.assertEqual(decoder.decode(unpack(output)[0][3], raw=True), fields)

    def test_goaway_discards_excluded_data_and_drains_accepted_stream(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        bridge.feed('L', frame(b'excluded', 0, 0, 3))
        goaway = frame((1).to_bytes(4, 'big') + b'\0' * 4, 7, 0, 0)
        forward, reverse = bridge.feed('R', goaway)
        self.assertEqual(unpack(forward)[0][0], 7)
        self.assertEqual(unpack(forward)[1:], [(8, 0, 0, (8).to_bytes(4, 'big'))])
        self.assertEqual(reverse, b'')
        self.assertEqual(len(bridge.control['flow']['L']['queue']), 1)
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, reverse = bridge.feed('R', updates)
        self.assertEqual(reverse, frame(b'z', 0, 0, 1))
        previous = json.dumps(bridge.control)
        with self.assertRaisesRegex(CommitException, 'must not increase'):
            bridge.feed('R', frame((3).to_bytes(4, 'big') + b'\0' * 4, 7, 0, 0))
        self.assertEqual(json.dumps(bridge.control), previous)

    def test_both_directions_can_have_pending_output(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        for side in ('L', 'R'):
            bridge.feed(side, frame(b'x', 0, 1, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        self.assertTrue(bridge.control['flow']['L']['queue'])
        self.assertTrue(bridge.control['flow']['R']['queue'])
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        for side in ('L', 'R'):
            _, reverse = bridge.feed(side, updates)
            self.assertEqual(reverse, frame(b'z', 0, 1, 1))
        self.assertEqual(bridge.control['flow']['L']['queue'], [])
        self.assertEqual(bridge.control['flow']['R']['queue'], [])

    def test_hold_does_not_acknowledge_unreleased_input(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        forward, reverse = bridge.feed('L', frame(b'x', 0, 0, 1),
                                      lambda m: m.parts.hold_from(m.parts[0]))
        self.assertEqual((forward, reverse), (b'', b''))
        self.assertEqual(bridge.control['flow']['L']['credit'], 0)
        forward, reverse = bridge.feed('L', b'')
        self.assertEqual(forward, frame(b'x', 0, 0, 1))
        self.assertEqual([item[2] for item in unpack(reverse)], [0, 1])

    def test_closed_stream_churn_and_late_credit(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        for stream in range(1, 6000, 2):
            bridge.feed('L', frame(b'', 0, 1, stream))
        self.assertEqual(bridge.control['flow']['L']['streams'], {})
        self.assertEqual(bridge.control['flow']['L']['retired'], {'1': [[1, 5999]]})
        before = json.dumps(bridge.control)
        self.assertEqual(bridge.feed('R', frame((10).to_bytes(4, 'big'), 8, 0, 1)), (b'', b''))
        self.assertEqual(json.dumps(bridge.control), before)
        with self.assertRaisesRegex(CommitException, 'termination'):
            bridge.feed('L', frame(b'invalid', 0, 0, 1))

    def test_out_of_order_closure_preserves_open_holes(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        for stream in (1, 3, 5):
            bridge.feed('L', frame(b'open', 0, 0, stream))
        for stream in (5, 1):
            bridge.feed('L', frame(b'', 0, 1, stream))
        self.assertEqual(set(bridge.control['flow']['L']['streams']), {'3'})
        bridge.feed('L', frame(b'still open', 0, 0, 3))
        bridge.feed('L', frame(b'', 0, 1, 3))
        self.assertEqual(bridge.control['flow']['L']['retired'], {'1': [[1, 5]]})

    def test_active_and_sparse_retirement_quotas_remain_bounded(self):
        for end, step, error in ((0, 2, 'stream quota'), (1, 4, 'range quota')):
            bridge = self.make_bridge()
            bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            bridge.feed('L', b''.join(frame(b'', 0, end, stream)
                                     for stream in range(1, 1024 * step, step)))
            previous = json.dumps(bridge.control)
            with self.assertRaisesRegex(CommitException, error):
                bridge.feed('L', frame(b'', 0, end, 1024 * step + 1))
            self.assertEqual(json.dumps(bridge.control), previous)

    def test_inflight_data_after_reset_refunds_only_connection(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('R', frame(b'\0\0\0\x08', 3, 0, 1))
        forward, reverse = bridge.feed('L', frame(b'late', 0, 0, 1))
        self.assertEqual(forward, b'')
        self.assertEqual(unpack(reverse), [(8, 0, 0, (4).to_bytes(4, 'big'))])

    def test_reset_does_not_overtake_own_queued_headers(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 0, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        headers, _ = bridge.feed('L', frame(hpack.Encoder().encode([(b':method', b'GET')]), 1, 4, 3))
        self.assertEqual([item[0] for item in unpack(headers)], [1])
        output, _ = bridge.feed('L', frame(b'\0\0\0\x08', 3, 0, 3))
        self.assertEqual(output, b'')
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, output = bridge.feed('R', updates)
        self.assertEqual([item[0] for item in unpack(output)], [0, 3])

    def test_input_end_stream_is_enforced_while_output_is_pending(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 1, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        before = json.dumps(bridge.control)
        with self.assertRaisesRegex(CommitException, 'termination'):
            bridge.feed('L', frame(b'after end', 0, 0, 1))
        self.assertEqual(json.dumps(bridge.control), before)

    def test_goaway_keeps_hpack_for_excluded_streams_in_both_directions(self):
        for side, stream in (('L', 3), ('R', 2)):
            peer = 'R' if side == 'L' else 'L'
            bridge = self.make_bridge()
            bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
            bridge.feed(side, frame(b'x', 0, 0, stream),
                        lambda m: m.parts[0].set_bytes(b'z' * 65536))
            encoder, decoder = hpack.Encoder(), hpack.Decoder()
            fields = [(b'x-shared', b'compression state')]
            headers, _ = bridge.feed(side, frame(encoder.encode(fields), 1, 5, stream + 2))
            self.assertEqual(decoder.decode(unpack(headers)[0][3], raw=True), fields)
            forward, reverse = bridge.feed(peer, frame(b'\0' * 8, 7, 0, 0))
            self.assertEqual(unpack(forward)[0][0], 7)
            self.assertEqual(reverse, b'')
            # Race with GOAWAY: decode source indices without creating a new
            # destination compression block for already excluded headers.
            forward, reverse = bridge.feed(side, frame(encoder.encode(fields), 1, 4, stream + 4) +
                                           frame(b'ignored', 0, 1, stream + 4))
            self.assertEqual(forward, b'')
            self.assertEqual(unpack(reverse), [(8, 0, 0, (7).to_bytes(4, 'big'))])
            accepted = 2 if side == 'L' else 1
            forward, _ = bridge.feed(side, frame(encoder.encode(fields), 1, 5, accepted))
            self.assertEqual(decoder.decode(unpack(forward)[0][3], raw=True), fields)

    def test_reset_markers_survive_fresh_workers(self):
        from inspection_cookbook_test import run
        from inspection_translate_worker_test import event
        states, control = {}, None
        script = f'return api.message.translate(safety=Safety.{self.safety.title()})'
        for side, wire in [('L', frame(b'first', 0, 0, 1)),
                           ('R', frame(b'\0\0\0\x08', 3, 0, 1)),
                           ('L', frame(b'late', 0, 0, 1))]:
            request = event(wire, side)
            request['details']['info']['webhook_control'] = {'content-reverse': True}
            result = run(script, request, translate_allowed=control is None, translate_active=control is not None,
                         translate_state=states.get(side), translate_control=control, instance={'mode': 'flow'})
            self.assertTrue(result['ok'], result)
            states[side] = result['translate_state']
            control = result['translate_control']
        self.assertEqual(base64.b64decode(result['replacement']), b'')
        self.assertEqual(unpack(base64.b64decode(result['replacement_reverse'])),
                         [(8, 0, 0, (4).to_bytes(4, 'big'))])

    def test_expansion_shrink_zero_and_following_data_both_directions(self):
        for side in ('L', 'R'):
            for size in (0, 1, 16384, 65535, 65536, 200000):
                with self.subTest(side=side, size=size):
                    peers = self.make_peers()
                    peers.open(reverse=side == 'R')
                    peers.data(side, b'x', b'a' * size)
                    peers.data(side, b'next', b'next', end=True)
                    target = 'R' if side == 'L' else 'L'
                    self.assertEqual(b''.join(peers.received[target]), b'a' * size + b'next')
                    self.assertEqual(peers.ended[target].count(1), 1)
                    self.assertEqual(peers.bridge.control['flow'][side]['queue'], [])

    def test_padding_and_end_stream_after_multiple_windows(self):
        for side in ('L', 'R'):
            peers = self.make_peers()
            peers.open(reverse=side == 'R')
            peers.data(side, b'abc', b'z' * 150000, end=True, padding=17)
            target = 'R' if side == 'L' else 'L'
            self.assertEqual(b''.join(peers.received[target]), b'z' * 150000)
            self.assertEqual(peers.ended[target], [1])

    def test_shrink_full_input_window_repeatedly(self):
        peers = self.make_peers()
        peers.open()
        for _ in range(12):
            peers.data('L', b'x' * 16000, b'')
        self.assertEqual(peers.peers['L'].local_flow_control_window(1), 65535)
        peers.data('L', b'final', b'final', end=True)
        self.assertEqual(b''.join(peers.received['R']), b'final')

    def test_invalid_credit_and_quota_are_retryable(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        before = json.dumps(bridge.control)
        for value in (0, 0x7fffffff):
            message = bridge.message('R', frame(value.to_bytes(4, 'big'), 8, 0, 0))
            with self.assertRaises(CommitException):
                bridge.publish('R', message)
            self.assertEqual(json.dumps(bridge.control), before)
            self.assertIsNone(message._translation.result)
        message = bridge.message('L', frame(b'x', 0, 0, 1))
        message.parts[0].set_bytes(b'a' * 500000)
        with self.assertRaisesRegex(CommitException, '384 KiB'):
            bridge.publish('L', message)
        message.parts[0].set_bytes(b'ok')
        self.assertEqual(bridge.publish('L', message), frame(b'ok', 0, 0, 1))

    def test_fragmented_update_releases_reverse_without_new_data(self):
        bridge = self.make_bridge()
        bridge.feed('L', b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')
        bridge.feed('L', frame(b'x', 0, 1, 1), lambda m: m.parts[0].set_bytes(b'z' * 65536))
        update = frame(b'\x00\x00\x00\x01', 8, 0, 0) + frame(b'\x00\x00\x00\x01', 8, 0, 1)
        for byte in update[:-1]:
            _, reverse = bridge.feed('R', bytes([byte]))
            self.assertEqual(reverse, b'')
        forward, reverse = bridge.feed('R', update[-1:])
        self.assertEqual(reverse, frame(b'z', 0, 1, 1))
        self.assertEqual(unpack(forward)[0][0], 8)


class ExpertWindowsTests(WindowsTests):
    safety = 'expert'


if __name__ == '__main__':
    unittest.main()
