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
from inspection_api import Message, HeldCommit, CommitException, _prepare_translation
from inspection_h2_test import frame, unpack


class Bridge:
    def __init__(self, safety='easy'):
        self.safety = safety
        self.tables, self.held = {}, {}
        self.control = None
        self.reverse = b''

    def message(self, side, wire):
        message = Message(wire, len(wire), {})
        _prepare_translation(message, {
            'event': {'details': {'info': {'side': side, 'webhook_control': {'content-reverse': True}}}},
            'translate_allowed': self.control is None,
            'translate_active': self.control is not None,
            'translate_state': self.tables.get(side), 'translate_control': self.control,
            'held_parts': self.held.get(side),
        })
        return message

    def publish(self, side, message):
        result = message.translate(safety=self.safety)
        transaction = message._translation
        self.tables[side] = json.loads(json.dumps(transaction.checkpoint))
        self.control = json.loads(json.dumps(transaction.control_checkpoint))
        self.held[side] = result.checkpoint if isinstance(result, HeldCommit) else None
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
        bridge.feed('L', frame(block, 1, 5, 3))
        bridge.feed('R', frame(b'\x00\x01\x00\x00\x00\x00', 4, 0, 0))
        forward, _ = bridge.feed('L', frame(b'', 4, 1, 0))
        self.assertEqual(forward, b'')
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, reverse = bridge.feed('R', updates)
        self.assertEqual([item[0] for item in unpack(reverse)], [0, 1, 4])

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
        bridge.feed('L', frame(encoder.encode(fields), 1, 5, 3))
        bridge.feed('R', frame(b'\x00\x00\x00\x08', 3, 0, 3))
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, reverse = bridge.feed('R', updates)
        self.assertEqual([item[0] for item in unpack(reverse)], [0, 1])
        self.assertEqual(decoder.decode(unpack(reverse)[1][3], raw=True), fields)
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
        bridge.feed('L', frame(hpack.Encoder().encode([(b':method', b'GET')]), 1, 4, 3))
        output, _ = bridge.feed('L', frame(b'\0\0\0\x08', 3, 0, 3))
        self.assertEqual(output, b'')
        updates = frame((1).to_bytes(4, 'big'), 8, 0, 0) + frame((1).to_bytes(4, 'big'), 8, 0, 1)
        _, output = bridge.feed('R', updates)
        self.assertEqual([item[0] for item in unpack(output)], [0, 1, 3])

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
            bridge.feed(side, frame(encoder.encode(fields), 1, 5, stream + 2))
            forward, reverse = bridge.feed(peer, frame(b'\0' * 8, 7, 0, 0))
            self.assertEqual(unpack(forward)[0][0], 7)
            self.assertEqual(decoder.decode(unpack(reverse)[0][3], raw=True), fields)
            # Race with GOAWAY: decode subsequent source indices and preserve
            # destination compression state, but discard application DATA.
            forward, reverse = bridge.feed(side, frame(encoder.encode(fields), 1, 4, stream + 4) +
                                           frame(b'ignored', 0, 1, stream + 4))
            self.assertEqual([item[0] for item in unpack(forward)], [1])
            self.assertEqual(decoder.decode(unpack(forward)[0][3], raw=True), fields)
            self.assertEqual(unpack(reverse), [(8, 0, 0, (7).to_bytes(4, 'big'))])

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
