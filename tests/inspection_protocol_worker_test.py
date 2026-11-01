"""Protocol snapshots cross actual sandbox workers, not shared Python objects."""
import base64
import copy
import unittest

from inspection_cookbook_test import fixture, run
from inspection_protocol_state import ProtocolStateOwner
import inspection_protocol_state_test as state_fixtures


class ProtocolWorkerTests(unittest.TestCase):
    def setup_tracking(self):
        result = run('api.connection.track_protocols()', fixture('setup'),
                     instance={'mode': 'flow'})
        self.assertTrue(result['ok'], result)
        self.assertFalse(result.get('rewrite_requested', False))
        return result['protocol_state']

    def callback(self, script, event, checkpoint, **options):
        result = run(script, event, protocol_state=checkpoint,
                     instance={'mode': 'flow'}, hold_allowed=True, **options)
        self.assertTrue(result['ok'], result)
        return result

    def test_tracking_is_opt_in_and_requires_flow_setup(self):
        disabled = run('api.print(api.http1.state, api.http2.state)', fixture('h1'))
        self.assertTrue(disabled['ok'], disabled)
        self.assertEqual(disabled['logs'], ['None None'])
        self.assertNotIn('protocol_state', disabled)

        for event, mode in ((fixture('setup'), 'message'), (fixture('h1'), 'flow')):
            with self.subTest(mode=mode, action=event.get('action')):
                rejected = run('api.connection.track_protocols()', event, instance={'mode': mode})
                self.assertFalse(rejected['ok'], rejected)
                self.assertNotIn('protocol_state', rejected)

    def test_immutable_entry_view_and_durable_publication(self):
        checkpoint = self.setup_tracking()
        script = '''
from dataclasses import FrozenInstanceError
state, = api.http1.state
api.print(state.sequence, state.content_complete, state.published)
try:
    state.published = True
except FrozenInstanceError:
    api.print('immutable')
result = api.message.commit()
api.print(state.published)
return result
'''
        first = self.callback(script, fixture('h1'), checkpoint)
        self.assertEqual(first['logs'], ['1 True False', 'immutable', 'False'])
        stored, = first['protocol_state']['http1']['messages']
        self.assertTrue(stored['published'])

        second = self.callback('api.print(api.http1.state[0].sequence)', fixture('h1'),
                               first['protocol_state'])
        self.assertEqual(second['logs'], ['2'])
        self.assertEqual(len(second['protocol_state']['http1']['messages']), 1)

    def test_hold_resume_keeps_identity_across_fresh_workers(self):
        checkpoint = self.setup_tracking()
        script = '''
state, = api.http1.state
api.print(state.sequence, state.content_complete, state.suspended)
if not state.content_complete:
    api.message.parts.hold_from(api.message.parts[0])
return api.message.commit()
'''
        first = self.callback(script, fixture('h1-partial'), checkpoint)
        self.assertEqual(first['logs'], ['1 False False'])
        stored, = first['protocol_state']['http1']['messages']
        self.assertTrue(stored['suspended'])
        self.assertFalse(stored['published'])

        # A callback from the other direction must not release the held request.
        peer = fixture('opaque')
        peer['details']['info']['side'] = 'R'
        observed = self.callback('api.print(api.http1.state[0].suspended)', peer,
                                 first['protocol_state'], peer_held_parts=first['held_parts'])
        self.assertEqual(observed['logs'], ['True'])
        self.assertTrue(observed['protocol_state']['http1']['messages'][0]['suspended'])

        tail = fixture('opaque')
        tail['details']['info'].update(content=base64.b64encode(b'bc').decode(),
                                      content_annotations=[])
        resumed = self.callback(script, tail, observed['protocol_state'],
                                held_parts=first['held_parts'])
        self.assertEqual(resumed['logs'], ['1 True True'])
        stored, = resumed['protocol_state']['http1']['messages']
        self.assertTrue(stored['published'])
        self.assertFalse(stored['suspended'])
        self.assertIsNone(resumed['held_parts'])

    def test_failure_does_not_return_candidate_checkpoint(self):
        checkpoint = self.setup_tracking()
        before = copy.deepcopy(checkpoint)
        failed = run("raise RuntimeError('rollback')", fixture('h1'),
                     protocol_state=checkpoint, instance={'mode': 'flow'})

        self.assertFalse(failed['ok'], failed)
        self.assertNotIn('protocol_state', failed)
        self.assertEqual(checkpoint, before)

    def test_checkpoint_cannot_cross_connections(self):
        checkpoint = self.setup_tracking()
        event = fixture('h1')
        event['id'] = 'another-connection'
        result = run('pass', event, protocol_state=checkpoint, instance={'mode': 'flow'})

        self.assertFalse(result['ok'], result)
        self.assertIn('another connection', str(result))

    def test_raw_replacement_leaves_publication_unknown(self):
        first = self.callback("return b''", fixture('h1'), self.setup_tracking())
        stored, = first['protocol_state']['http1']['messages']
        self.assertIsNone(stored['published'])

        # An unrelated callback must not turn an unknown old result into success.
        second = self.callback('pass', fixture('opaque'), first['protocol_state'])
        stored, = second['protocol_state']['http1']['messages']
        self.assertIsNone(stored['published'])

    def test_h2_suspend_and_reverse_resume_with_real_peer(self):
        import h2.events
        from inspection_h2_test import frame
        from inspection_translate_windows_test import Peers
        from inspection_translate_worker_test import event

        peers = Peers()
        checkpoint = self.setup_tracking()

        def invoke(side, wire, script):
            nonlocal checkpoint
            peer = 'R' if side == 'L' else 'L'
            request = event(wire, side)
            request['id'] = 'cookbook'
            request['details']['info']['webhook_control'] = {'content-reverse': True}
            result = self.callback(script, request, checkpoint,
                translate_active=True,
                translate_state=peers.bridge.tables.get(side),
                peer_translate_state=peers.bridge.tables.get(peer),
                translate_control=peers.bridge.control,
                held_parts=peers.bridge.held.get(side),
                peer_held_parts=peers.bridge.held.get(peer),
                hold_credit_available=True, hold_credit_reserved=peers.bridge.reserved)

            checkpoint = result['protocol_state']
            peers.bridge.tables[side] = result['translate_state']
            peers.bridge.control = result['translate_control']
            peers.bridge.reserved = result.get('hold_credit_reservation', False)
            peers.bridge.held[side] = result['held_parts']
            if 'peer_translate_state' in result:
                peers.bridge.tables[peer] = result['peer_translate_state']
            if 'peer_held_parts' in result:
                peers.bridge.held[peer] = result['peer_held_parts']

            return result

        peers.peers['L'].send_headers(1, [
            (':method', 'GET'), (':scheme', 'https'),
            (':authority', 'test.example'), (':path', '/'),
        ], end_stream=True)
        suspended = invoke('L', peers.peers['L'].data_to_send(), '''
stream, = api.http2.state
api.print(stream.request.content_complete, stream.request.suspended)
api.message.suspend(api.message.parts[0])
return api.message.translate()
''')
        self.assertEqual(suspended['logs'], ['True False'])
        stream, = checkpoint['http2']['streams']
        self.assertTrue(stream['request']['suspended'])
        self.assertFalse(stream['request']['published'])

        resumed = invoke('R', frame(b'12345678', 6, 0, 0), '''
api.print(api.http2.state[0].request.suspended)
api.message.resume(1)
return api.message.translate()
''')
        self.assertEqual(resumed['logs'], ['True'])
        stream, = checkpoint['http2']['streams']
        self.assertFalse(stream['request']['suspended'])
        self.assertTrue(stream['request']['published'])
        self.assertIsNone(stream['response']['content_complete'])

        events = peers.peers['R'].receive_data(base64.b64decode(resumed['replacement_reverse']))
        requests = [item.stream_id for item in events if isinstance(item, h2.events.RequestReceived)]
        self.assertEqual(requests, [1])


class ProtocolOwnerTests(unittest.TestCase):
    def test_failed_observation_does_not_retire_committed_records(self):
        owner = ProtocolStateOwner('one')
        owner.observe('L', state_fixtures.H1StateTests.parts(b'GET / HTTP/1.1\r\n\r\n'))
        owner.finish({}, set(), known_publication=True)
        before = owner.checkpoint()

        with self.assertRaises(ValueError):
            owner.observe('wrong-side', [])

        self.assertEqual(owner.checkpoint(), before)

    def test_unknown_and_incomplete_records_remain_bounded(self):
        owner = ProtocolStateOwner('one')
        owner.h1._limit = 2
        for _ in range(2):
            owner.observe('L', state_fixtures.H1StateTests.parts(b'GET / HTTP/1.1\r\n\r\n'))
            owner.finish({}, set(), known_publication=False)

        before = owner.checkpoint()
        with self.assertRaisesRegex(ValueError, 'limit'):
            owner.observe('L', state_fixtures.H1StateTests.parts(b'GET / HTTP/1.1\r\n\r\n'))

        self.assertEqual(owner.checkpoint(), before)


if __name__ == '__main__':
    unittest.main()
