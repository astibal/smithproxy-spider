"""ClientHello meta drafts and real sandboxed native script publication."""

import base64
from dataclasses import FrozenInstanceError
import unittest

from addon_tls_native_test import client_hello
from native_lifecycle_test import Worker
from inspection_tls import ClientHelloDraft, TlsDecision


def observation():
    value = client_hello()
    value['upstream'] = {
        'sni': 'probe.invalid',
        'alpn_base64': base64.b64encode(b'\x08http/1.1').decode(),
        'openssl_cipher_list': 'ECDHE+AESGCM',
    }
    return value


class DraftTests(unittest.TestCase):
    def test_snapshot_commit_and_no_commit(self):
        draft = ClientHelloDraft(observation())
        original = draft.original()
        draft.sni = 'edited.invalid'
        draft.openssl_cipher_list = original.openssl_cipher_list + ':!AES128'

        self.assertEqual(draft.publish(None)['upstream']['sni'], 'probe.invalid')
        committed = draft.commit()
        draft.sni = 'later.invalid'
        draft.alpn_offers.clear()

        self.assertEqual(draft.publish(committed)['upstream']['sni'], 'edited.invalid')
        self.assertEqual(committed.alpn_offers, (b'http/1.1',))
        self.assertEqual(original.sni, 'probe.invalid')
        self.assertIs(original, draft.original())
        with self.assertRaises(FrozenInstanceError):
            original.sni = 'invalid'
        with self.assertRaises(TypeError):
            original.alpn_offers[0] = b'h2'

    def test_invalid_edits_and_foreign_commit(self):
        for name, value in [('sni', '127.0.0.1'), ('sni', 'bad..name'),
                            ('alpn_offers', [b'h2']), ('alpn_offers', None),
                            ('openssl_cipher_list', 'bad\0expression'),
                            ('decision', 'continue')]:
            with self.subTest(name=name, value=value):
                draft = ClientHelloDraft(observation())
                setattr(draft, name, value)
                with self.assertRaises(ValueError):
                    draft.commit()

        first = ClientHelloDraft(observation())
        second = ClientHelloDraft(observation())
        with self.assertRaises(ValueError):
            first.publish(second.commit())

    def test_explicit_decisions(self):
        draft = ClientHelloDraft(observation())
        draft.decision = TlsDecision.BYPASS
        self.assertEqual(draft.publish(draft.commit()),
                         {'proceed': True, 'ignore_connection': True})
        draft.decision = TlsDecision.TERMINATE
        self.assertEqual(draft.publish(draft.commit()),
                         {'proceed': False, 'ignore_connection': False})

    def test_native_worker_retains_state_and_exposes_enum(self):
        worker = Worker("""
def init(api, state):
    return {'calls': 0}

def main(api, state):
    state['calls'] += 1
    if api.tls is not None:
        assert api.tls.event is TlsEvent.CLIENT_HELLO
        assert api.message is None
        assert state['calls'] == 2
        assert api.state['setup'] is True
        hello = api.tls.client_hello
        hello.sni = 'native.invalid'
        hello.openssl_cipher_list = hello.original().openssl_cipher_list + ':!AES128'
        api.state['hello'] = True
        return hello.commit()
    api.state['setup'] = True
""")
        self.addCleanup(worker.close)
        self.assertTrue(worker.ready['ready'], worker.ready)
        setup = worker.call(event={'id': 'session', 'action': 'connection-start'})
        self.assertTrue(setup['ok'], setup)

        result = worker.call(
            event={'id': 'session', 'action': 'tls-lifecycle',
                   'details': {'tls': observation()}},
            instance_state=setup['instance_state'],
        )
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['decision']['upstream']['sni'], 'native.invalid')
        self.assertTrue(result['instance_state']['hello'])


class HandshakeTests(unittest.TestCase):
    def observation(self, phase='established', side='server', attempt=1):
        return {'envelope': {'version': 1, 'connection_id': 'session',
                            'event': phase, 'side': side, 'attempt': attempt},
                'sni': 'origin.invalid', 'cipher': 'TLS_AES_128_GCM_SHA256',
                'tls_version': 'TLSv1.3', 'alpn_base64': 'aDI=', 'certificates': [],
                'upstream': {'sni': 'origin.invalid', 'alpn_base64': 'Amgy',
                             'openssl_cipher_list': 'DEFAULT'}}

    def test_outcome_is_immutable_and_decisions_are_explicit(self):
        from inspection_tls import TlsView, TlsEvent, TlsSide
        view = TlsView.from_observation(self.observation())
        self.assertIs(view.event, TlsEvent.ESTABLISHED)
        self.assertIs(view.side, TlsSide.SERVER)
        draft = view.outcome
        self.assertEqual(draft.alpn, b'h2')
        with self.assertRaises(AttributeError):
            draft.sni = 'edited.invalid'
        with self.assertRaises(FrozenInstanceError):
            draft.original().sni = 'edited.invalid'

        draft.decision = TlsDecision.TERMINATE
        self.assertEqual(view.publish(None), {'proceed': True})
        result = draft.commit()
        draft.decision = TlsDecision.CONTINUE
        self.assertEqual(view.publish(result), {'proceed': False})
        other = TlsView.from_observation(self.observation()).outcome
        with self.assertRaises(ValueError):
            draft.publish(other.commit())
        draft.decision = TlsDecision.BYPASS
        with self.assertRaises(ValueError):
            draft.commit()

        failure = self.observation('failed')
        with self.assertRaises(ValueError):
            TlsView.from_observation(failure)
        failure['error'] = 'handshake timeout'
        draft = TlsView.from_observation(failure).outcome
        self.assertEqual(draft.error, 'handshake timeout')
        draft.decision = TlsDecision.TERMINATE
        with self.assertRaises(ValueError):
            draft.commit()

    def test_start_commit_and_client_read_only_settings(self):
        from inspection_tls import TlsView
        draft = TlsView.from_observation(self.observation('start')).start
        original = draft.original()
        draft.sni = 'edited.invalid'
        draft.alpn_offers = []
        self.assertEqual(draft.publish(None)['upstream']['sni'], 'origin.invalid')
        result = draft.commit()
        draft.sni = 'later.invalid'
        self.assertEqual(draft.publish(result)['upstream']['sni'], 'edited.invalid')
        self.assertEqual(result.alpn_offers, ())
        self.assertEqual(original.sni, 'origin.invalid')
        draft.decision = TlsDecision.BYPASS
        with self.assertRaises(ValueError):
            draft.commit()

        client = TlsView.from_observation(self.observation('start', 'client')).start
        client.sni = 'not-supported.invalid'
        with self.assertRaises(ValueError):
            client.commit()
        client.sni = client.original().sni
        client.decision = TlsDecision.TERMINATE
        self.assertEqual(client.publish(client.commit()), {'proceed': False})

    def test_quic_offer_and_outcome_share_the_native_api(self):
        from inspection_tls import TlsView, TlsTransport
        observed = self.observation('start')
        observed['upstream'] = {'sni': 'origin.invalid', 'alpn': 'h3', 'ciphers': None}
        view = TlsView.from_observation(observed, TlsTransport.QUIC)
        self.assertIs(view.transport, TlsTransport.QUIC)
        draft = view.start
        draft.sni = 'quic.invalid'
        draft.openssl_ciphersuites = ''
        result = draft.commit()
        draft.alpn_offers.clear()
        self.assertEqual(draft.publish(result)['upstream'],
                         {'sni': 'quic.invalid', 'alpn': 'h3', 'ciphers': ''})
        self.assertEqual(draft.publish(None)['upstream']['sni'], 'origin.invalid')
        with self.assertRaises(ValueError):
            draft.commit()

        observed = self.observation()
        observed['alpn'] = 'h3'
        view = TlsView.from_observation(observed, TlsTransport.QUIC)
        self.assertEqual(view.outcome.alpn, b'h3')

    def test_worker_delivers_all_events_without_content_and_keeps_state(self):
        worker = Worker("""
def init(api, state):
    return {'calls': 0}

def main(api, state):
    if api.tls is None:
        return
    assert api.phase == 'tls' and api.message is None
    state['calls'] += 1
    api.state['calls'] = state['calls']
    api.state['transport'] = api.tls.transport.value
    api.state['side'] = api.tls.side.value
    if api.tls.event is TlsEvent.START:
        return api.tls.start.commit()
    return api.tls.outcome.commit()
""")
        self.addCleanup(worker.close)
        self.assertTrue(worker.ready['ready'], worker.ready)
        state = {}
        for transport in ['tls', 'quic']:
            for side in ['server', 'client']:
                for phase in ['start', 'established', 'failed']:
                    if transport == 'quic' and side == 'client' and phase == 'start':
                        continue
                    observed = self.observation(phase, side)
                    observed['error'] = 'timeout' if phase == 'failed' else None
                    if transport == 'quic':
                        observed['alpn'] = 'h3'
                        observed['upstream'] = {'sni': 'origin.invalid', 'alpn': 'h3', 'ciphers': None}
                    response = worker.call(event={
                        'id': 'session', 'action': transport + '-lifecycle',
                        'details': {transport: observed}}, instance_state=state)
                    self.assertTrue(response['ok'], response)
                    state = response['instance_state']
                    self.assertEqual(state['transport'], transport)
                    self.assertEqual(state['side'], side)
        self.assertEqual(state['calls'], 11)


if __name__ == '__main__':
    unittest.main()
