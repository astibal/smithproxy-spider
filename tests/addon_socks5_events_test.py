"""Live-decision facade for the proposed SOCKS5 authentication producer."""

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_connection import Client
from addon_runtime import AddonGeneration
from addon_socks5_events import (
    Socks5AddonEvents,
    Socks5AuthObservation,
    Socks5TransportError,
)


def envelope(username='alice', password='secret', valid=True):
    return {
        'version': 1,
        'event': 'authenticate',
        'username': username,
        'password': password,
        'valid': valid,
    }


class Socks5EnvelopeTests(unittest.TestCase):
    def test_observation_preserves_policy_result_and_escaped_credentials(self):
        observed = Socks5AuthObservation.parse(
            envelope('\\xff', '\\xfe', False))
        self.assertEqual(observed.username, '\\xff')
        self.assertEqual(observed.password, '\\xfe')
        self.assertFalse(observed.valid)

    def test_envelope_is_exact_bounded_and_typed(self):
        cases = (
            ([], 'must be an object'),
            ({**envelope(), 'version': True}, 'version'),
            ({**envelope(), 'event': 'result'}, 'event'),
            ({**envelope(), 'username': 7}, 'bounded text'),
            ({**envelope(), 'password': 'x' * 1021}, 'bounded text'),
            ({**envelope(), 'valid': 1}, 'boolean'),
            ({**envelope(), 'method': 2}, 'unknown fields'),
        )
        for candidate, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(Socks5TransportError, pattern):
                    Socks5AuthObservation.parse(candidate)


class Socks5AdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_addon_overrides_policy_in_both_directions(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_socks5_transport_v12.json').read_text())
        source = '''events = []
def socks5_auth(data):
    before = data.valid
    data.valid = data.username == "override" and data.password == "allow"
    peername = data.client_conn.peername
    events.append({
        "client_host": None if peername is None else peername[0],
        "client_port_present": (
            peername is not None
            and isinstance(peername[1], int)
            and peername[1] > 0
        ),
        "username": data.username,
        "password": data.password,
        "valid_before": before,
        "valid_after": data.valid,
    })
'''
        generation = AddonGeneration(source, Socks5AddonEvents.HOOKS)
        await generation.start()
        adapter = Socks5AddonEvents(generation)
        client = Client(
            peername=('127.0.0.1', 41000),
            sockname=('127.0.0.1', 1080),
        )
        try:
            cases = (
                envelope('override', 'allow', False),
                envelope('alice', 'secret', True),
                envelope('\\xff', '\\xfe', False),
            )
            results = []
            for value in cases:
                decision, failures = await adapter.authenticate(client, value)
                self.assertEqual(failures, ())
                results.append(decision.valid)
            self.assertEqual(results, [True, False, False])
            self.assertEqual(generation.addon.module.events, corpus['hooks'])
        finally:
            await generation.close()

    async def test_client_identity_is_observed_but_only_valid_is_a_decision(self):
        source = '''seen = None
def socks5_auth(data):
    global seen
    seen = data.client_conn
    data.client_conn = object()
    data.username = "changed"
    data.password = "changed"
    data.valid = True
'''
        generation = AddonGeneration(source, Socks5AddonEvents.HOOKS)
        await generation.start()
        adapter = Socks5AddonEvents(generation)
        client = Client(peername=None, sockname=None)
        try:
            decision, failures = await adapter.authenticate(
                client, envelope(valid=False))
            self.assertEqual(failures, ())
            self.assertTrue(decision.valid)
            self.assertIs(generation.addon.module.seen, client)
        finally:
            await generation.close()

    async def test_non_boolean_result_and_non_native_client_fail_closed(self):
        source = 'def socks5_auth(data):\n    data.valid = 1\n'
        generation = AddonGeneration(source, Socks5AddonEvents.HOOKS)
        await generation.start()
        adapter = Socks5AddonEvents(generation)
        try:
            with self.assertRaisesRegex(
                    Socks5TransportError, 'native Client'):
                await adapter.authenticate(object(), envelope())
            with self.assertRaisesRegex(
                    Socks5TransportError, 'remain a boolean'):
                await adapter.authenticate(
                    Client(peername=None, sockname=None), envelope())
        finally:
            await generation.close()


if __name__ == '__main__':
    unittest.main()
