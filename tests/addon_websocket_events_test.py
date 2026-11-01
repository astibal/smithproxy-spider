"""Logical WebSocket lifecycle over the proposed producer envelope."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_connection import Client, Server
from addon_flow import HTTPFlow
from addon_runtime import AddonGeneration
from addon_websocket_events import (
    WebSocketAddonEvents,
    WebSocketObservation,
    WebSocketSetup,
    WebSocketTerminal,
    WebSocketTransportError,
)


def setup_envelope(identity='websocket-reference'):
    return {
        'version': 1,
        'connection_id': identity,
        'exchange_id': 1,
        'event': 'start',
        'subprotocol': None,
        'extensions': [],
    }


def message_envelope(identity, sequence, direction, opcode=1,
                     compressed_on_wire=False):
    return {
        'version': 1,
        'connection_id': identity,
        'event': 'message',
        'sequence': sequence,
        'direction': direction,
        'opcode': opcode,
        'compressed_on_wire': compressed_on_wire,
    }


def terminal_envelope(identity='websocket-reference'):
    return {
        'version': 1,
        'connection_id': identity,
        'event': 'end',
        'close_code': 1000,
        'close_reason': '',
        'closed_by_client': True,
        'transport_error': None,
    }


class WebSocketEnvelopeTests(unittest.TestCase):
    def test_setup_message_and_terminal_are_explicit(self):
        setup = WebSocketSetup.parse(setup_envelope())
        self.assertEqual(setup.connection_id, 'websocket-reference')
        self.assertEqual(setup.exchange_id, 1)
        self.assertIsNone(setup.subprotocol)
        self.assertEqual(setup.extensions, ())

        message = WebSocketObservation.parse(
            message_envelope(
                setup.connection_id, 7, 'server-to-client',
                opcode=2, compressed_on_wire=True,
            ),
            setup,
            None,
        )
        self.assertEqual(message.sequence, 7)
        self.assertFalse(message.from_client)
        self.assertEqual(int(message.opcode), 2)
        self.assertTrue(message.compressed_on_wire)

        terminal = WebSocketTerminal.parse(
            terminal_envelope(), setup)
        self.assertEqual(terminal.close_code, 1000)
        self.assertEqual(terminal.close_reason, '')
        self.assertTrue(terminal.closed_by_client)
        self.assertIsNone(terminal.transport_error)

    def test_malformed_envelopes_fail_closed(self):
        setup_cases = []
        wrong_version = setup_envelope()
        wrong_version['version'] = 2
        setup_cases.append((wrong_version, 'version'))
        boolean_exchange = setup_envelope()
        boolean_exchange['exchange_id'] = True
        setup_cases.append((boolean_exchange, 'positive integer'))
        unknown_field = setup_envelope()
        unknown_field['framing'] = 'raw'
        setup_cases.append((unknown_field, 'unknown fields'))
        bad_extensions = setup_envelope()
        bad_extensions['extensions'] = 'permessage-deflate'
        setup_cases.append((bad_extensions, 'bounded list'))

        for candidate, pattern in setup_cases:
            with self.subTest(setup=pattern):
                with self.assertRaisesRegex(WebSocketTransportError, pattern):
                    WebSocketSetup.parse(candidate)

        setup = WebSocketSetup.parse(setup_envelope())
        message_cases = []
        changed_identity = message_envelope(
            'different', 0, 'client-to-server')
        message_cases.append((changed_identity, 'identity changed'))
        sequence_gap = message_envelope(
            setup.connection_id, 3, 'client-to-server')
        message_cases.append((sequence_gap, 'not contiguous'))
        control_opcode = message_envelope(
            setup.connection_id, 2, 'client-to-server', opcode=9)
        message_cases.append((control_opcode, 'text or binary'))
        invalid_direction = message_envelope(
            setup.connection_id, 2, 'sideways')
        message_cases.append((invalid_direction, 'direction'))
        boolean_compression = message_envelope(
            setup.connection_id, 2, 'client-to-server')
        boolean_compression['compressed_on_wire'] = 1
        message_cases.append((boolean_compression, 'boolean'))

        for candidate, pattern in message_cases:
            with self.subTest(message=pattern):
                with self.assertRaisesRegex(WebSocketTransportError, pattern):
                    WebSocketObservation.parse(candidate, setup, 1)

        terminal_cases = []
        bad_code = terminal_envelope()
        bad_code['close_code'] = True
        terminal_cases.append((bad_code, 'unsigned 16-bit'))
        bad_owner = terminal_envelope()
        bad_owner['closed_by_client'] = 1
        terminal_cases.append((bad_owner, 'boolean or null'))
        control_reason = terminal_envelope()
        control_reason['close_reason'] = 'bad\nreason'
        terminal_cases.append((control_reason, 'bounded text'))

        for candidate, pattern in terminal_cases:
            with self.subTest(terminal=pattern):
                with self.assertRaisesRegex(WebSocketTransportError, pattern):
                    WebSocketTerminal.parse(candidate, setup)

    def test_every_envelope_field_is_bounded_and_typed(self):
        setup_cases = (
            ([], 'must be an object'),
            ({**setup_envelope(), 'event': 'message'}, 'event must be start'),
            ({**setup_envelope(), 'connection_id': 7}, 'bounded text'),
            ({**setup_envelope(), 'subprotocol': 7}, 'bounded text or null'),
            ({**setup_envelope(), 'subprotocol': 'x' * 1025}, 'bounded text'),
            ({**setup_envelope(), 'extensions': ['x' * 1025]}, 'bounded text'),
            ({**setup_envelope(), 'extensions': ['x'] * 65}, 'bounded list'),
        )
        for candidate, pattern in setup_cases:
            with self.subTest(setup=pattern):
                with self.assertRaisesRegex(WebSocketTransportError, pattern):
                    WebSocketSetup.parse(candidate)

        setup = WebSocketSetup.parse(setup_envelope())
        message_cases = (
            ({**message_envelope(
                setup.connection_id, 0, 'client-to-server'),
              'event': 'start'}, 'event must be message'),
            (message_envelope(
                setup.connection_id, True, 'client-to-server'),
             'non-negative integer'),
        )
        for candidate, pattern in message_cases:
            with self.subTest(message=pattern):
                with self.assertRaisesRegex(WebSocketTransportError, pattern):
                    WebSocketObservation.parse(candidate, setup, None)

        changed = terminal_envelope()
        changed['connection_id'] = 'different'
        with self.assertRaisesRegex(WebSocketTransportError, 'identity changed'):
            WebSocketTerminal.parse(changed, setup)

        terminal_cases = (
            ({**terminal_envelope(), 'event': 'start'}, 'event must be end'),
            ({**terminal_envelope(), 'transport_error': 7},
             'bounded text or null'),
            ({**terminal_envelope(), 'transport_error': 'x' * 1025},
             'bounded text'),
        )
        for candidate, pattern in terminal_cases:
            with self.subTest(terminal=pattern):
                with self.assertRaisesRegex(WebSocketTransportError, pattern):
                    WebSocketTerminal.parse(candidate, setup)


class WebSocketAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        source = '''events = []
def record(hook, flow, message=None, before=None):
    events.append({
        "hook": hook,
        "message_count": len(flow.websocket.messages),
        "from_client": None if message is None else message.from_client,
        "before": before,
        "after": None if message is None else message.content.decode(),
        "dropped": None if message is None else message.dropped,
        "injected": None if message is None else message.injected,
    })
def websocket_start(flow):
    record("websocket_start", flow)
def websocket_message(flow):
    message = flow.websocket.messages[-1]
    before = message.content.decode()
    if message.from_client:
        message.content = message.content.upper()
    else:
        message.content = b"client:" + message.content
    record("websocket_message", flow, message, before)
def websocket_end(flow):
    record("websocket_end", flow)
'''
        self.generation = AddonGeneration(
            source, WebSocketAddonEvents.HOOKS)
        await self.generation.start()
        self.adapter = WebSocketAddonEvents(self.generation)
        self.flow = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        self.setup = WebSocketSetup.parse(setup_envelope())

    async def asyncTearDown(self):
        await self.generation.close()

    async def test_lifecycle_matches_reference_wire_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_websocket_transport_v12.json').read_text())
        await self.adapter.start(self.setup, self.flow)

        client_decision, client_failures = await self.adapter.message(
            message_envelope(
                self.setup.connection_id, 0, 'client-to-server'),
            b'hello',
        )
        server_decision, server_failures = await self.adapter.message(
            message_envelope(
                self.setup.connection_id, 1, 'server-to-client'),
            b'reply',
        )
        end_failures = await self.adapter.stop(terminal_envelope())

        self.assertEqual(client_decision.action, 'replace')
        self.assertEqual(client_decision.content, b'HELLO')
        self.assertEqual(server_decision.action, 'replace')
        self.assertEqual(server_decision.content, b'client:reply')
        self.assertEqual(client_failures, ())
        self.assertEqual(server_failures, ())
        self.assertEqual(end_failures, ())
        self.assertEqual(self.generation.addon.module.events, corpus['hooks'])
        self.assertFalse(self.flow.live)
        self.assertEqual(self.flow.websocket.close_code, 1000)
        self.assertTrue(self.flow.websocket.closed_by_client)

    async def test_pass_drop_binary_and_empty_replacement_are_distinct(self):
        source = '''def websocket_message(flow):
    message = flow.websocket.messages[-1]
    if message.content == b"drop":
        message.drop()
    elif message.content == b"empty":
        message.content = b""
    elif message.content == b"binary":
        message.type = 2
'''
        generation = AddonGeneration(source, WebSocketAddonEvents.HOOKS)
        await generation.start()
        adapter = WebSocketAddonEvents(generation)
        flow = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        setup = WebSocketSetup.parse(setup_envelope('decisions'))
        try:
            await adapter.start(setup, flow)
            expected = (
                (b'pass', 'pass', None, None),
                (b'drop', 'drop', None, None),
                (b'empty', 'replace', 1, b''),
                (b'binary', 'replace', 2, b'binary'),
            )
            for sequence, (content, action, opcode, result) in enumerate(expected):
                decision, failures = await adapter.message(
                    message_envelope(
                        setup.connection_id, sequence, 'client-to-server'),
                    content,
                )
                self.assertEqual(failures, ())
                self.assertEqual(decision.action, action)
                self.assertEqual(decision.opcode, opcode)
                self.assertEqual(decision.content, result)
        finally:
            adapter.release_connection(setup.connection_id)
            await generation.close()

    async def test_two_flows_share_generation_state_but_not_histories(self):
        source = '''ordinal = 0
def websocket_message(flow):
    global ordinal
    ordinal += 1
    message = flow.websocket.messages[-1]
    message.content = str(ordinal).encode() + b":" + message.content
'''
        generation = AddonGeneration(source, WebSocketAddonEvents.HOOKS)
        await generation.start()
        adapter = WebSocketAddonEvents(generation)
        first = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        second = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        first_setup = WebSocketSetup.parse(setup_envelope('shared-first'))
        second_setup = WebSocketSetup.parse(setup_envelope('shared-second'))
        try:
            await adapter.start(first_setup, first)
            await adapter.start(second_setup, second)
            operations = (
                (first_setup, b'one-a'),
                (second_setup, b'two-a'),
                (first_setup, b'one-b'),
                (second_setup, b'two-b'),
            )
            observed = []
            for setup, content in operations:
                flow = first if setup is first_setup else second
                sequence = len(flow.websocket.messages)
                decision, failures = await adapter.message(
                    message_envelope(
                        setup.connection_id,
                        sequence,
                        'client-to-server',
                    ),
                    content,
                )
                self.assertEqual(failures, ())
                observed.append(decision.content)

            self.assertEqual(
                observed,
                [b'1:one-a', b'2:two-a', b'3:one-b', b'4:two-b'],
            )
            self.assertEqual(
                [message.content for message in first.websocket.messages],
                [b'1:one-a', b'3:one-b'],
            )
            self.assertEqual(
                [message.content for message in second.websocket.messages],
                [b'2:two-a', b'4:two-b'],
            )
        finally:
            adapter.release_connection(first_setup.connection_id)
            adapter.release_connection(second_setup.connection_id)
            await generation.close()

    async def test_kill_is_state_only_for_message_decisions_and_end(self):
        source = '''observed = []
def websocket_start(flow):
    flow.kill()
    observed.append(("start", flow.live, str(flow.error)))
def websocket_message(flow):
    observed.append(("message", flow.live, str(flow.error)))
def websocket_end(flow):
    observed.append(("end", flow.live, str(flow.error)))
'''
        generation = AddonGeneration(source, WebSocketAddonEvents.HOOKS)
        await generation.start()
        adapter = WebSocketAddonEvents(generation)
        flow = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        setup = WebSocketSetup.parse(setup_envelope('state-only-kill'))
        try:
            self.assertEqual(await adapter.start(setup, flow), ())
            decision, failures = await adapter.message(
                message_envelope(
                    setup.connection_id, 0, 'client-to-server'),
                b'continues',
            )
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'pass')
            self.assertEqual(
                await adapter.stop(
                    terminal_envelope('state-only-kill')),
                (),
            )
            self.assertEqual(generation.addon.module.observed, [
                ('start', False, 'Connection killed.'),
                ('message', False, 'Connection killed.'),
                ('end', False, 'Connection killed.'),
            ])
        finally:
            await generation.close()

    async def test_history_replacement_invalid_text_and_injection_fail_closed(self):
        sources = (
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages = []\n',
                'replace the message history',
            ),
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages[-1].content = b"\\xff"\n',
                'valid UTF-8',
            ),
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages[-1].injected = True\n',
                'cannot become injected',
            ),
        )
        for index, (source, pattern) in enumerate(sources):
            with self.subTest(pattern=pattern):
                generation = AddonGeneration(
                    source, WebSocketAddonEvents.HOOKS)
                await generation.start()
                adapter = WebSocketAddonEvents(generation)
                identity = 'invalid-' + str(index)
                flow = HTTPFlow(
                    Client(peername=None, sockname=None),
                    Server(address=None),
                    live=True,
                )
                setup = WebSocketSetup.parse(setup_envelope(identity))
                try:
                    await adapter.start(setup, flow)
                    with self.assertRaisesRegex(
                            WebSocketTransportError, pattern):
                        await adapter.message(
                            message_envelope(
                                identity, 0, 'client-to-server'),
                            b'hello',
                        )
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

    async def test_sequence_and_terminal_identity_are_enforced(self):
        await self.adapter.start(self.setup, self.flow)
        await self.adapter.message(
            message_envelope(
                self.setup.connection_id, 0, 'client-to-server'),
            b'hello',
        )
        with self.assertRaisesRegex(WebSocketTransportError, 'not contiguous'):
            await self.adapter.message(
                message_envelope(
                    self.setup.connection_id, 2, 'server-to-client'),
                b'reply',
            )
        changed = terminal_envelope()
        changed['connection_id'] = 'different'
        with self.assertRaisesRegex(
                WebSocketTransportError, 'without setup'):
            await self.adapter.stop(changed)

        failures = await self.adapter.abort(
            self.setup.connection_id, 'producer disconnected')
        self.assertEqual(failures, ())
        self.assertFalse(self.flow.live)
        self.assertEqual(str(self.flow.error), 'producer disconnected')

    async def test_start_guards_flow_and_transport_state_identity(self):
        await self.adapter.start(self.setup, self.flow)
        with self.assertRaisesRegex(
                WebSocketTransportError, 'already active'):
            await self.adapter.start(self.setup, self.flow)
        self.adapter.release_connection(self.setup.connection_id)

        inactive = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=False,
        )
        with self.assertRaisesRegex(WebSocketTransportError, 'live upgraded'):
            await self.adapter.start(self.setup, inactive)

        occupied = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        occupied.websocket = object()
        with self.assertRaisesRegex(WebSocketTransportError, 'already owns'):
            await self.adapter.start(self.setup, occupied)

        source = '''def websocket_start(flow):
    flow.websocket = None
'''
        generation = AddonGeneration(source, WebSocketAddonEvents.HOOKS)
        await generation.start()
        adapter = WebSocketAddonEvents(generation)
        flow = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        setup = WebSocketSetup.parse(setup_envelope('replace-state'))
        try:
            with self.assertRaisesRegex(
                    WebSocketTransportError, 'must not replace'):
                await adapter.start(setup, flow)
            self.assertIsNone(flow.websocket)
        finally:
            await generation.close()

    async def test_content_and_terminal_events_require_active_setup(self):
        with self.assertRaisesRegex(WebSocketTransportError, 'must be bytes'):
            await self.adapter.message(
                message_envelope(
                    self.setup.connection_id, 0, 'client-to-server'),
                'text',
            )
        with self.assertRaisesRegex(WebSocketTransportError, 'without setup'):
            await self.adapter.message(
                message_envelope(
                    self.setup.connection_id, 0, 'client-to-server'),
                b'text',
            )
        with self.assertRaisesRegex(WebSocketTransportError, 'without setup'):
            await self.adapter.stop(terminal_envelope())
        self.assertEqual(await self.adapter.abort('missing', 'gone'), ())

    async def test_transport_error_is_retained_before_end_hook(self):
        await self.adapter.start(self.setup, self.flow)
        terminal = terminal_envelope()
        terminal['close_code'] = None
        terminal['close_reason'] = None
        terminal['closed_by_client'] = None
        terminal['transport_error'] = 'connection reset'
        failures = await self.adapter.stop(terminal)
        self.assertEqual(failures, ())
        self.assertEqual(str(self.flow.error), 'connection reset')
        self.assertIsNone(self.flow.websocket.close_code)
        self.assertIsNone(self.flow.websocket.closed_by_client)

    async def test_clean_end_hook_observes_live_flow_before_retirement(self):
        source = '''observed = []
def websocket_end(flow):
    observed.append((flow.live, flow.websocket.close_code))
'''
        generation = AddonGeneration(source, WebSocketAddonEvents.HOOKS)
        await generation.start()
        adapter = WebSocketAddonEvents(generation)
        flow = HTTPFlow(
            Client(peername=None, sockname=None),
            Server(address=None),
            live=True,
        )
        setup = WebSocketSetup.parse(setup_envelope('end-liveness'))
        try:
            await adapter.start(setup, flow)
            failures = await adapter.stop(
                terminal_envelope('end-liveness'))
            self.assertEqual(failures, ())
            self.assertEqual(generation.addon.module.observed, [(True, 1000)])
            self.assertFalse(flow.live)
        finally:
            await generation.close()

    async def test_history_and_generation_limits_fail_before_publication(self):
        cases = (
            ('MAX_MESSAGES', 0, 'message history limit'),
            ('MAX_GENERATION_MESSAGES', 0, 'generation message limit'),
            ('MAX_HISTORY_BYTES', 0, 'history exceeds'),
            ('MAX_GENERATION_HISTORY_BYTES', 0, 'generation history limit'),
        )
        for index, (attribute, value, pattern) in enumerate(cases):
            with self.subTest(limit=attribute):
                source = 'def websocket_message(flow):\n    pass\n'
                generation = AddonGeneration(
                    source, WebSocketAddonEvents.HOOKS)
                await generation.start()
                adapter = WebSocketAddonEvents(generation)
                setattr(adapter, attribute, value)
                identity = 'limit-' + str(index)
                flow = HTTPFlow(
                    Client(peername=None, sockname=None),
                    Server(address=None),
                    live=True,
                )
                setup = WebSocketSetup.parse(setup_envelope(identity))
                try:
                    await adapter.start(setup, flow)
                    with self.assertRaisesRegex(
                            WebSocketTransportError, pattern):
                        await adapter.message(
                            message_envelope(
                                identity, 0, 'client-to-server'),
                            b'x',
                        )
                    self.assertEqual(flow.websocket.messages, [])
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

    async def test_mutation_limits_and_types_are_checked_after_callback(self):
        cases = (
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages[-1].content = b"expanded"\n',
                'MAX_HISTORY_BYTES',
                4,
                'history exceeds',
            ),
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages[-1].content = b"expanded"\n',
                'MAX_GENERATION_HISTORY_BYTES',
                4,
                'generation history limit',
            ),
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages[-1].content = "text"\n',
                None,
                None,
                'must remain bytes',
            ),
            (
                'def websocket_message(flow):\n'
                '    flow.websocket.messages[-1].type = 9\n',
                None,
                None,
                'must remain text or binary',
            ),
        )
        for index, (source, attribute, value, pattern) in enumerate(cases):
            with self.subTest(pattern=pattern):
                generation = AddonGeneration(
                    source, WebSocketAddonEvents.HOOKS)
                await generation.start()
                adapter = WebSocketAddonEvents(generation)
                if attribute is not None:
                    setattr(adapter, attribute, value)
                identity = 'mutation-' + str(index)
                flow = HTTPFlow(
                    Client(peername=None, sockname=None),
                    Server(address=None),
                    live=True,
                )
                setup = WebSocketSetup.parse(setup_envelope(identity))
                try:
                    await adapter.start(setup, flow)
                    with self.assertRaisesRegex(
                            WebSocketTransportError, pattern):
                        await adapter.message(
                            message_envelope(
                                identity, 0, 'client-to-server'),
                            b'x',
                        )
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

    async def test_generation_count_defense_rejects_inconsistent_accounting(self):
        await self.adapter.start(self.setup, self.flow)
        self.flow.websocket.messages.append(object())
        self.adapter._generation_message_count = 1
        self.adapter._history_counts[self.setup.connection_id] = 0
        self.adapter.MAX_GENERATION_MESSAGES = 1
        with self.assertRaisesRegex(
                WebSocketTransportError, 'generation message limit'):
            self.adapter._commit_accounting(
                self.setup.connection_id, self.flow, 0)

    async def test_corrupt_existing_history_is_rejected(self):
        await self.adapter.start(self.setup, self.flow)
        self.flow.websocket.messages.append(
            type('Message', (), {'content': 'not-bytes'})())
        with self.assertRaisesRegex(WebSocketTransportError, 'must remain bytes'):
            self.adapter._measure_history(self.flow)


if __name__ == '__main__':
    unittest.main()
