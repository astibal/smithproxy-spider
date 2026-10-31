"""Raw TCP/UDP addon lifecycle over an explicit producer envelope."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_native import NativeAddonAdapter
from addon_raw_events import (
    RawTransportContent,
    RawTransportError,
    RawTransportSetup,
    RawTransportTerminal,
)
from addon_runtime import AddonGeneration
from inspection_api import Connection, Http2, Message, RewritePart


HTTP2 = Http2(False, (), ())


def envelope(kind='tcp'):
    return {
        'version': 1,
        'kind': kind,
        'delivery': 'raw',
        'client': {
            'peername': ['192.0.2.10', 41000],
            'sockname': ['192.0.2.20', 443],
        },
        'server': {
            'address': ['198.51.100.30', 443],
            'peername': ['198.51.100.30', 443],
            'sockname': ['192.0.2.20', 52000],
        },
    }


def setup_api(identity, metadata):
    return SimpleNamespace(
        phase='setup',
        session_id=identity,
        info={'raw_transport': metadata},
        instance=SimpleNamespace(mode='flow'),
        connection=Connection(phase='setup', instance_mode='flow'),
    )


def content_envelope(setup, direction, sequence):
    value = deepcopy(setup)
    value.update({
        'direction': direction,
        'sequence': sequence,
        'unit': 'stream-chunk' if setup['kind'] == 'tcp' else 'datagram',
    })
    return value


def terminal_envelope(setup, state='closed', message=''):
    value = deepcopy(setup)
    value['terminal'] = {'state': state, 'message': message}
    return value


def content_api(identity, side, payload, metadata):
    message = Message(payload, len(payload), {})
    return SimpleNamespace(
        phase='content',
        session_id=identity,
        side=side,
        info={'raw_transport': metadata},
        message=message,
        http2=HTTP2,
        print=lambda *values: None,
        connection=Connection(message, instance_mode='flow'),
    )


class RawEnvelopeTests(unittest.TestCase):
    def test_setup_and_content_preserve_explicit_transport_identity(self):
        raw = envelope('udp')
        setup = RawTransportSetup.parse(raw)
        self.assertEqual(setup.kind, 'udp')
        self.assertEqual(setup.client.peername, ('192.0.2.10', 41000))
        self.assertEqual(setup.server.address, ('198.51.100.30', 443))
        self.assertEqual(setup.server.transport_protocol, 'udp')

        content = content_envelope(raw, 'client-to-server', 7)
        observed = RawTransportContent.parse(content, setup, 'L', None)
        self.assertTrue(observed.from_client)
        self.assertEqual(observed.sequence, 7)

    def test_malformed_or_changed_envelope_fails_closed(self):
        cases = (
            ('version', 2, 'version'),
            ('version', True, 'version'),
            ('kind', 'quic', 'kind'),
            ('delivery', 'decoded', 'delivery'),
        )
        for field, value, pattern in cases:
            with self.subTest(field=field, value=value):
                candidate = envelope()
                candidate[field] = value
                with self.assertRaisesRegex(RawTransportError, pattern):
                    RawTransportSetup.parse(candidate)

        raw = envelope()
        setup = RawTransportSetup.parse(raw)
        gap = content_envelope(raw, 'server-to-client', 9)
        with self.assertRaisesRegex(RawTransportError, 'contiguous'):
            RawTransportContent.parse(gap, setup, 'R', 7)
        wrong_side = content_envelope(raw, 'client-to-server', 8)
        with self.assertRaisesRegex(RawTransportError, 'callback side'):
            RawTransportContent.parse(wrong_side, setup, 'R', 7)
        changed = content_envelope(raw, 'client-to-server', 8)
        changed['server']['address'][1] = 8443
        with self.assertRaisesRegex(RawTransportError, 'identity changed'):
            RawTransportContent.parse(changed, setup, 'L', 7)

    def test_endpoint_schema_is_exact_bounded_and_allows_unknown_observations(self):
        nullable = envelope()
        nullable['client']['sockname'] = None
        nullable['server']['address'] = None
        nullable['server']['peername'] = None
        setup = RawTransportSetup.parse(nullable)
        self.assertIsNone(setup.client.sockname)
        self.assertIsNone(setup.server.address)
        self.assertIsNone(setup.server.peername)

        cases = []
        unknown = envelope()
        unknown['client']['tls'] = True
        cases.append((unknown, 'unknown fields'))
        bad_host = envelope()
        bad_host['server']['address'][0] = 'bad\r\nhost'
        cases.append((bad_host, 'bounded text'))
        bool_port = envelope()
        bool_port['client']['peername'][1] = True
        cases.append((bool_port, 'integer'))
        large_port = envelope()
        large_port['server']['sockname'][1] = 65536
        cases.append((large_port, 'integer'))
        long_host = envelope()
        long_host['server']['address'][0] = 'x' * 1025
        cases.append((long_host, 'bounded text'))

        for candidate, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(RawTransportError, pattern):
                    RawTransportSetup.parse(candidate)

    def test_content_and_terminal_envelopes_reject_every_ambiguous_shape(self):
        raw = envelope('udp')
        setup = RawTransportSetup.parse(raw)

        setup_cases = []
        not_an_object = deepcopy(raw)
        not_an_object['client'] = []
        setup_cases.append((not_an_object, 'must be an object'))
        bad_address = deepcopy(raw)
        bad_address['client']['peername'] = ['client-only']
        setup_cases.append((bad_address, 'null or'))
        for candidate, pattern in setup_cases:
            with self.subTest(setup=pattern):
                with self.assertRaisesRegex(RawTransportError, pattern):
                    RawTransportSetup.parse(candidate)

        content_cases = []
        bad_direction = content_envelope(raw, 'sideways', 0)
        content_cases.append((bad_direction, 'direction is invalid'))
        bad_unit = content_envelope(raw, 'client-to-server', 0)
        bad_unit['unit'] = 'stream-chunk'
        content_cases.append((bad_unit, 'unit does not match'))
        bad_sequence = content_envelope(raw, 'client-to-server', True)
        content_cases.append((bad_sequence, 'non-negative integer'))
        for candidate, pattern in content_cases:
            with self.subTest(content=pattern):
                with self.assertRaisesRegex(RawTransportError, pattern):
                    RawTransportContent.parse(candidate, setup, 'L', None)

        terminal_cases = []
        changed_identity = terminal_envelope(raw)
        changed_identity['server']['address'][1] = 8443
        terminal_cases.append((changed_identity, 'identity changed'))
        non_text_message = terminal_envelope(raw)
        non_text_message['terminal']['message'] = None
        terminal_cases.append((non_text_message, 'bounded text'))
        long_message = terminal_envelope(raw)
        long_message['terminal']['message'] = 'x' * 1025
        terminal_cases.append((long_message, 'bounded text'))
        control_message = terminal_envelope(raw, 'error', 'bad\nmessage')
        terminal_cases.append((control_message, 'control character'))
        for candidate, pattern in terminal_cases:
            with self.subTest(terminal=pattern):
                with self.assertRaisesRegex(RawTransportError, pattern):
                    RawTransportTerminal.parse(candidate, setup)


class RawAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_and_udp_lifecycle_matches_reference_wire_corpora(self):
        for kind in ('tcp', 'udp'):
            with self.subTest(kind=kind):
                corpus = json.loads(
                    (ROOT / 'tests/corpus' / f'addon_{kind}_v12.json').read_text())
                source = f'''events = []
def record(hook, flow, message=None, before=None):
    events.append({{
        "hook": hook,
        "message_count": len(flow.messages),
        "from_client": None if message is None else message.from_client,
        "before": before,
        "after": None if message is None else message.content.decode(),
        "error": None if flow.error is None else str(flow.error),
    }})
def {kind}_start(flow):
    record("{kind}_start", flow)
def {kind}_message(flow):
    message = flow.messages[-1]
    before = message.content.decode()
    if message.from_client:
        message.content = message.content.upper()
    else:
        message.content = b"client:" + message.content
    record("{kind}_message", flow, message, before)
def {kind}_end(flow):
    record("{kind}_end", flow)
'''
                addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                raw = envelope(kind)
                try:
                    self.assertEqual(
                        await adapter.setup(
                            setup_api('reference-' + kind, raw), None, None), ())
                    client = content_api(
                        'reference-' + kind,
                        'L',
                        b'hello',
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    server = content_api(
                        'reference-' + kind,
                        'R',
                        b'echo:HELLO',
                        content_envelope(raw, 'server-to-client', 1),
                    )
                    client_result = await adapter.content(client)
                    server_result = await adapter.content(server)
                    await adapter.stop(
                        'reference-' + kind,
                        {'raw_transport': terminal_envelope(raw)},
                    )

                    self.assertEqual(
                        client_result.decode(), corpus['origin']['received'])
                    self.assertEqual(
                        server_result.decode(), corpus['client_received'])
                    self.assertEqual(addon.addon.module.events, corpus['hooks'])
                finally:
                    await adapter.close()

    async def test_tcp_output_order_is_stable_across_fragmentation_patterns(self):
        source = '''def tcp_message(flow):
    flow.messages[-1].content = flow.messages[-1].content.swapcase()
'''
        payload = b'AbCdEfGhIjKlMnOp'
        patterns = (
            (payload,),
            tuple(payload[index:index + 1] for index in range(len(payload))),
            (payload[:3], payload[3:11], payload[11:]),
        )
        outputs = []
        hook_counts = []
        for pattern_index, chunks in enumerate(patterns):
            addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
            await addon.start()
            adapter = NativeAddonAdapter(
                addon, opaque_part_factory=RewritePart)
            raw = envelope('tcp')
            identity = 'fragment-' + str(pattern_index)
            try:
                await adapter.setup(setup_api(identity, raw), None, None)
                output = bytearray()
                for sequence, chunk in enumerate(chunks):
                    api = content_api(
                        identity,
                        'L',
                        chunk,
                        content_envelope(
                            raw, 'client-to-server', sequence),
                    )
                    output.extend(await adapter.content(api))
                flow = adapter.raw._flows[identity]
                hook_counts.append(len(flow.messages))
                outputs.append(bytes(output))
                await adapter.stop(
                    identity, {'raw_transport': terminal_envelope(raw)})
            finally:
                await adapter.close()

        self.assertEqual(outputs, [payload.swapcase()] * len(patterns))
        self.assertEqual(hook_counts, [1, len(payload), 3])

    async def test_tcp_bidirectional_mutation_and_clean_lifecycle(self):
        source = '''events = []
def tcp_start(flow):
    events.append(["start", flow.client_conn.peername, flow.server_conn.address])
def tcp_message(flow):
    message = flow.messages[-1]
    events.append(["message", message.from_client, message.content, len(flow.messages)])
    prefix = b"client:" if message.from_client else b"server:"
    message.content = prefix + message.content.upper()
def tcp_end(flow):
    events.append(["end", flow.live, len(flow.messages)])
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        try:
            start = adapter.setup(setup_api('tcp-1', raw), None, None)
            self.assertEqual(await start, ())
            client = content_api(
                'tcp-1', 'L', b'hello',
                content_envelope(raw, 'client-to-server', 20))
            server = content_api(
                'tcp-1', 'R', b'world',
                content_envelope(raw, 'server-to-client', 21))
            self.assertEqual(await adapter.content(client), b'client:HELLO')
            self.assertEqual(await adapter.content(server), b'server:WORLD')
            self.assertEqual(await adapter.stop(
                'tcp-1', {'raw_transport': terminal_envelope(raw)}), ())
            self.assertEqual(addon.addon.module.events, [
                ['start', ('192.0.2.10', 41000), ('198.51.100.30', 443)],
                ['message', True, b'hello', 1],
                ['message', False, b'world', 2],
                ['end', False, 2],
            ])
            self.assertEqual(addon.active_flows, 0)
        finally:
            await adapter.close()

    async def test_raw_client_lifecycle_wraps_protocol_hooks_with_one_identity(self):
        source = '''events = []
clients = []
def client_connected(client):
    clients.append(client)
    events.append(("client_connected", client.connected,
                   client.timestamp_end is None))
def tcp_start(flow):
    clients.append(flow.client_conn)
    events.append(("tcp_start", flow.client_conn.connected))
def tcp_end(flow):
    clients.append(flow.client_conn)
    events.append(("tcp_end", flow.client_conn.connected,
                   flow.client_conn.timestamp_end is not None))
def client_disconnected(client):
    clients.append(client)
    events.append(("client_disconnected", client.connected,
                   client.timestamp_end is not None))
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        try:
            self.assertEqual(
                await adapter.setup(setup_api('raw-lifecycle', raw), None, None),
                (),
            )
            self.assertEqual(await adapter.stop(
                'raw-lifecycle',
                {'raw_transport': terminal_envelope(raw)},
            ), ())
            self.assertEqual(await adapter.stop('raw-lifecycle'), ())

            module = addon.addon.module
            self.assertEqual(module.events, [
                ('client_connected', True, True),
                ('tcp_start', True),
                ('tcp_end', False, True),
                ('client_disconnected', False, True),
            ])
            self.assertEqual(len(module.clients), 4)
            self.assertTrue(all(client is module.clients[0]
                                for client in module.clients))
        finally:
            await adapter.close()

    async def test_raw_message_hook_failure_is_logged_after_publication(self):
        source = '''def tcp_message(flow):
    flow.messages[-1].content = b"published"
    raise ValueError("visible raw failure")
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        try:
            await adapter.setup(setup_api('raw-failure', raw), None, None)
            api = content_api(
                'raw-failure',
                'L',
                b'original',
                content_envelope(raw, 'client-to-server', 0),
            )
            logs = []
            api.print = logs.append
            self.assertEqual(await adapter.content(api), b'published')
            self.assertEqual(logs, [
                'Addon module tcp_message: ValueError: visible raw failure',
            ])
            self.assertEqual(addon.state, 'running')
        finally:
            await adapter.close()

    async def test_udp_preserves_empty_datagrams_and_terminal_error(self):
        source = '''events = []
def udp_start(flow):
    events.append("start")
def udp_message(flow):
    message = flow.messages[-1]
    events.append(["message", message.from_client, message.content])
    if message.content == b"":
        message.content = b"empty"
    elif message.content == b"drop-to-empty":
        message.content = b""
    else:
        message.content += b"!"
def udp_error(flow):
    events.append(["error", str(flow.error), len(flow.messages)])
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('udp')
        try:
            self.assertEqual(
                await adapter.setup(setup_api('udp-1', raw), None, None), ())
            cases = (
                ('L', b'', 'client-to-server', 1, b'empty'),
                ('R', b'drop-to-empty', 'server-to-client', 2, b''),
                ('L', b'last', 'client-to-server', 3, b'last!'),
            )
            for side, payload, direction, sequence, expected in cases:
                api = content_api(
                    'udp-1', side, payload,
                    content_envelope(raw, direction, sequence))
                self.assertEqual(await adapter.content(api), expected)

            failures = await adapter.stop(
                'udp-1', {'raw_transport': terminal_envelope(
                    raw, 'error', 'connection reset by peer')})
            self.assertEqual(failures, ())
            self.assertEqual(addon.addon.module.events, [
                'start',
                ['message', True, b''],
                ['message', False, b'drop-to-empty'],
                ['message', True, b'last'],
                ['error', 'connection reset by peer', 3],
            ])
        finally:
            await adapter.close()

    async def test_two_connections_share_script_state_not_message_history(self):
        source = '''counter = 0
events = []
def tcp_start(flow):
    events.append(["start", len(flow.messages)])
def tcp_message(flow):
    global counter
    counter += 1
    flow.messages[-1].content = str(counter).encode()
    events.append(["message", counter, len(flow.messages)])
def tcp_end(flow):
    events.append(["end", len(flow.messages)])
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        try:
            for identity in ('one', 'two'):
                self.assertEqual(
                    await adapter.setup(setup_api(identity, raw), None, None), ())
            observations = (
                ('one', 10, b'1'), ('two', 10, b'2'), ('one', 11, b'3'))
            for identity, sequence, expected in observations:
                api = content_api(
                    identity, 'L', b'x',
                    content_envelope(raw, 'client-to-server', sequence))
                self.assertEqual(await adapter.content(api), expected)
            for identity in ('one', 'two'):
                await adapter.stop(
                    identity, {'raw_transport': terminal_envelope(raw)})
            self.assertEqual(addon.addon.module.events, [
                ['start', 0], ['start', 0],
                ['message', 1, 1], ['message', 2, 1], ['message', 3, 2],
                ['end', 2], ['end', 1],
            ])
        finally:
            await adapter.close()

    async def test_malformed_content_invalidates_without_publication(self):
        source = '''events = []
def tcp_start(flow):
    events.append("start")
def tcp_message(flow):
    events.append("message")
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        try:
            self.assertEqual(
                await adapter.setup(setup_api('bad', raw), None, None), ())
            invalid = content_envelope(raw, 'server-to-client', 1)
            api = content_api('bad', 'L', b'original', invalid)
            with self.assertRaisesRegex(RawTransportError, 'callback side'):
                await adapter.content(api)
            self.assertEqual(addon.addon.module.events, ['start'])
            self.assertEqual(addon.state, 'failed')
        finally:
            await adapter.close()

    async def test_unsupported_transport_decisions_fail_closed(self):
        cases = {
            'kill': 'flow.kill()',
            'intercept': 'flow.intercept()',
        }
        for name, action in cases.items():
            with self.subTest(action=name):
                source = f'''def tcp_message(flow):
    {action}
'''
                addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                raw = envelope('tcp')
                identity = 'decision-' + name
                try:
                    self.assertEqual(
                        await adapter.setup(setup_api(identity, raw), None, None), ())
                    api = content_api(
                        identity,
                        'L',
                        b'original',
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    with self.assertRaisesRegex(
                            RawTransportError, 'producer control support'):
                        await adapter.content(api)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    await adapter.close()

    async def test_message_history_cannot_be_replaced_or_grown_without_bound(self):
        cases = {
            'replace': 'flow.messages = []',
            'oversize': 'flow.messages[-1].content = b"x" * (16 * 1024 * 1024 + 1)',
        }
        patterns = {
            'replace': 'message history',
            'oversize': 'exceeds 16 MiB',
        }
        for name, action in cases.items():
            with self.subTest(action=name):
                source = f'''def udp_message(flow):
    {action}
'''
                addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                raw = envelope('udp')
                identity = 'history-' + name
                try:
                    self.assertEqual(
                        await adapter.setup(setup_api(identity, raw), None, None), ())
                    api = content_api(
                        identity,
                        'L',
                        b'original',
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    with self.assertRaisesRegex(RawTransportError, patterns[name]):
                        await adapter.content(api)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    await adapter.close()

    async def test_malformed_terminal_invalidates_and_releases_the_flow(self):
        addon = AddonGeneration('', NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        try:
            self.assertEqual(
                await adapter.setup(setup_api('terminal', raw), None, None), ())
            terminal = terminal_envelope(raw)
            terminal['terminal']['state'] = 'half-closed'
            with self.assertRaisesRegex(RawTransportError, 'terminal state'):
                await adapter.stop('terminal', {'raw_transport': terminal})
            self.assertEqual(addon.state, 'failed')
            self.assertEqual(addon.active_flows, 0)
            self.assertEqual(adapter.active_connections, 0)
        finally:
            await adapter.close()

    async def test_close_aborts_each_active_flow_once_before_generation_done(self):
        source = '''events = []
def udp_error(flow):
    events.append([str(flow.error), flow.live, len(flow.messages)])
def done():
    events.append("done")
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('udp')
        for identity in ('retire-one', 'retire-two'):
            self.assertEqual(
                await adapter.setup(setup_api(identity, raw), None, None), ())

        self.assertEqual(await adapter.close(), ())
        self.assertEqual(addon.addon.module.events, [
            ['Raw transport closed without a terminal observation', False, 0],
            ['Raw transport closed without a terminal observation', False, 0],
            'done',
        ])
        self.assertEqual(addon.active_flows, 0)
        self.assertEqual(adapter.active_connections, 0)

    async def test_http_and_raw_connections_cannot_change_classification(self):
        cases = ('http-to-raw', 'raw-to-http')
        for name in cases:
            with self.subTest(case=name):
                addon = AddonGeneration('', NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                raw = envelope('tcp')
                try:
                    if name == 'http-to-raw':
                        setup = setup_api(name, raw)
                        setup.info = {}
                        self.assertIsNone(adapter.setup(setup, None, None))
                        api = content_api(
                            name, 'L', b'original',
                            content_envelope(raw, 'client-to-server', 0))
                        pattern = 'cannot change into a raw transport'
                    else:
                        self.assertEqual(
                            await adapter.setup(setup_api(name, raw), None, None), ())
                        api = content_api(
                            name, 'L', b'original',
                            content_envelope(raw, 'client-to-server', 0))
                        api.info = {}
                        pattern = 'missing raw_transport metadata'

                    with self.assertRaisesRegex(RawTransportError, pattern):
                        await adapter.content(api)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    await adapter.close()

    async def test_generation_aggregate_quotas_span_all_raw_connections(self):
        cases = (
            ('bytes', 5, 100, b'abc', b'def', 'generation history limit'),
            ('messages', 100, 1, b'a', b'b', 'generation message limit'),
        )
        for name, byte_limit, message_limit, first, second, pattern in cases:
            with self.subTest(quota=name):
                addon = AddonGeneration('', NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                adapter.raw.MAX_GENERATION_HISTORY_BYTES = byte_limit
                adapter.raw.MAX_GENERATION_MESSAGES = message_limit
                raw = envelope('tcp')
                try:
                    for identity in ('quota-one', 'quota-two'):
                        await adapter.setup(setup_api(identity, raw), None, None)
                    first_api = content_api(
                        'quota-one',
                        'L',
                        first,
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    self.assertEqual(await adapter.content(first_api), first)
                    second_api = content_api(
                        'quota-two',
                        'L',
                        second,
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    with self.assertRaisesRegex(RawTransportError, pattern):
                        await adapter.content(second_api)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    await adapter.close()
                self.assertEqual(adapter.raw._generation_history_bytes, 0)
                self.assertEqual(adapter.raw._generation_message_count, 0)

    async def test_raw_prepublication_guards_cover_native_shape_and_limits(self):
        cases = (
            ('empty-tcp', 'tcp', b'', None, 'must not be empty'),
            ('message-limit', 'tcp', b'x', 'message-limit', 'history limit'),
            ('byte-limit', 'tcp', b'xx', 'byte-limit', 'exceeds 16 MiB'),
            ('invalid-parts', 'udp', b'x', 'invalid-parts', 'one Opaque'),
        )
        for name, kind, payload, adjustment, pattern in cases:
            with self.subTest(case=name):
                addon = AddonGeneration('', NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                raw = envelope(kind)
                try:
                    await adapter.setup(setup_api(name, raw), None, None)
                    if adjustment == 'message-limit':
                        adapter.raw.MAX_MESSAGES = 0
                    elif adjustment == 'byte-limit':
                        adapter.raw.MAX_HISTORY_BYTES = 1

                    api = content_api(
                        name,
                        'L',
                        payload,
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    if adjustment == 'invalid-parts':
                        api.message.parts.append(
                            RewritePart(b'extra', data=b'extra'))

                    with self.assertRaisesRegex(RawTransportError, pattern):
                        await adapter.content(api)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    await adapter.close()

    async def test_raw_posthook_guards_reject_growth_and_non_byte_content(self):
        cases = (
            ('aggregate-growth',
             "flow.messages[-1].content = b'expanded'",
             'generation history limit'),
            ('non-bytes',
             "flow.messages[-1].content = 'text'",
             'must remain bytes'),
        )
        for name, mutation, pattern in cases:
            with self.subTest(case=name):
                source = f'''def udp_message(flow):
    {mutation}
'''
                addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                if name == 'aggregate-growth':
                    adapter.raw.MAX_GENERATION_HISTORY_BYTES = 4
                raw = envelope('udp')
                try:
                    await adapter.setup(setup_api(name, raw), None, None)
                    api = content_api(
                        name,
                        'L',
                        b'x',
                        content_envelope(raw, 'client-to-server', 0),
                    )
                    with self.assertRaisesRegex(RawTransportError, pattern):
                        await adapter.content(api)
                    self.assertEqual(addon.state, 'failed')
                finally:
                    await adapter.close()

    async def test_empty_udp_expansion_requires_a_native_part_factory(self):
        source = '''def udp_message(flow):
    flow.messages[-1].content = b"expanded"
'''
        addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        raw = envelope('udp')
        try:
            await adapter.setup(setup_api('no-factory', raw), None, None)
            api = content_api(
                'no-factory',
                'L',
                b'',
                content_envelope(raw, 'client-to-server', 0),
            )
            with self.assertRaisesRegex(RawTransportError, 'Opaque Part factory'):
                await adapter.content(api)
            self.assertEqual(addon.state, 'failed')
        finally:
            await adapter.close()

    async def test_empty_udp_passthrough_needs_no_part_factory(self):
        addon = AddonGeneration('', NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon)
        raw = envelope('udp')
        try:
            await adapter.setup(setup_api('empty-passthrough', raw), None, None)
            api = content_api(
                'empty-passthrough',
                'L',
                b'',
                content_envelope(raw, 'client-to-server', 0),
            )
            self.assertEqual(await adapter.content(api), b'')
            flow = adapter.raw._flows['empty-passthrough']
            self.assertEqual(len(flow.messages), 1)
            self.assertEqual(flow.messages[0].content, b'')
            await adapter.stop(
                'empty-passthrough',
                {'raw_transport': terminal_envelope(raw)},
            )
        finally:
            await adapter.close()

    async def test_raw_lifecycle_rejects_duplicate_or_orphan_operations(self):
        addon = AddonGeneration('', NativeAddonAdapter.HOOKS)
        await addon.start()
        adapter = NativeAddonAdapter(addon, opaque_part_factory=RewritePart)
        raw = envelope('tcp')
        setup = RawTransportSetup.parse(raw)
        try:
            await adapter.setup(setup_api('duplicate', raw), None, None)
            with self.assertRaisesRegex(RawTransportError, 'already active'):
                await adapter.raw.start('duplicate', setup)

            orphan = Message(b'x', 1, {})
            with self.assertRaisesRegex(RawTransportError, 'without setup'):
                await adapter.raw.content(
                    'orphan',
                    'L',
                    orphan,
                    setup,
                    content_envelope(raw, 'client-to-server', 0),
                )
            self.assertEqual(await adapter.raw.stop(
                'orphan', setup, terminal_envelope(raw)), ())
            self.assertEqual(await adapter.raw.abort(
                'orphan', setup, 'not active'), ())
        finally:
            await adapter.close()

    async def test_start_hook_failure_has_explicit_recoverable_and_fatal_paths(self):
        cases = (
            ('recoverable', 'raise ValueError("ordinary")', False),
            ('fatal', 'raise SystemExit("fatal")', True),
        )
        for name, action, fatal in cases:
            with self.subTest(path=name):
                source = f'''def tcp_start(flow):
    {action}
'''
                addon = AddonGeneration(source, NativeAddonAdapter.HOOKS)
                await addon.start()
                adapter = NativeAddonAdapter(
                    addon, opaque_part_factory=RewritePart)
                raw = envelope('tcp')
                try:
                    started = adapter.setup(setup_api(name, raw), None, None)
                    if fatal:
                        with self.assertRaisesRegex(SystemExit, 'fatal'):
                            await started
                        self.assertEqual(addon.state, 'failed')
                        self.assertEqual(adapter.active_connections, 0)
                        self.assertEqual(addon.active_flows, 0)
                    else:
                        failures = await started
                        self.assertEqual(len(failures), 1)
                        self.assertIsInstance(failures[0].exception, ValueError)
                        self.assertEqual(adapter.active_connections, 1)
                        self.assertEqual(addon.state, 'running')
                        await adapter.stop(
                            name, {'raw_transport': terminal_envelope(raw)})
                finally:
                    await adapter.close()


if __name__ == '__main__':
    unittest.main()
