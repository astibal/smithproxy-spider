"""Complete DNS lifecycle over the proposed producer envelope."""

import ipaddress
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_dns import (
    DNSMessage,
    Question,
    ResourceRecord,
    classes,
    op_codes,
    response_codes,
    types,
)
from addon_dns_events import (
    DNSAddonEvents,
    DNSExchangeEvent,
    DNSTransportError,
    DNSTransportSetup,
)
from addon_runtime import AddonGeneration


def setup_envelope(transport='udp'):
    return {
        'version': 1,
        'delivery': 'dns-message',
        'transport': transport,
        'client': {
            'peername': ['192.0.2.10', 41000],
            'sockname': ['192.0.2.20', 53],
        },
        'server': {
            'address': ['198.51.100.53', 53],
            'peername': ['198.51.100.53', 53],
            'sockname': ['192.0.2.20', 52000],
        },
    }


def event_envelope(event, exchange_id=1, transport='udp', message=None):
    result = {
        'version': 1,
        'delivery': 'dns-message',
        'transport': transport,
        'event': event,
        'exchange_id': exchange_id,
    }
    if event == 'error':
        result['message'] = 'upstream timeout' if message is None else message
    return result


def query(message_id=0x1234, name='probe.invalid'):
    return DNSMessage(
        id=message_id,
        query=True,
        op_code=op_codes.QUERY,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=True,
        recursion_available=False,
        reserved=0,
        response_code=response_codes.NOERROR,
        questions=[Question(name, types.A, classes.IN)],
        answers=[],
        authorities=[],
        additionals=[],
    )


class DNSEnvelopeTests(unittest.TestCase):
    def test_setup_and_exchange_preserve_explicit_identity(self):
        setup = DNSTransportSetup.parse(setup_envelope('tcp'))
        self.assertEqual(setup.transport, 'tcp')
        self.assertEqual(setup.client.peername, ('192.0.2.10', 41000))
        self.assertEqual(setup.server.address, ('198.51.100.53', 53))
        self.assertEqual(setup.server.transport_protocol, 'tcp')

        request = DNSExchangeEvent.parse(
            event_envelope('request', 17, 'tcp'), setup, 'request')
        self.assertEqual(request.event, 'request')
        self.assertEqual(request.exchange_id, 17)
        self.assertIsNone(request.error)

        error = DNSExchangeEvent.parse(
            event_envelope('error', 17, 'tcp'), setup, 'error')
        self.assertEqual(error.error, 'upstream timeout')

    def test_setup_schema_is_exact_and_bounded(self):
        cases = []
        wrong_type = setup_envelope()
        wrong_type['transport'] = 'quic'
        cases.append((wrong_type, 'udp or tcp'))
        wrong_version = setup_envelope()
        wrong_version['version'] = True
        cases.append((wrong_version, 'version'))
        wrong_delivery = setup_envelope()
        wrong_delivery['delivery'] = 'datagram'
        cases.append((wrong_delivery, 'delivery'))
        unknown = setup_envelope()
        unknown['port'] = 53
        cases.append((unknown, 'unknown fields'))
        bad_client = setup_envelope()
        bad_client['client'] = []
        cases.append((bad_client, 'must be an object'))
        bad_address = setup_envelope()
        bad_address['server']['address'] = ['host-only']
        cases.append((bad_address, 'null or'))
        empty_host = setup_envelope()
        empty_host['server']['address'] = ['', 53]
        cases.append((empty_host, 'bounded text'))
        bool_port = setup_envelope()
        bool_port['client']['peername'][1] = True
        cases.append((bool_port, 'integer'))

        for candidate, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(DNSTransportError, pattern):
                    DNSTransportSetup.parse(candidate)

    def test_exchange_schema_rejects_ambiguous_events(self):
        setup = DNSTransportSetup.parse(setup_envelope())
        cases = []
        changed_transport = event_envelope('request', transport='tcp')
        cases.append((changed_transport, 'identity changed'))
        wrong_event = event_envelope('response')
        cases.append((wrong_event, 'event must be request'))
        bool_exchange = event_envelope('request', True)
        cases.append((bool_exchange, 'positive integer'))
        unknown = event_envelope('request')
        unknown['direction'] = 'client-to-server'
        cases.append((unknown, 'unknown fields'))

        for candidate, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(DNSTransportError, pattern):
                    DNSExchangeEvent.parse(candidate, setup, 'request')

        bad_error = event_envelope('error', message='bad\nerror')
        with self.assertRaisesRegex(DNSTransportError, 'bounded text'):
            DNSExchangeEvent.parse(bad_error, setup, 'error')


class DNSAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_local_response_lifecycle_matches_reference_wire_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_dns_transport_v12.json').read_text())
        source = '''import ipaddress
from mitmproxy import dns
events = []
def report(name, flow, before=None):
    question = flow.request.question
    answer = None
    if flow.response and flow.response.answers:
        answer = str(flow.response.answers[0].ipv4_address)
    events.append({
        "hook": name,
        "flow_type": flow.type,
        "question": None if question is None else question.name,
        "request_query": flow.request.query,
        "response_present": flow.response is not None,
        "response_code": None if flow.response is None else flow.response.response_code,
        "answer_before": before,
        "answer_after": answer,
    })
def dns_request(flow):
    report("dns_request", flow)
    question = flow.request.question
    flow.response = flow.request.succeed([
        dns.ResourceRecord.A(
            question.name,
            ipaddress.IPv4Address("192.0.2.10"),
            ttl=30,
        ),
    ])
def dns_response(flow):
    before = str(flow.response.answers[0].ipv4_address)
    flow.response.answers[0].ipv4_address = ipaddress.IPv4Address("192.0.2.99")
    report("dns_response", flow, before)
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        setup = DNSTransportSetup.parse(setup_envelope())
        adapter.register_connection('reference', setup)
        try:
            decision, failures = await adapter.request(
                'reference', event_envelope('request'), query().packed)
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'local-response')
            self.assertEqual(generation.addon.module.events, corpus['hooks'])

            response = DNSMessage.unpack(decision.content)
            wire = corpus['wire']
            self.assertEqual(response.id, wire['id'])
            self.assertEqual(response.query, wire['query'])
            self.assertEqual(response.response_code, wire['response_code'])
            self.assertEqual(response.recursion_available,
                             wire['recursion_available'])
            self.assertEqual(
                [len(response.questions), len(response.answers),
                 len(response.authorities), len(response.additionals)],
                wire['counts'],
            )
            question = response.questions[0]
            self.assertEqual(
                [question.name, question.type, question.class_],
                wire['question'],
            )
            answer = response.answers[0]
            self.assertEqual(
                [answer.name, answer.type, answer.class_, answer.ttl,
                 str(answer.ipv4_address)],
                wire['answer'],
            )
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('reference')
            await generation.close()

    async def test_local_error_response_matches_reference_wire_corpus(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_dns_local_error_v12.json').read_text())
        source = '''from mitmproxy import dns
events = []
flow_identity = None
def dns_request(flow):
    global flow_identity
    flow_identity = id(flow)
    events.append({
        "hook": "dns_request",
        "question": flow.request.question.name,
        "response_present": flow.response is not None,
    })
    flow.response = flow.request.fail(dns.response_codes.NXDOMAIN)
def dns_response(flow):
    before = flow.response.response_code
    flow.response.response_code = dns.response_codes.REFUSED
    events.append({
        "hook": "dns_response",
        "same_flow": id(flow) == flow_identity,
        "before": before,
        "after": flow.response.response_code,
    })
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.register_connection(
            'local-error',
            DNSTransportSetup.parse(setup_envelope()),
        )
        try:
            decision, failures = await adapter.request(
                'local-error',
                event_envelope('request'),
                query(0x5678, 'local-error.example.com').packed,
            )
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'local-response')
            self.assertEqual(generation.addon.module.events, corpus['hooks'])

            response = DNSMessage.unpack(decision.content)
            wire = corpus['wire']
            self.assertEqual(response.id, wire['id'])
            self.assertFalse(response.query)
            self.assertEqual(response.response_code, wire['response_code'])
            self.assertEqual(
                [len(response.questions), len(response.answers),
                 len(response.authorities), len(response.additionals)],
                wire['counts'],
            )
            self.assertEqual(response.question.name, wire['question'][0])
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('local-error')
            await generation.close()

    async def test_complex_message_matches_reference_wire_corpus(self):
        self.maxDiff = None
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_dns_complex_v12.json').read_text())
        source = '''import ipaddress
events = []
def records(values):
    return [
        [record.name, record.type, record.class_, record.ttl, record.data.hex()]
        for record in values
    ]
def snapshot(message):
    return {
        "id": message.id,
        "query": message.query,
        "op_code": message.op_code,
        "authoritative_answer": message.authoritative_answer,
        "truncation": message.truncation,
        "recursion_desired": message.recursion_desired,
        "recursion_available": message.recursion_available,
        "reserved": message.reserved,
        "response_code": message.response_code,
        "questions": [
            [question.name, question.type, question.class_]
            for question in message.questions
        ],
        "answers": records(message.answers),
        "authorities": records(message.authorities),
        "additionals": records(message.additionals),
    }
def dns_request(flow):
    events.append({
        "hook": "dns_request",
        "message": snapshot(flow.request),
    })
    response = flow.request.copy()
    response.id = flow.request.id
    response.query = False
    flow.response = response
def dns_response(flow):
    flow.response.answers[0].ttl = 99
    flow.response.additionals[0].ipv4_address = ipaddress.IPv4Address(
        "192.0.2.99"
    )
    events.append({
        "hook": "dns_response",
        "message": snapshot(flow.response),
    })
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.register_connection(
            'complex',
            DNSTransportSetup.parse(setup_envelope()),
        )
        try:
            decision, failures = await adapter.request(
                'complex',
                event_envelope('request'),
                bytes.fromhex(corpus['input_hex']),
            )
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'local-response')
            self.assertEqual(generation.addon.module.events, corpus['hooks'])

            response = DNSMessage.unpack(decision.content)
            expected = corpus['hooks'][1]['message']
            self.assertEqual(response.id, expected['id'])
            self.assertFalse(response.query)
            self.assertEqual(response.op_code, expected['op_code'])
            self.assertEqual(response.reserved, expected['reserved'])
            self.assertEqual(response.response_code, expected['response_code'])
            self.assertEqual(
                [question.name for question in response.questions],
                ['alpha.example.com', 'beta.example.com'],
            )
            self.assertEqual(response.answers[0].ttl, 99)
            self.assertEqual(
                str(response.additionals[0].ipv4_address),
                '192.0.2.99',
            )
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('complex')
            await generation.close()

    async def test_forwarded_request_and_response_share_one_flow(self):
        source = '''events = []
def dns_request(flow):
    events.append(("request", id(flow), flow.request.question.name))
    flow.request.questions[0].name = "upstream.invalid"
def dns_response(flow):
    events.append(("response", id(flow), flow.request.question.name))
    flow.response.answers[0].ttl = 90
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        setup = DNSTransportSetup.parse(setup_envelope('tcp'))
        adapter.register_connection('forwarded', setup)
        try:
            request_decision, failures = await adapter.request(
                'forwarded',
                event_envelope('request', 7, 'tcp'),
                query(77).packed,
            )
            self.assertEqual(failures, ())
            self.assertEqual(request_decision.action, 'forward')
            forwarded = DNSMessage.unpack(request_decision.content)
            self.assertEqual(forwarded.question.name, 'upstream.invalid')
            self.assertEqual(generation.active_flows, 1)

            upstream = forwarded.succeed([
                ResourceRecord.A(
                    forwarded.question.name,
                    ipaddress.IPv4Address('192.0.2.5'),
                    ttl=30,
                ),
            ])
            response_decision, failures = await adapter.response(
                'forwarded',
                event_envelope('response', 7, 'tcp'),
                upstream.packed,
            )
            self.assertEqual(failures, ())
            self.assertEqual(response_decision.action, 'replace-response')
            response = DNSMessage.unpack(response_decision.content)
            self.assertEqual(response.answers[0].ttl, 90)
            events = generation.addon.module.events
            self.assertEqual(events[0][1], events[1][1])
            self.assertEqual(events[1][2], 'upstream.invalid')
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('forwarded')
            await generation.close()

    async def test_two_clients_share_script_state_without_crossing_flows(self):
        source = '''import ipaddress
events = []
ordinal = 0
def record(hook, flow):
    global ordinal
    ordinal += 1
    events.append((
        ordinal,
        hook,
        flow.request.question.name,
        id(flow),
    ))
def dns_request(flow):
    record("request", flow)
def dns_response(flow):
    name = flow.request.question.name
    if name == "first.example.com":
        flow.response.answers[0].ipv4_address = ipaddress.IPv4Address("192.0.2.101")
    elif name == "second.example.com":
        flow.response.answers[0].ipv4_address = ipaddress.IPv4Address("192.0.2.102")
    else:
        raise RuntimeError("unexpected question " + name)
    record("response", flow)
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        setup = DNSTransportSetup.parse(setup_envelope())
        adapter.register_connection('first-client', setup)
        adapter.register_connection('second-client', setup)
        try:
            first_request, failures = await adapter.request(
                'first-client',
                event_envelope('request', exchange_id=1),
                query(0xCAFE, 'first.example.com').packed,
            )
            self.assertEqual(failures, ())
            self.assertEqual(first_request.action, 'forward')

            second_request, failures = await adapter.request(
                'second-client',
                event_envelope('request', exchange_id=1),
                query(0xCAFE, 'second.example.com').packed,
            )
            self.assertEqual(failures, ())
            self.assertEqual(second_request.action, 'forward')
            self.assertEqual(generation.active_flows, 2)

            def upstream_response(request_decision):
                request = DNSMessage.unpack(request_decision.content)
                return request.succeed([
                    ResourceRecord.A(
                        request.question.name,
                        ipaddress.IPv4Address('192.0.2.10'),
                        ttl=60,
                    ),
                ])

            second_response, failures = await adapter.response(
                'second-client',
                event_envelope('response', exchange_id=1),
                upstream_response(second_request).packed,
            )
            self.assertEqual(failures, ())
            first_response, failures = await adapter.response(
                'first-client',
                event_envelope('response', exchange_id=1),
                upstream_response(first_request).packed,
            )
            self.assertEqual(failures, ())

            second_message = DNSMessage.unpack(second_response.content)
            first_message = DNSMessage.unpack(first_response.content)
            self.assertEqual(
                str(second_message.answers[0].ipv4_address),
                '192.0.2.102',
            )
            self.assertEqual(
                str(first_message.answers[0].ipv4_address),
                '192.0.2.101',
            )

            events = generation.addon.module.events
            self.assertEqual(
                [(item[0], item[1], item[2]) for item in events],
                [
                    (1, 'request', 'first.example.com'),
                    (2, 'request', 'second.example.com'),
                    (3, 'response', 'second.example.com'),
                    (4, 'response', 'first.example.com'),
                ],
            )
            flow_by_name = {
                item[2]: item[3]
                for item in events
                if item[1] == 'request'
            }
            for _, _, name, identity in events:
                self.assertEqual(identity, flow_by_name[name])
            self.assertNotEqual(
                flow_by_name['first.example.com'],
                flow_by_name['second.example.com'],
            )
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('first-client')
            adapter.release_connection('second-client')
            await generation.close()

    async def test_request_kill_synthesizes_servfail_and_intercept_fails_closed(self):
        sources = (
            ('def dns_request(flow):\n    flow.kill()\n', 'local-response'),
            ('def dns_request(flow):\n    flow.intercept()\n', None),
        )
        for index, (source, action) in enumerate(sources):
            with self.subTest(source=source):
                generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
                await generation.start()
                adapter = DNSAddonEvents(generation)
                identity = 'control-' + str(index)
                adapter.register_connection(
                    identity, DNSTransportSetup.parse(setup_envelope()))
                try:
                    if action is None:
                        with self.assertRaisesRegex(
                                DNSTransportError, 'suspension support'):
                            await adapter.request(
                                identity,
                                event_envelope('request'),
                                query().packed,
                            )
                    else:
                        decision, failures = await adapter.request(
                            identity,
                            event_envelope('request'),
                            query().packed,
                        )
                        self.assertEqual(failures, ())
                        self.assertEqual(decision.action, action)
                        response = DNSMessage.unpack(decision.content)
                        self.assertEqual(
                            response.response_code,
                            response_codes.SERVFAIL,
                        )
                        self.assertEqual(response.answers, [])
                    self.assertEqual(generation.active_flows, 0)
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

    async def test_response_hook_kill_keeps_local_and_upstream_responses(self):
        sources = (
            '''def dns_request(flow):
    flow.response = flow.request.succeed([])
def dns_response(flow):
    flow.kill()
''',
            'def dns_response(flow):\n    flow.kill()\n',
        )
        for index, source in enumerate(sources):
            with self.subTest(local=index == 0):
                generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
                await generation.start()
                adapter = DNSAddonEvents(generation)
                identity = 'response-kill-' + str(index)
                adapter.register_connection(
                    identity, DNSTransportSetup.parse(setup_envelope()))
                try:
                    decision, failures = await adapter.request(
                        identity,
                        event_envelope('request'),
                        query().packed,
                    )
                    if index == 1:
                        self.assertEqual(decision.action, 'forward')
                        decision, failures = await adapter.response(
                            identity,
                            event_envelope('response'),
                            query().succeed([]).packed,
                        )
                    self.assertEqual(failures, ())
                    expected_action = (
                        'local-response' if index == 0
                        else 'replace-response'
                    )
                    self.assertEqual(decision.action, expected_action)
                    response = DNSMessage.unpack(decision.content)
                    self.assertEqual(response.response_code, response_codes.NOERROR)
                    self.assertEqual(generation.active_flows, 0)
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

    async def test_request_local_response_survives_kill_and_runs_response_hook(self):
        source = '''events = []
def dns_request(flow):
    flow.response = flow.request.succeed([])
    flow.kill()
    events.append((
        "request",
        flow.live,
        flow.error.msg,
        flow.response is not None,
    ))
def dns_response(flow):
    events.append((
        "response",
        flow.live,
        flow.error.msg,
        flow.response is not None,
    ))
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.register_connection(
            'request-local-kill',
            DNSTransportSetup.parse(setup_envelope()),
        )
        try:
            decision, failures = await adapter.request(
                'request-local-kill',
                event_envelope('request'),
                query().packed,
            )
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'local-response')
            response = DNSMessage.unpack(decision.content)
            self.assertEqual(response.response_code, response_codes.NOERROR)
            self.assertEqual(
                generation.addon.module.events,
                [
                    ('request', False, 'Connection killed.', True),
                    ('response', False, 'Connection killed.', True),
                ],
            )
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('request-local-kill')
            await generation.close()

    async def test_error_and_connection_abort_deliver_dns_error(self):
        source = '''events = []
def dns_error(flow):
    events.append((flow.request.id, flow.error.msg, flow.live))
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.register_connection(
            'errors', DNSTransportSetup.parse(setup_envelope()))
        try:
            for exchange in (1, 2, 3):
                decision, failures = await adapter.request(
                    'errors', event_envelope('request', exchange),
                    query(exchange).packed,
                )
                self.assertEqual(decision.action, 'forward')
                self.assertEqual(failures, ())

            decision, failures = await adapter.error(
                'errors', event_envelope('error', 1))
            self.assertEqual(decision.action, 'error')
            self.assertEqual(failures, ())
            abort_failures = await adapter.abort_connection(
                'errors', 'connection closed')
            self.assertEqual(abort_failures, ())
            self.assertEqual(
                sorted(generation.addon.module.events),
                [
                    (1, 'upstream timeout', False),
                    (2, 'connection closed', False),
                    (3, 'connection closed', False),
                ],
            )
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('errors')
            await generation.close()

    async def test_connection_and_exchange_admission_are_strict(self):
        generation = AddonGeneration('', DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation, max_connections=1)
        setup = DNSTransportSetup.parse(setup_envelope())
        try:
            for identity, pattern in (
                ('', 'non-empty'),
                ('x' * 1025, 'exceeds'),
            ):
                with self.subTest(identity=pattern):
                    with self.assertRaisesRegex(DNSTransportError, pattern):
                        adapter.register_connection(identity, setup)
            with self.assertRaisesRegex(DNSTransportError, 'validated'):
                adapter.register_connection('bad-setup', object())

            adapter.register_connection('one', setup)
            with self.assertRaisesRegex(DNSTransportError, 'already active'):
                adapter.register_connection('one', setup)
            with self.assertRaisesRegex(DNSTransportError, 'connection limit'):
                adapter.register_connection('two', setup)

            await adapter.request(
                'one', event_envelope('request'), query().packed)
            with self.assertRaisesRegex(DNSTransportError, 'already active'):
                await adapter.request(
                    'one', event_envelope('request'), query().packed)
            with self.assertRaisesRegex(DNSTransportError, 'without request'):
                await adapter.response(
                    'one', event_envelope('response', 2),
                    query(2).succeed([]).packed,
                )

            flow = generation.get_flow('one', 1)
            flow.response = query().succeed([])
            with self.assertRaisesRegex(DNSTransportError, 'already present'):
                await adapter.response(
                    'one', event_envelope('response'),
                    query().succeed([]).packed,
                )
            with self.assertRaisesRegex(DNSTransportError, 'without connection setup'):
                await adapter.request(
                    'missing', event_envelope('request'), query().packed)
        finally:
            adapter.release_connection('one')
            await generation.close()

    async def test_release_is_scoped_and_missing_flow_identity_is_rejected(self):
        generation = AddonGeneration('', DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        setup = DNSTransportSetup.parse(setup_envelope())
        adapter.register_connection('first', setup)
        adapter.register_connection('second', setup)
        try:
            await adapter.request(
                'first', event_envelope('request'), query(1).packed)
            await adapter.request(
                'second', event_envelope('request'), query(2).packed)
            adapter.release_connection('first')
            self.assertEqual(generation.active_flows, 1)

            generation.release_flow('second', 1)
            with self.assertRaisesRegex(DNSTransportError, 'lost its flow'):
                await adapter.response(
                    'second', event_envelope('response'),
                    query(2).succeed([]).packed,
                )
        finally:
            adapter.release_connection('first')
            adapter.release_connection('second')
            await generation.close()

    async def test_dispatch_exception_releases_error_and_abort_flows(self):
        generation = AddonGeneration('', DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.register_connection(
            'dispatch', DNSTransportSetup.parse(setup_envelope()))
        try:
            await adapter.request(
                'dispatch', event_envelope('request', 1), query(1).packed)
            await adapter.request(
                'dispatch', event_envelope('request', 2), query(2).packed)

            async def fail_dispatch(name, flow):
                raise RuntimeError('dispatch failed')

            original_dispatch = generation.dispatch
            generation.dispatch = fail_dispatch
            with self.assertRaisesRegex(RuntimeError, 'dispatch failed'):
                await adapter.error(
                    'dispatch', event_envelope('error', 1))
            self.assertEqual(generation.active_flows, 1)
            with self.assertRaisesRegex(RuntimeError, 'dispatch failed'):
                await adapter.abort_connection('dispatch', 'closed')
            self.assertEqual(generation.active_flows, 0)
        finally:
            if 'original_dispatch' in locals():
                generation.dispatch = original_dispatch
            adapter.release_connection('dispatch')
            await generation.close()

    async def test_malformed_input_and_invalid_mutations_fail_closed(self):
        sources = (
            ('', 'request', 'query'),
            ('def dns_request(flow):\n    flow.request = None\n',
             'request', 'DNSMessage'),
            ('def dns_request(flow):\n    flow.request.query = False\n',
             'request', 'remain a query'),
            ('def dns_request(flow):\n    flow.request.id = 65536\n',
             'request', 'invalid message'),
            ('def dns_request(flow):\n    flow.response = flow.request\n',
             'request', 'remain a response'),
        )
        for index, (source, operation, pattern) in enumerate(sources):
            with self.subTest(pattern=pattern):
                generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
                await generation.start()
                adapter = DNSAddonEvents(generation)
                identity = 'invalid-' + str(index)
                adapter.register_connection(
                    identity, DNSTransportSetup.parse(setup_envelope()))
                try:
                    payload = query().succeed([]).packed if index == 0 else query().packed
                    with self.assertRaisesRegex(DNSTransportError, pattern):
                        await adapter.request(
                            identity, event_envelope(operation), payload)
                    self.assertEqual(generation.active_flows, 0)
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

        generation = AddonGeneration('', DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.register_connection(
            'wire', DNSTransportSetup.parse(setup_envelope()))
        try:
            for payload, pattern in (
                ('text', 'must be bytes'),
                (b'', 'outside producer limits'),
                (b'broken', 'invalid message'),
                (query().packed + b'x', 'invalid message'),
            ):
                with self.subTest(pattern=pattern):
                    with self.assertRaisesRegex(DNSTransportError, pattern):
                        await adapter.request(
                            'wire', event_envelope('request'), payload)
        finally:
            adapter.release_connection('wire')
            await generation.close()

    async def test_response_state_and_size_limits_are_enforced(self):
        source = '''def dns_response(flow):
    flow.response.answers[0].data = b"x" * 100
'''
        generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
        await generation.start()
        adapter = DNSAddonEvents(generation)
        adapter.MAX_MESSAGE_BYTES = 64
        adapter.register_connection(
            'size', DNSTransportSetup.parse(setup_envelope()))
        try:
            request_decision, _ = await adapter.request(
                'size', event_envelope('request'), query().packed)
            response = DNSMessage.unpack(request_decision.content).succeed([
                ResourceRecord.A(
                    'probe.invalid', ipaddress.IPv4Address('192.0.2.5')),
            ])
            with self.assertRaisesRegex(
                    DNSTransportError, 'outside producer limits'):
                await adapter.response(
                    'size', event_envelope('response'), response.packed)
            self.assertEqual(generation.active_flows, 0)
        finally:
            adapter.release_connection('size')
            await generation.close()

    async def test_response_replacements_may_shrink_grow_and_reach_the_wire_limit(self):
        record = ResourceRecord(
            'probe.invalid',
            65000,
            classes.IN,
            60,
            b'x',
        )
        original = query().succeed([record])
        fixed_size = len(original.packed) - len(record.data)
        maximum_data_size = DNSAddonEvents.MAX_MESSAGE_BYTES - fixed_size

        cases = (
            ('smaller', 0),
            ('larger', 1024),
            ('maximum', maximum_data_size),
        )
        for index, (name, replacement_size) in enumerate(cases, start=1):
            with self.subTest(case=name):
                source = '''def dns_response(flow):
    flow.response.answers[0].data = b"z" * REPLACEMENT_SIZE
'''.replace('REPLACEMENT_SIZE', str(replacement_size))
                generation = AddonGeneration(source, DNSAddonEvents.HOOKS)
                await generation.start()
                adapter = DNSAddonEvents(generation)
                identity = 'response-size-' + str(index)
                adapter.register_connection(
                    identity,
                    DNSTransportSetup.parse(setup_envelope()),
                )
                try:
                    request_decision, failures = await adapter.request(
                        identity,
                        event_envelope('request'),
                        query().packed,
                    )
                    self.assertEqual(failures, ())
                    self.assertEqual(request_decision.action, 'forward')

                    response_decision, failures = await adapter.response(
                        identity,
                        event_envelope('response'),
                        original.packed,
                    )
                    self.assertEqual(failures, ())
                    self.assertEqual(
                        response_decision.action,
                        'replace-response',
                    )
                    self.assertEqual(
                        len(response_decision.content),
                        fixed_size + replacement_size,
                    )
                    if name == 'maximum':
                        self.assertEqual(
                            len(response_decision.content),
                            DNSAddonEvents.MAX_MESSAGE_BYTES,
                        )

                    response = DNSMessage.unpack(response_decision.content)
                    self.assertEqual(
                        response.answers[0].data,
                        b'z' * replacement_size,
                    )
                    self.assertEqual(generation.active_flows, 0)
                finally:
                    adapter.release_connection(identity)
                    await generation.close()

    def test_constructor_rejects_ambiguous_connection_limits(self):
        generation = object()
        for value in (True, 0, 1025):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, 'between 1 and 1024'):
                    DNSAddonEvents(generation, max_connections=value)


if __name__ == '__main__':
    unittest.main()
