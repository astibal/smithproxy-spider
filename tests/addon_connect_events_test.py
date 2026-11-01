"""HTTP CONNECT lifecycle over the proposed native producer boundary."""

from pathlib import Path
import sys
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_connection import Client, ConnectionState, Server
from addon_connect_events import (
    HTTPConnectAddonEvents,
    HTTPConnectEvent,
    HTTPConnectTransportError,
)
from addon_http import Headers
from addon_http_message import Request, Response
from addon_runtime import AddonGeneration


def event(name, *, connection='client-1', exchange=1, mode='regular'):
    return {
        'version': 1,
        'delivery': 'http-connect',
        'connection_id': connection,
        'exchange_id': exchange,
        'event': name,
        'mode': mode,
    }


def connect_request(host='example.test', port=443):
    now = time.time()
    authority = f'{host}:{port}'
    return Request(
        host,
        port,
        b'CONNECT',
        b'',
        b'',
        authority.encode('ascii'),
        b'HTTP/1.1',
        Headers([(b'Host', authority.encode('ascii'))]),
        b'',
        None,
        now,
        now,
    )


def descriptors():
    client = Client(
        peername=('192.0.2.10', 41000),
        sockname=('192.0.2.20', 8080),
    )
    client.state = ConnectionState.OPEN
    server = Server(address=None)
    return client, server


def observe_server(server, *, address, peername, open_connection):
    server.state = ConnectionState.CLOSED
    server.address = address
    server.peername = peername
    server.sockname = ('192.0.2.20', 52000) if peername else None
    server.state = (
        ConnectionState.OPEN if open_connection else ConnectionState.CLOSED
    )


class HTTPConnectEnvelopeTests(unittest.TestCase):
    def test_event_preserves_explicit_identity_and_mode(self):
        observation = HTTPConnectEvent.parse(
            event('request', connection='client-a', exchange=7, mode='upstream'),
            'request',
        )

        self.assertEqual(observation.connection_id, 'client-a')
        self.assertEqual(observation.exchange_id, 7)
        self.assertEqual(observation.mode, 'upstream')
        self.assertEqual(observation.key, ('client-a', 7))

    def test_event_schema_is_exact_bounded_and_typed(self):
        cases = []
        not_object = []
        cases.append((not_object, 'must be an object'))
        wrong_version = event('request')
        wrong_version['version'] = True
        cases.append((wrong_version, 'version'))
        wrong_delivery = event('request')
        wrong_delivery['delivery'] = 'http'
        cases.append((wrong_delivery, 'delivery'))
        empty_connection = event('request', connection='')
        cases.append((empty_connection, 'connection_id'))
        long_connection = event('request', connection='x' * 1025)
        cases.append((long_connection, 'connection_id'))
        bool_exchange = event('request', exchange=True)
        cases.append((bool_exchange, 'positive integer'))
        wrong_event = event('connected')
        cases.append((wrong_event, 'event must be request'))
        wrong_mode = event('request', mode='reverse')
        cases.append((wrong_mode, 'regular or upstream'))
        unknown = event('request')
        unknown['authority'] = 'example.test:443'
        cases.append((unknown, 'missing or unknown'))

        for candidate, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(
                        HTTPConnectTransportError, pattern):
                    HTTPConnectEvent.parse(candidate, 'request')


class HTTPConnectAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_regular_reroute_and_outcome_mutation_share_one_flow(self):
        source = '''events = []
def http_connect(flow):
    events.append(("request", id(flow), id(flow.server_conn), flow.server_conn.address))
    flow.request.host = "rerouted.test"
    flow.request.port = 9443
def http_connected(flow):
    events.append(("connected", id(flow), id(flow.server_conn), flow.server_conn.address))
    flow.response.status_code = 299
    flow.kill()
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            decision, failures = await adapter.request(
                event('request'), connect_request(), client, server)
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'continue')
            self.assertEqual(
                (decision.request.host, decision.request.port),
                ('rerouted.test', 9443),
            )
            self.assertEqual(adapter.active_exchanges, 1)

            observe_server(
                server,
                address=('rerouted.test', 9443),
                peername=('198.51.100.10', 9443),
                open_connection=True,
            )
            outcome, failures = await adapter.connected(
                event('connected'), Response.make(200))
            self.assertEqual(failures, ())
            self.assertEqual(outcome.action, 'send-response')
            self.assertEqual(outcome.response.status_code, 299)
            self.assertEqual(adapter.active_exchanges, 0)
            self.assertEqual(generation.active_flows, 0)

            observed = generation.addon.module.events
            self.assertEqual(observed[0][0], 'request')
            self.assertEqual(observed[1][0], 'connected')
            self.assertEqual(observed[0][1], observed[1][1])
            self.assertEqual(observed[0][2], observed[1][2])
            self.assertIsNone(observed[0][3])
            self.assertEqual(observed[1][3], ('rerouted.test', 9443))
        finally:
            await generation.close()

    async def test_local_response_runs_error_on_the_same_flow(self):
        source = '''from mitmproxy import http
events = []
def http_connect(flow):
    events.append(("request", id(flow), flow.response))
    flow.response = http.Response.make(418, b"blocked")
def http_connect_error(flow):
    events.append(("error", id(flow), flow.response.status_code))
    flow.response.status_code = 419
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            decision, failures = await adapter.request(
                event('request'), connect_request(), client, server)
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'local-response')
            self.assertEqual(decision.response.status_code, 418)

            outcome, failures = await adapter.error(event('error'))
            self.assertEqual(failures, ())
            self.assertEqual(outcome.action, 'send-response')
            self.assertEqual(outcome.response.status_code, 419)
            self.assertEqual(adapter.active_exchanges, 0)
            events = generation.addon.module.events
            self.assertEqual(events[0][1], events[1][1])
        finally:
            await generation.close()

    async def test_existing_auth_response_is_visible_and_preserved(self):
        source = '''seen = []
def http_connect(flow):
    seen.append((flow.response.status_code, "proxy-authorization" in flow.request.headers))
def http_connect_error(flow):
    seen.append((flow.response.status_code, "proxy-authorization" in flow.request.headers))
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        request = connect_request()
        request.headers['Proxy-Authorization'] = 'Basic rejected'
        try:
            decision, _ = await adapter.request(
                event('request'), request, client, server, Response.make(407))
            self.assertEqual(decision.action, 'local-response')
            outcome, _ = await adapter.error(event('error'))
            self.assertEqual(outcome.response.status_code, 407)
            self.assertEqual(
                generation.addon.module.seen,
                [(407, True), (407, True)],
            )
        finally:
            await generation.close()

    async def test_request_kill_is_the_only_early_terminal_decision(self):
        source = '''def http_connect(flow):
    flow.kill()
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            decision, failures = await adapter.request(
                event('request'), connect_request(), client, server)
            self.assertEqual(failures, ())
            self.assertEqual(decision.action, 'kill')
            self.assertEqual(adapter.active_exchanges, 0)
            self.assertEqual(generation.active_flows, 0)
        finally:
            await generation.close()

    async def test_upstream_hook_is_non_live_and_only_authority_is_returned(self):
        source = '''from mitmproxy import exceptions, http
events = []
def http_connect(flow):
    events.append(("request", id(flow), id(flow.server_conn), flow.live))
def http_connected(flow):
    events.append(("connected", id(flow), id(flow.server_conn), flow.live))
def http_connect_upstream(flow):
    try:
        flow.kill()
    except exceptions.ControlException as error:
        events.append(("upstream", id(flow), id(flow.server_conn), flow.live, str(error)))
    flow.request.host = "rewritten.invalid"
    flow.request.port = 9443
    flow.response = http.Response.make(418)
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            decision, _ = await adapter.request(
                event('request', mode='upstream'),
                connect_request(),
                client,
                server,
            )
            self.assertEqual(decision.action, 'continue')

            observe_server(
                server,
                address=('example.test', 443),
                peername=None,
                open_connection=False,
            )
            outcome, _ = await adapter.connected(
                event('connected', mode='upstream'),
                Response.make(200),
            )
            self.assertEqual(outcome.response.status_code, 200)
            self.assertEqual(adapter.active_exchanges, 1)

            observe_server(
                server,
                address=('upstream.test', 8080),
                peername=('198.51.100.20', 8080),
                open_connection=True,
            )
            upstream, failures = await adapter.upstream(
                event('upstream', mode='upstream'))
            self.assertEqual(failures, ())
            self.assertEqual(upstream.action, 'upstream-authority')
            self.assertEqual(
                (upstream.request.host, upstream.request.port),
                ('rewritten.invalid', 9443),
            )
            self.assertEqual(adapter.active_exchanges, 0)

            observed = generation.addon.module.events
            self.assertEqual([item[0] for item in observed], [
                'request', 'connected', 'upstream',
            ])
            self.assertEqual(len({item[1] for item in observed}), 1)
            self.assertEqual(len({item[2] for item in observed}), 1)
            self.assertEqual(observed[2][3:], (False, 'Flow is not killable.'))
        finally:
            await generation.close()

    async def test_unhandled_late_kill_is_a_hook_failure_not_a_wire_action(self):
        source = '''def http_connect_upstream(flow):
    flow.kill()
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            await adapter.request(
                event('request', mode='upstream'),
                connect_request(),
                client,
                server,
            )
            await adapter.connected(
                event('connected', mode='upstream'),
                Response.make(200),
            )
            decision, failures = await adapter.upstream(
                event('upstream', mode='upstream'))
            self.assertEqual(decision.action, 'upstream-authority')
            self.assertEqual(len(failures), 1)
            self.assertRegex(str(failures[0].exception), 'not killable')
        finally:
            await generation.close()

    async def test_sequence_mode_and_duplicate_guards_fail_closed(self):
        generation = AddonGeneration('', HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'without a request'):
                await adapter.connected(event('connected'), Response.make(200))

            await adapter.request(
                event('request'), connect_request(), client, server)
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'already active'):
                await adapter.request(
                    event('request'), connect_request(), client, server)
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'mode changed'):
                await adapter.connected(
                    event('connected', mode='upstream'), Response.make(200))
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'out of order'):
                await adapter.upstream(event('upstream'))

            released = adapter.abort_connection('client-1')
            self.assertEqual(len(released), 1)
            self.assertEqual(adapter.active_exchanges, 0)
            self.assertEqual(adapter.abort_connection('unknown'), ())
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'non-empty'):
                adapter.abort_connection('')
        finally:
            await generation.close()

    async def test_invalid_native_values_and_hook_replacements_are_rejected(self):
        generation = AddonGeneration(
            'def http_connect(flow):\n    flow.request = object()\n',
            HTTPConnectAddonEvents.HOOKS,
        )
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            cases = (
                (object(), client, server, None, 'native CONNECT Request'),
                (connect_request(), object(), server, None, 'descriptors'),
                (connect_request(), client, object(), None, 'descriptors'),
                (connect_request(), client, server, object(), 'HTTP Response'),
            )
            for request, selected_client, selected_server, response, pattern in cases:
                with self.subTest(pattern=pattern):
                    with self.assertRaisesRegex(
                            HTTPConnectTransportError, pattern):
                        await adapter.request(
                            event('request'),
                            request,
                            selected_client,
                            selected_server,
                            response,
                        )

            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'retain an HTTP Request'):
                await adapter.request(
                    event('request'), connect_request(), client, server)
            self.assertEqual(adapter.active_exchanges, 0)
            self.assertEqual(generation.active_flows, 0)
        finally:
            await generation.close()

    async def test_request_rejects_interception_and_unknown_terminal_state(self):
        cases = (
            (
                'def http_connect(flow):\n    flow.intercept()\n',
                'interception',
            ),
            (
                'def http_connect(flow):\n    flow.live = False\n',
                'unsupported flow state',
            ),
        )
        for source, pattern in cases:
            with self.subTest(pattern=pattern):
                generation = AddonGeneration(
                    source, HTTPConnectAddonEvents.HOOKS)
                await generation.start()
                adapter = HTTPConnectAddonEvents(generation)
                client, server = descriptors()
                try:
                    with self.assertRaisesRegex(
                            HTTPConnectTransportError, pattern):
                        await adapter.request(
                            event('request'),
                            connect_request(),
                            client,
                            server,
                        )
                    self.assertEqual(adapter.active_exchanges, 0)
                finally:
                    await generation.close()

    async def test_connected_revalidates_response_and_control_state(self):
        cases = (
            (
                'def http_connected(flow):\n    flow.response = object()\n',
                'retain an HTTP Response',
            ),
            (
                'def http_connected(flow):\n    flow.intercept()\n',
                'interception',
            ),
        )
        for source, pattern in cases:
            with self.subTest(pattern=pattern):
                generation = AddonGeneration(
                    source, HTTPConnectAddonEvents.HOOKS)
                await generation.start()
                adapter = HTTPConnectAddonEvents(generation)
                client, server = descriptors()
                try:
                    await adapter.request(
                        event('request'), connect_request(), client, server)
                    with self.assertRaisesRegex(
                            HTTPConnectTransportError, pattern):
                        await adapter.connected(
                            event('connected'), Response.make(200))
                    self.assertEqual(adapter.active_exchanges, 0)
                finally:
                    await generation.close()

    async def test_error_accepts_native_response_and_rejects_bad_sequence(self):
        source = '''def http_connect_error(flow):
    flow.intercept()
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            await adapter.request(
                event('request'), connect_request(), client, server)
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'interception'):
                await adapter.error(event('error'), Response.make(502))
            self.assertEqual(adapter.active_exchanges, 0)

            await adapter.request(
                event('request', exchange=2, mode='upstream'),
                connect_request(),
                client,
                server,
            )
            await adapter.connected(
                event('connected', exchange=2, mode='upstream'),
                Response.make(200),
            )
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'out of order'):
                await adapter.error(
                    event('error', exchange=2, mode='upstream'),
                    Response.make(502),
                )
            adapter.abort_connection('client-1')
        finally:
            await generation.close()

    async def test_upstream_rejects_interception_and_releases_flow(self):
        source = '''def http_connect_upstream(flow):
    flow.intercept()
'''
        generation = AddonGeneration(source, HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        try:
            await adapter.request(
                event('request', mode='upstream'),
                connect_request(),
                client,
                server,
            )
            await adapter.connected(
                event('connected', mode='upstream'), Response.make(200))
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'interception'):
                await adapter.upstream(event('upstream', mode='upstream'))
            self.assertEqual(adapter.active_exchanges, 0)
        finally:
            await generation.close()

    async def test_incomplete_response_and_wrong_outcome_value_fail_closed(self):
        generation = AddonGeneration('', HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = HTTPConnectAddonEvents(generation)
        client, server = descriptors()
        incomplete = Response(
            b'HTTP/1.1', 502, b'Bad Gateway', Headers(),
            None, None, time.time(), time.time(),
        )
        try:
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'complete byte body'):
                await adapter.request(
                    event('request'),
                    connect_request(),
                    client,
                    server,
                    incomplete,
                )

            await adapter.request(
                event('request'), connect_request(), client, server)
            with self.assertRaisesRegex(
                    HTTPConnectTransportError, 'retain an HTTP Response'):
                await adapter.connected(event('connected'), object())
            adapter.abort_connection('client-1')
        finally:
            await generation.close()


if __name__ == '__main__':
    unittest.main()
