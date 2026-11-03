"""Native CONNECT prelude, descriptor identity and bounded wire decisions."""

import base64
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from addon_connection import ConnectionState
from addon_connect_events import HTTPConnectAddonEvents, HTTPConnectTransportError
from addon_connect_native import response_bytes, response_value
from addon_http_message import Response
from addon_native import NativeAddonAdapter
from addon_runtime import AddonGeneration


def encode(raw):
    return base64.b64encode(raw).decode('ascii')


def observation(event, identity='c1', response=None):
    return {
        'envelope': {
            'version': 1, 'delivery': 'http-connect', 'connection_id': identity,
            'exchange_id': 1, 'event': event, 'mode': 'regular',
        },
        'target': ['example.test', 443],
        'client_peername': ['192.0.2.1', 40000],
        'client_sockname': ['192.0.2.2', 8080],
        'peername': ['192.0.2.3', 443] if event == 'connected' else None,
        'request_base64': encode(b'CONNECT example.test:443 HTTP/1.1\r\n'
                                 b'Proxy-Authorization: Basic secret\r\n\r\n'),
        'authenticated': True,
        'response_base64': encode(response) if response else None,
    }


class ConnectNativeTests(unittest.IsolatedAsyncioTestCase):
    async def start(self, source):
        generation = AddonGeneration(source, NativeAddonAdapter.HOOKS | HTTPConnectAddonEvents.HOOKS)
        await generation.start()
        adapter = NativeAddonAdapter(generation)
        self.addAsyncCleanup(adapter.close)
        return generation, adapter

    async def test_setup_keeps_flow_and_descriptors(self):
        generation, adapter = await self.start('''events = []
def client_connected(client):
    events.append(("client", id(client)))
def http_connect(flow):
    events.append(("request", id(flow), id(flow.client_conn), id(flow.server_conn),
                   flow.server_conn.address, "proxy-authorization" in flow.request.headers))
def http_connected(flow):
    events.append(("connected", id(flow), id(flow.client_conn), id(flow.server_conn),
                   flow.server_conn.address, flow.server_conn.peername))
''')
        result = await adapter.http_connect(observation('request'))
        self.assertEqual(result['action'], 'continue')
        calls = []
        api = SimpleNamespace(phase='setup', session_id='c1', info={},
                              instance=SimpleNamespace(mode='flow'),
                              connection=SimpleNamespace(
                                  request_rewrite=lambda: calls.append('rewrite'),
                                  track_states=lambda: calls.append('states')))
        adapter.setup(api, None, None)
        result = await adapter.http_connect(observation(
            'connected', response=b'HTTP/1.1 200 Connection Established\r\n\r\n'))
        self.assertEqual(result['action'], 'send-response')
        events = generation.addon.module.events
        self.assertEqual([item[0] for item in events], ['client', 'request', 'connected'])
        self.assertEqual(events[1][1:4], events[2][1:4])
        self.assertEqual(events[1][4:], (None, False))
        self.assertEqual(events[2][4:], (('example.test', 443), ('192.0.2.3', 443)))
        self.assertEqual(calls, ['rewrite', 'states'])
        self.assertEqual(adapter.connect.active_exchanges, 0)
        registered = adapter._connections['c1']
        self.assertEqual(registered.server.state, ConnectionState.OPEN)
        await adapter.stop('c1')
        self.assertEqual(registered.server.state, ConnectionState.CLOSED)
        self.assertIsNotNone(registered.server.timestamp_end)

    async def test_local_response_and_error_mutation(self):
        generation, adapter = await self.start('''from mitmproxy import http
seen = []
def http_connect(flow):
    seen.append(id(flow))
    flow.response = http.Response.make(418, b"tea")
def http_connect_error(flow):
    seen.append(id(flow))
    flow.response.status_code = 419
''')
        decision = await adapter.http_connect(observation('request'))
        self.assertEqual(decision['action'], 'local-response')
        error = observation('error')
        error['response_base64'] = decision['response_base64']
        result = await adapter.http_connect(error)
        response = response_value(result['response_base64'])
        self.assertEqual(response.status_code, 419)
        self.assertEqual(response.raw_content, b'tea')
        self.assertEqual(len(set(generation.addon.module.seen)), 1)

    async def test_abort_does_not_emit_ordinary_http_error(self):
        generation, adapter = await self.start('''events = []
def http_connect(flow):
    events.append("connect")
def error(flow):
    events.append("error")
def client_disconnected(client):
    events.append("stop")
''')
        await adapter.http_connect(observation('request'))
        await adapter.stop('c1')
        self.assertEqual(generation.addon.module.events, ['connect', 'stop'])
        self.assertEqual(adapter.connect.active_exchanges, 0)
        self.assertEqual(adapter.active_connections, 0)

    async def test_failed_prelude_releases_connection_on_stop(self):
        generation, adapter = await self.start("def http_connect(flow): raise ValueError('failure')")
        with self.assertRaises(HTTPConnectTransportError):
            await adapter.http_connect(observation('request'))
        self.assertEqual(generation.state, 'failed')
        await adapter.stop('c1')
        self.assertEqual(adapter.active_connections, 0)
        self.assertEqual(adapter.connect.active_exchanges, 0)

    async def test_reroute_and_kill_are_distinct(self):
        _, adapter = await self.start('''def http_connect(flow):
    if flow.client_conn.peername[1] == 40000:
        flow.request.host = "alternate.test"
        flow.request.port = 8443
    else:
        flow.kill()
''')
        result = await adapter.http_connect(observation('request'))
        self.assertEqual(result['target'], ('alternate.test', 8443))
        killed = observation('request', 'c2')
        killed['client_peername'][1] = 40001
        result = await adapter.http_connect(killed)
        self.assertEqual(result, {'action': 'kill'})
        self.assertEqual(adapter.connect.active_exchanges, 1)

    def test_response_rejects_header_injection_and_oversize(self):
        response = Response.make(403, b'denied')
        response.headers['x-test'] = 'a\r\nb: c'
        with self.assertRaises(HTTPConnectTransportError):
            response_bytes(response)
        with self.assertRaises(HTTPConnectTransportError):
            response_bytes(Response.make(403, b'x' * (256 * 1024)))

    async def test_rejected_authentication_headers_remain_observable(self):
        generation, adapter = await self.start('''seen = []
def http_connect(flow):
    seen.append((flow.response.status_code, flow.request.headers['proxy-authorization']))
''')
        request = observation('request', response=b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
        request['authenticated'] = False
        result = await adapter.http_connect(request)
        self.assertEqual(result['action'], 'local-response')
        self.assertEqual(generation.addon.module.seen, [(407, 'Basic secret')])


if __name__ == '__main__':
    unittest.main()
