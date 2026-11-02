"""Real packaged addon generations at the native authentication boundary."""
import base64
import json
import subprocess
import unittest

from addon_worker_test import worker_command
from authentication_worker_test import observation


class AuthenticationAddonTests(unittest.TestCase):
    def worker(self, source, hook='authentication'):
        process = subprocess.Popen(worker_command('--persistent'), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.close, process)
        ready = self.exchange(process, {'script': '#!mitmproxy\n' + source, 'hook': hook})
        return process, ready

    def close(self, process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)

    def exchange(self, process, request):
        process.stdin.write(json.dumps(request) + '\n')
        process.stdin.flush()
        line = process.stdout.readline()
        self.assertTrue(line, 'worker exited without a response')
        return json.loads(line)

    def call(self, process, auth):
        return self.exchange(process, {'_request_id': 1, 'authentication': auth})

    def connect(self, status='accepted'):
        auth = observation(status)
        auth['protocol'] = 'http-connect'
        wire = (b'CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n'
                b'Proxy-Authorization: Basic dGVzdDpzZWNyZXQ=\r\nX-Observed: yes\r\n\r\n')
        auth['http_connect'] = {'host': 'example.test', 'port': 443,
                                'request_base64': base64.b64encode(wire).decode()}
        return auth

    def test_socks_persistent_veto_and_cleanup_redaction(self):
        source = '''
from mitmproxy.proxy.layers import modes
calls = 0
secret = None
async def socks5_auth(data: modes.Socks5AuthData):
    global calls, secret
    assert data.client_conn.peername == ('127.0.0.1', 12345)
    assert data.valid is True
    calls += 1
    secret = data.password
    print(secret)
    data.valid = calls == 1
def done():
    print(secret)
    raise ValueError(secret)
'''
        process, ready = self.worker(source)
        self.assertTrue(ready.get('ready'), ready)
        first = self.call(process, observation())
        second = self.call(process, observation())
        self.assertTrue(first['auth_allowed'], first)
        self.assertFalse(second['auth_allowed'], second)
        shutdown = self.exchange(process, {'_shutdown': True})
        self.assertNotIn('DO-NOT-RETAIN', str(first) + str(second) + str(shutdown))

    def test_socks_cannot_upgrade_aaa_and_errors_are_closed(self):
        for status in ('rejected', 'unavailable'):
            process, ready = self.worker('def socks5_auth(data): data.valid = True')
            self.assertTrue(ready.get('ready'), ready)
            result = self.call(process, observation(status))
            self.assertTrue(result['ok'], result)
            self.assertFalse(result['auth_allowed'], result)
        for body in ("data.valid = 'yes'", 'raise ValueError(data.password)'):
            process, ready = self.worker('def socks5_auth(data): ' + body)
            self.assertTrue(ready.get('ready'), ready)
            result = self.call(process, observation())
            self.assertFalse(result['ok'], result)
            self.assertFalse(result['auth_allowed'], result)
            self.assertTrue(result['_worker_recycle'], result)
            self.assertNotIn('DO-NOT-RETAIN', str(result))

    def test_connect_observes_real_request_and_aaa_ordering(self):
        source = '''
def http_connect(flow):
    assert flow.request.method == 'CONNECT'
    assert flow.request.authority == 'example.test:443'
    assert flow.request.host == 'example.test' and flow.request.port == 443
    assert flow.request.headers['x-observed'] == 'yes'
    assert flow.client_conn.peername == ('127.0.0.1', 12345)
    assert flow.server_conn.address == ('example.test', 443)
    assert flow.server_conn.peername is None
    status = flow.metadata['smithproxy_auth']['status']
    if status == 'accepted':
        assert flow.response is None
        assert 'proxy-authorization' not in flow.request.headers
        assert flow.metadata['proxyauth'] == ('test-user', 'DO-NOT-RETAIN')
    else:
        assert 'proxy-authorization' in flow.request.headers
        assert flow.response.status_code == (407 if status == 'rejected' else 503)
        flow.response = None
'''
        process, ready = self.worker(source)
        self.assertTrue(ready.get('ready'), ready)
        for status in ('accepted', 'rejected', 'unavailable'):
            result = self.call(process, self.connect(status))
            self.assertTrue(result['ok'], result)
            self.assertEqual(result['auth_allowed'], status == 'accepted')

    def test_connect_veto_errors_and_unsupported_controls(self):
        for body in ("flow.response = http.Response.make(403)", 'flow.kill()',
                     "flow.request.host = 'elsewhere.test'", 'flow.intercept()',
                     "raise ValueError(flow.metadata['proxyauth'][1])"):
            process, ready = self.worker('from mitmproxy import http\ndef http_connect(flow): ' + body)
            self.assertTrue(ready.get('ready'), ready)
            result = self.call(process, self.connect())
            self.assertFalse(result['auth_allowed'], result)
            self.assertNotIn('DO-NOT-RETAIN', str(result))

    def test_missing_context_and_capability_separation(self):
        process, ready = self.worker('def http_connect(flow): pass')
        self.assertTrue(ready.get('ready'), ready)
        auth = self.connect()
        del auth['http_connect']
        self.assertFalse(self.call(process, auth)['ok'])

        for source, hook in [('def socks5_auth(data): pass', 'content'),
                             ('def request(flow): pass', 'authentication'),
                             ('def http_connected(flow): pass', 'authentication')]:
            process, ready = self.worker(source, hook)
            self.assertFalse(ready.get('ready', False), ready)


if __name__ == '__main__':
    unittest.main()
