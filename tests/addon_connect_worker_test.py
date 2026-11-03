"""CONNECT lifecycle over the packaged worker's real IPC boundary."""

import json
import subprocess
import unittest

from addon_connect_native_test import observation
from addon_worker_test import callback, worker_command


class ConnectWorkerTests(unittest.TestCase):
    def worker(self, source):
        process = subprocess.Popen(worker_command('--persistent'), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.close, process)
        ready = self.exchange(process, {'script': '#!mitmproxy\n' + source})
        self.assertTrue(ready.get('ready'), ready)
        return process

    @staticmethod
    def close(process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)

    def exchange(self, process, value):
        process.stdin.write(json.dumps(value) + '\n')
        process.stdin.flush()
        line = process.stdout.readline()
        self.assertTrue(line, 'packaged worker exited without a response')
        return json.loads(line)

    def test_prelude_and_setup_keep_one_flow(self):
        process = self.worker('''def http_connect(flow):
    flow.metadata['identity'] = (id(flow), id(flow.client_conn), id(flow.server_conn))
def http_connected(flow):
    assert flow.metadata['identity'] == (id(flow), id(flow.client_conn), id(flow.server_conn))
    flow.response.status_code = 299
''')
        request = self.exchange(process, {'_request_id': 1, 'http_connect': observation('request')})
        self.assertTrue(request['ok'], request)
        self.assertIn('replacement', request)
        self.assertEqual(request['_request_id'], 1)
        setup = self.exchange(process, {'_request_id': 2, **callback('c1', 'connection-start')})
        self.assertTrue(setup['ok'], setup)
        result = self.exchange(process, {'_request_id': 3, 'http_connect': observation(
            'connected', response=b'HTTP/1.1 200 Connection Established\r\n\r\n')})
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['decision']['action'], 'send-response')
        self.assertIn('replacement', result)
        self.assertEqual(result['_request_id'], 3)

    def test_request_and_generation_cleanup_do_not_publish_credentials(self):
        process = self.worker('''secret = ''
def http_connect(flow):
    global secret
    secret = flow.request.headers['proxy-authorization']
    print(secret)
def client_disconnected(client):
    print(secret)
def done():
    print(secret)
''')
        request = observation('request')
        request['authenticated'] = False
        result = self.exchange(process, {'_request_id': 1, 'http_connect': request})
        self.assertTrue(result['ok'], result)
        self.assertNotIn('Basic secret', str(result))
        shutdown = self.exchange(process, {'_shutdown': True})
        self.assertNotIn('Basic secret', str(shutdown))

    def test_upstream_hook_stays_unavailable(self):
        process = subprocess.Popen(worker_command('--persistent'), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.close, process)
        ready = self.exchange(process, {'script': '#!mitmproxy\ndef http_connect_upstream(flow): pass'})
        self.assertFalse(ready.get('ready', False), ready)


if __name__ == '__main__':
    unittest.main()
