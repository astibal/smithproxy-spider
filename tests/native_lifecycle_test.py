"""Native lifecycle and real UDP RADIUS traffic inside the production sandbox."""
import base64
import io
import json
import socket
import subprocess
import sys
import threading
import unittest

from inspection_sandbox_test import SOURCE
from worker_bootstrap import packed


class Worker:
    def __init__(self, script, **options):
        self.process = subprocess.Popen(
            [sys.executable, '-I', '-c', packed(SOURCE), '--persistent'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        self.ready = self.exchange({'script': script, **options})

    def exchange(self, request):
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError(self.process.stderr.read())
        return json.loads(line)

    def call(self, **extra):
        return self.exchange({'_request_id': 1, 'event': {'details': {'info': {
            'content': base64.b64encode(b'hello').decode()}}}, **extra})

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)


class LifecycleTests(unittest.TestCase):
    def worker(self, script, **options):
        worker = Worker(script, **options)
        self.addCleanup(worker.close)
        return worker

    def test_legacy_function_bodies(self):
        for source in ('return "legacy"', '    return "legacy"'):
            with self.subTest(source=source):
                result = self.single(source)
                self.assertTrue(result['ok'], result)
                self.assertEqual(base64.b64decode(result['replacement']), b'legacy')

    def test_state_and_cleanup(self):
        worker = self.worker('''
from collections import deque

def init(api, state):
    assert state is None and api.phase == 'init'
    assert not hasattr(api, 'message')
    print('init')
    return deque()

def main(api, state):
    state.append(api.text)
    api.state['calls'] = len(state)
    print('main', len(state))
    return api.bytes

def exit(api, state):
    assert api.phase == 'exit'
    print('exit', len(state))
''')
        self.assertTrue(worker.ready['native_lifecycle'])
        for index in range(1, 301):
            result = worker.call()
            self.assertTrue(result['ok'], result)
            expected = ['main ' + str(index)]
            if index == 1:
                expected.insert(0, 'init')
            self.assertEqual(result['logs'], expected)
            self.assertEqual(result['instance_state'], {'calls': index})
            self.assertFalse(result['_worker_rotate'])
        self.assertEqual(worker.exchange({'_shutdown': True})['logs'], ['exit 300'])
        self.assertEqual(worker.process.wait(timeout=5), 0)

    def test_validation_is_inert_and_preview_runs_cleanup(self):
        script = '''
from __future__ import annotations
raise AssertionError('module executed')
def main(api, state):
    raise AssertionError('main executed')
'''
        result = self.single(script, validate_only=True, script_api='spider')
        self.assertTrue(result['ok'], result)
        result = self.single('''
def init(api, state):
    return object()
def main(api, state):
    assert state is not None
    return 'preview'
def exit(api, state):
    print('exit')
''')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['logs'], ['exit'])

    def single(self, script, **options):
        result = subprocess.run([sys.executable, '-I', '-c', packed(SOURCE)],
                                input=json.dumps({'script': script, **options}),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_module_annotations_and_tcp_client(self):
        peer = socket.socket()
        peer.bind(('127.0.0.1', 0))
        peer.listen(1)
        peer.settimeout(2)
        self.addCleanup(peer.close)
        port = peer.getsockname()[1]
        received = []

        def serve():
            try:
                connection, _ = peer.accept()
            except socket.timeout:
                return
            with connection:
                connection.settimeout(2)
                received.append(connection.recv(16))
                connection.sendall(b'pong')

        server = threading.Thread(target=serve)
        server.start()
        self.addCleanup(server.join, 3)
        script = f'''from __future__ import annotations
from dataclasses import dataclass
import socket

@dataclass
class State:
    client: object

def init(api, state):
    return State(socket.create_connection(('127.0.0.1', {port}), timeout=1))

def main(api, state):
    state.client.sendall(b'ping')
    return state.client.recv(16)

def exit(api, state):
    state.client.close()
'''
        worker = self.worker(script, network_enabled=True)
        self.assertTrue(worker.ready.get('ready'), worker.ready)
        result = worker.call()
        self.assertTrue(result['ok'], result)
        self.assertEqual(base64.b64decode(result['replacement']), b'pong')
        self.assertTrue(worker.exchange({'_shutdown': True})['ok'])
        server.join(timeout=3)
        self.assertEqual(received, [b'ping'])

    def test_failure_and_signature(self):
        for script in (
            'def main(api): pass',
            'async def main(api, state): pass',
            'def init(api, state): raise ValueError("init failed")\ndef main(api, state): pass',
        ):
            self.assertFalse(self.single(script)['ok'])
        worker = self.worker('def main(api, state): raise ValueError("main failed")')
        result = worker.call()
        self.assertFalse(result['ok'])
        self.assertTrue(result['_worker_recycle'])
        self.assertEqual(worker.process.wait(timeout=5), 0)
        result = self.single('def main(api, state): pass\ndef exit(api, state): raise ValueError("exit failed")')
        self.assertFalse(result['ok'])
        self.assertIn('exit failed', result['error'])

    def test_network_does_not_grant_process_or_file_access(self):
        for operation in ("open('/etc/passwd').read()", "__import__('os').fork()"):
            result = self.single(operation, network_enabled=True)
            self.assertFalse(result['ok'], result)
            self.assertIn('PermissionError', result['error'])
        self.assertFalse(self.single('pass', network_enabled='true')['ok'])


DICTIONARY = 'ATTRIBUTE User-Name 1 string\nATTRIBUTE User-Password 2 string\n'


class RadiusTests(unittest.TestCase):
    worker = LifecycleTests.worker

    # A bounded local peer exercises wire encoding, password encryption and reply
    # verification without installing a daemon or touching machine configuration.
    def test_radius_client_lives_in_init(self):
        from pyrad.dictionary import Dictionary
        from pyrad.packet import AuthPacket, AccessAccept, AccessReject

        peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer.bind(('127.0.0.1', 0))
        peer.settimeout(0.1)
        self.addCleanup(peer.close)
        port = peer.getsockname()[1]
        stopped = threading.Event()
        requests = []
        failures = []
        dictionary = Dictionary(io.StringIO(DICTIONARY))

        def serve():
            while not stopped.is_set():
                try:
                    data, address = peer.recvfrom(4096)
                except socket.timeout:
                    continue
                try:
                    request = AuthPacket(packet=data, secret=b'test-secret', dict=dictionary)
                    valid = (request['User-Name'] == ['test-user'] and
                             request.PwDecrypt(request['User-Password'][0]) == 'test-password')
                    reply = request.CreateReply()
                    reply.code = AccessAccept if valid else AccessReject
                    requests.append(valid)
                    peer.sendto(reply.ReplyPacket(), address)
                except BaseException as error:
                    failures.append(error)
                    return

        server = threading.Thread(target=serve)
        server.start()
        def stop():
            stopped.set()
            server.join(timeout=2)
        self.addCleanup(stop)

        script = f'''
def init(api, state):
    from io import StringIO
    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    client = Client(server='127.0.0.1', authport={port}, secret=b'test-secret',
                    dict=Dictionary(StringIO({DICTIONARY!r})), retries=1, timeout=0.5)
    print('client initialized')
    return {{'client': client, 'calls': 0}}

def main(api, state):
    from pyrad.packet import AccessRequest, AccessAccept
    client = state['client']
    state['calls'] += 1
    request = client.CreateAuthPacket(code=AccessRequest, User_Name='test-user')
    password = 'test-password' if state['calls'] == 1 else 'wrong-password'
    request['User-Password'] = request.PwCrypt(password)
    reply = client.SendPacket(request)
    print('accepted' if reply.code == AccessAccept else 'rejected')

def exit(api, state):
    state['client']._CloseSocket()
    print('client closed')
'''
        enabled = self.worker(script, network_enabled=True)
        self.assertTrue(enabled.ready.get('ready'), enabled.ready)
        first = enabled.call()
        self.assertTrue(first['ok'], first)
        self.assertEqual(first['logs'], ['client initialized', 'accepted'])
        second = enabled.call()
        self.assertTrue(second['ok'], second)
        self.assertEqual(second['logs'], ['rejected'])
        shutdown = enabled.exchange({'_shutdown': True})
        self.assertTrue(shutdown['ok'], shutdown)
        self.assertEqual(shutdown['logs'], ['client closed'])

        disabled = self.worker(script)
        self.assertTrue(disabled.ready.get('ready'), disabled.ready)
        # An untrusted per-callback field cannot relax the startup policy.
        denied = disabled.call(network_enabled=True)
        self.assertFalse(denied['ok'], denied)
        self.assertIn('PermissionError', denied['error'])
        stop()
        self.assertEqual(requests, [True, False])
        self.assertEqual(failures, [])


if __name__ == '__main__':
    unittest.main()
