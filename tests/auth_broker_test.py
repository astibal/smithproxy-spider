"""Exercise the host client over real Unix sockets; optionally use Linux PAM."""
import argparse
import contextlib
import grp
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import tempfile
import threading
import time
import unittest


class Client:
    def __init__(self, executable, path):
        # A broken environment proxy must not affect the Unix transport.
        env = dict(os.environ, http_proxy='http://127.0.0.1:1', ALL_PROXY='http://127.0.0.1:1', NO_PROXY='')
        self.process = subprocess.Popen([executable, str(path)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, env=env)

    def verify(self, username='alice', password='secret'):
        self.process.stdin.write(json.dumps(dict(username=username, password=password)) + '\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError('authentication test client exited unexpectedly')
        return json.loads(line)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.communicate(timeout=5)


@contextlib.contextmanager
def responder(path, body, status=200, delay=0):
    failures = []
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(3)

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    request = b''
                    while b'\r\n\r\n' not in request:
                        part = connection.recv(4096)
                        if not part:
                            raise AssertionError('incomplete HTTP request')
                        request += part
                    headers, received = request.split(b'\r\n\r\n', 1)
                    assert headers.startswith(b'POST /v1/pap HTTP/1.1\r\n'), headers
                    length = next(int(line.split(b':', 1)[1]) for line in headers.split(b'\r\n')
                                  if line.lower().startswith(b'content-length:'))
                    while len(received) < length:
                        part = connection.recv(4096)
                        assert part
                        received += part
                    assert json.loads(received) == dict(version=1, username='alice', password='secret')
                    time.sleep(delay)
                    header = f'HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\nConnection: close\r\nLocation: http://127.0.0.1:1/\r\n\r\n'
                    try:
                        connection.sendall(header.encode() + body)
                    except BrokenPipeError:
                        if not delay:
                            raise
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            yield
        finally:
            worker.join(timeout=4)
            path.unlink()
            assert not worker.is_alive(), 'test responder did not stop'
            if failures:
                raise failures[0]


class AuthBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='spider-auth-')
        self.root = Path(self.temporary.name)
        self.path = self.root / 'auth.sock'
        self.client = Client(ARGS.probe, self.path)

    def tearDown(self):
        self.client.close()
        self.temporary.cleanup()

    def test_connect_on_demand_and_recover_without_cached_acceptance(self):
        self.assertEqual(self.client.verify()['status'], 'unavailable')
        accepted = dict(version=1, status='accepted', identity='canonical', groups=['proxy-users'])
        with responder(self.path, json.dumps(accepted).encode()):
            result = self.client.verify()
        self.assertEqual(result, dict(status='accepted', identity='canonical', groups=['proxy-users']))

        self.assertEqual(self.client.verify()['status'], 'unavailable')
        with responder(self.path, b'{"version":1,"status":"rejected"}'):
            result = self.client.verify()
        self.assertEqual(result, dict(status='rejected', identity='', groups=[]))

    def test_invalid_responses_and_timeout_fail_closed(self):
        accepted = dict(version=1, status='accepted', identity='alice', groups=['users'])
        cases = [b'not json', b'{}', b'[]', b'x' * 16385]
        changes = [dict(version=2), dict(version=True), dict(version=1.0), dict(status='error'),
                   dict(identity=''), dict(identity='x' * 513), dict(identity='a\0b'),
                   dict(groups=['']), dict(groups=['x'] * 65), dict(groups='users')]
        cases.extend(json.dumps(dict(accepted, **change)).encode() for change in changes)
        for body in cases:
            with self.subTest(body=body[:80]), responder(self.path, body):
                self.assertEqual(self.client.verify()['status'], 'unavailable')

        for status in (302, 401, 503):
            with self.subTest(status=status), responder(self.path, json.dumps(accepted).encode(), status):
                self.assertEqual(self.client.verify()['status'], 'unavailable')
        with responder(self.path, json.dumps(accepted).encode(), delay=0.5):
            self.assertEqual(self.client.verify()['status'], 'unavailable')

    def test_invalid_credentials_never_need_a_broker(self):
        for username, password in [('', 'x'), ('x', ''), ('x' * 256, 'x'), ('x', 'x' * 1025),
                                   ('a\0b', 'x'), ('x', 'a\0b'), ('x', '\x01' * 1024)]:
            with self.subTest(username_length=len(username), password_length=len(password)):
                self.assertEqual(self.client.verify(username, password)['status'], 'rejected')

    def test_invalid_paths_are_rejected(self):
        for path in ('', 'relative.sock', '/' + 'x' * 108):
            result = subprocess.run([ARGS.probe, path], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 2)

    def test_real_pam_group_account_and_daemon_restart(self):
        if not ARGS.broker or not ARGS.pam_module:
            self.skipTest('requires a Keyway build with tests enabled')

        user = pwd.getpwuid(os.getuid())
        group = grp.getgrgid(user.pw_gid).gr_name
        service = self.root / 'test-auth'
        config = self.root / 'broker.cfg'

        def start(allowed_group=group, account=''):
            service.write_text(f'auth required {ARGS.pam_module}\naccount required {ARGS.pam_module} {account}\n')
            config.write_text(f'socket="{self.path}"; pam={{enabled=true; service="test-auth"; allowed_group="{allowed_group}"; config_directory="{self.root}";}};')
            process = subprocess.Popen([ARGS.broker, '--config', str(config)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 3
            while not self.path.exists():
                if process.poll() is not None or time.monotonic() > deadline:
                    process.terminate()
                    raise AssertionError(process.communicate(timeout=3))
                time.sleep(0.01)
            return process

        for allowed_group, account, expected in [(group, '', 'accepted'),
                ('no-such-spider-group', '', 'rejected'), (group, 'deny', 'rejected'),
                (group, '', 'accepted')]:
            process = start(allowed_group, account)
            try:
                result = self.client.verify(user.pw_name, 'test-only-password')
                self.assertEqual(result['status'], expected)
                if expected == 'accepted':
                    self.assertEqual(result['identity'], user.pw_name)
                    self.assertEqual(result['groups'], [group])
                self.assertEqual(self.client.verify(user.pw_name, 'wrong')['status'], 'rejected')
            finally:
                process.terminate()
                process.communicate(timeout=3)
            self.assertEqual(self.client.verify(user.pw_name, 'test-only-password')['status'], 'unavailable')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', required=True)
    parser.add_argument('--broker')
    parser.add_argument('--pam-module')
    ARGS = parser.parse_args()
    unittest.main(argv=[__file__])
