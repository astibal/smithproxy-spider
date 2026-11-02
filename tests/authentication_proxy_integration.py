"""Real proxy -> Spider -> native script policy, with a temporary PAM broker.

The local relay captures only decision metadata and injects transport failures;
it is also the test-only lease API needed to discover Spider's callback URL.
"""
import base64
import grp
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.request import Request, urlopen

PROXY, BROKER, MODULE, SPIDER, NATIVE, FIXTURE = [Path(value).resolve() for value in sys.argv[1:7]]
sys.path.insert(0, str(NATIVE / 'tests/httpconnect'))
from http_connect_integration import free_port, make_config, process_env, wait_for_listener

USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name
PASSWORD = 'test-only-password'
TOKEN = 'auth-hook-test-token'
callback = None
relay_mode = 'forward'
observations = []


def post(url, body, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['X-Spider-Token'] = token
    with urlopen(Request(url, json.dumps(body).encode(), headers), timeout=8) as response:
        return json.load(response)


class Relay(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        global callback
        event = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path == '/api/authorize':
            result = {'auth_token': 'test', 'csrf_token': 'test'}
        elif self.path == '/api/v2/webhook/lease':
            callback = event['params']['url']
            result = {'lease_id': 'test', 'expires_at': int(time.time()) + 60}
        elif self.path == '/relay':
            if event.get('action') == 'proxy-authentication':
                auth = event['details']['authentication']
                observations.append((auth['protocol'], auth['status']))
                if relay_mode == 'wrong-id':
                    result = {'action': 'proxy-authentication', 'id': 'wrong',
                              'version': 1, 'decision': 'accept'}
                elif relay_mode == 'upgrade':
                    result = {'action': 'proxy-authentication', 'id': event['id'],
                              'version': 1, 'decision': 'accept'}
                else:
                    result = post(callback, event)
            else:
                result = {'action': 'accept'}
        else:
            result = {}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass


def receive(client, count):
    result = b''
    while len(result) < count:
        part = client.recv(count - len(result))
        assert part, result
        result += part
    return result


def http(port, target, expected, password=PASSWORD):
    secret = base64.b64encode(f'{USER}:{password}'.encode())
    with socket.create_connection(('127.0.0.1', port), timeout=8) as client:
        client.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n'.encode() +
                       b'Proxy-Authorization: Basic ' + secret + b'\r\n\r\n')
        response = b''
        while not response.endswith(b'\r\n\r\n'):
            response += receive(client, 1)
        assert response.startswith(f'HTTP/1.1 {expected} '.encode()), response


def socks(port, target, allowed, password=PASSWORD):
    with socket.create_connection(('127.0.0.1', port), timeout=8) as client:
        client.sendall(b'\x05\x01\x02')
        assert receive(client, 2) == b'\x05\x02'
        user, secret = USER.encode(), password.encode()
        client.sendall(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
        assert receive(client, 2) == bytes([1, 0 if allowed else 1])
        if allowed:
            client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target))
            reply = receive(client, 4)
            assert reply[:3] == b'\x05\x00\x00', reply
            receive(client, 6 if reply[3] == 1 else 18)


def target_connection(origin, expected):
    origin.settimeout(1 if expected else 0.15)
    try:
        connection, _ = origin.accept()
    except socket.timeout:
        assert not expected, 'accepted authentication never reached target'
        return
    connection.close()
    assert expected, 'denied authentication opened the target'


with tempfile.TemporaryDirectory(prefix='auth-webhook-live-') as directory:
    root = Path(directory)
    certificates = root / 'etc/certs/default'
    certificates.mkdir(parents=True)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=auth-webhook-test', '-keyout', str(certificates / 'ca-key.pem'),
                    '-out', str(certificates / 'ca-cert.pem')], check=True, capture_output=True)
    for name in ('cl', 'srv', 'portal'):
        shutil.copyfile(certificates / 'ca-key.pem', certificates / (name + '-key.pem'))
        shutil.copyfile(certificates / 'ca-cert.pem', certificates / (name + '-cert.pem'))
    for name in ('ip', 'sni', 'cc-ip', 'cc-sni'):
        (certificates / name).mkdir()
    (root / 'test-auth').write_text(f'auth required {MODULE}\naccount required {MODULE}\n')
    auth_socket = root / 'auth.sock'
    broker_config = root / 'broker.cfg'
    broker_config.write_text(f'socket="{auth_socket}"; pam={{service="test-auth"; allowed_group="{GROUP}"; config_directory="{root}";}};')

    relay = ThreadingHTTPServer(('127.0.0.1', 0), Relay)
    thread = threading.Thread(target=relay.serve_forever, daemon=True)
    thread.start()
    relay_url = f'http://127.0.0.1:{relay.server_port}'
    spider_port, http_port, socks_port = free_port(), free_port(), free_port()
    spider_url = f'http://127.0.0.1:{spider_port}'
    processes = []
    logs = []

    def launch(command, env):
        log = (root / f'process-{len(logs)}.log').open('w+')
        logs.append(log)
        process = subprocess.Popen(list(map(str, command)), env=env, stdout=log, stderr=log)
        processes.append(process)
        return process

    def configure(request):
        with urlopen(Request(spider_url + '/api/inspection', headers={'X-Spider-Token': TOKEN})) as response:
            request['revision'] = json.load(response)['revision']
        return post(spider_url + '/api/inspection', request, TOKEN)

    try:
        env = {**os.environ, 'SPIDER_TOKEN': TOKEN, 'SPIDER_SMITHPROXY_KEY': 'test-only',
               'SPIDER_COLLECTION_DIR': str(root / 'collection'), 'SPIDER_STORAGE_DIR': str(root / 'storage')}
        spider = launch([SPIDER, '--port', spider_port, '--bind', '127.0.0.1',
                         '--smithproxy-url', relay_url], env)
        wait_for_listener(spider, spider_port)
        deadline = time.monotonic() + 8
        while callback is None:
            assert time.monotonic() < deadline, 'no callback lease'
            time.sleep(0.02)
        broker = launch([BROKER, '--config', broker_config], os.environ.copy())
        deadline = time.monotonic() + 8
        while not auth_socket.exists():
            assert broker.poll() is None and time.monotonic() < deadline
            time.sleep(0.02)
        config = root / 'proxy.cfg'
        make_config(FIXTURE, config, root, root, http_port, free_port())
        content = config.read_text().replace('accept_socks = FALSE;', 'accept_socks = TRUE;')
        content = content.replace('socks_workers = 0;', f'socks_workers = 1; socks_port = "{socks_port}";')
        content = content.replace('settings = {', f'settings = {{\n webhook = {{enabled=true; url="{relay_url}/relay";}};', 1)
        config.write_text(content)
        proxy = launch([PROXY, '--config-file', config, '--debug', '--comm-auth', auth_socket], process_env(root))
        wait_for_listener(proxy, http_port)
        wait_for_listener(proxy, socks_port)
        state = configure({'operation': 'deploy', 'name': 'Auth test', 'hook': 'authentication',
                           'scope': 'all', 'script': 'def main(api, state): pass'})
        identity = state['chain'][0]['id']
        configure({'operation': 'enable', 'id': identity, 'enabled': True})

        def deploy(body):
            configure({'operation': 'deploy', 'id': identity, 'name': 'Auth test',
                       'hook': 'authentication', 'scope': 'all', 'script': 'def main(api, state):\n    ' + body})

        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0))
            origin.listen(10)
            target = origin.getsockname()[1]
            http(http_port, target, 200)
            target_connection(origin, True)
            socks(socks_port, target, True)
            target_connection(origin, True)
            deploy('api.auth.allowed = True')
            http(http_port, target, 407, 'wrong')
            socks(socks_port, target, False, 'wrong')
            target_connection(origin, False)
            relay_mode = 'upgrade'
            http(http_port, target, 407, 'wrong')
            socks(socks_port, target, False, 'wrong')
            target_connection(origin, False)
            relay_mode = 'forward'
            deploy('api.auth.allowed = False')
            http(http_port, target, 407)
            socks(socks_port, target, False)
            target_connection(origin, False)
            deploy('print(api.auth.password); raise ValueError(api.auth.password)')
            http(http_port, target, 407)
            socks(socks_port, target, False)
            target_connection(origin, False)
            deploy('import time; time.sleep(4)')
            http(http_port, target, 407)
            socks(socks_port, target, False)
            target_connection(origin, False)
            deploy('pass')
            relay_mode = 'wrong-id'
            http(http_port, target, 503)
            socks(socks_port, target, False)
            target_connection(origin, False)
            relay.shutdown()
            relay.server_close()
            http(http_port, target, 503)
            socks(socks_port, target, False)
            target_connection(origin, False)
            # Disabling the optional webhook restores direct AAA behavior,
            # even though the old callback endpoint is now unavailable.
            proxy.terminate()
            proxy.wait(timeout=10)
            direct_http, direct_socks = free_port(), free_port()
            direct_config = content.replace('webhook = {enabled=true;', 'webhook = {enabled=false;')
            direct_config = direct_config.replace(f'http_connect_port = "{http_port}";',
                                                  f'http_connect_port = "{direct_http}";')
            direct_config = direct_config.replace(f'socks_port = "{socks_port}";',
                                                  f'socks_port = "{direct_socks}";')
            config.write_text(direct_config)
            proxy = launch([PROXY, '--config-file', config, '--debug', '--comm-auth', auth_socket], process_env(root))
            wait_for_listener(proxy, direct_http)
            wait_for_listener(proxy, direct_socks)
            http(direct_http, target, 200)
            target_connection(origin, True)
            socks(direct_socks, target, True)
            target_connection(origin, True)
            http(direct_http, target, 407, 'wrong')
            target_connection(origin, False)
        assert {'http-connect', 'socks5'} <= {protocol for protocol, _ in observations}
        with urlopen(Request(spider_url + '/api/inspection', headers={'X-Spider-Token': TOKEN})) as response:
            assert PASSWORD not in response.read().decode()
        for log in logs:
            log.flush()
            log.seek(0)
            assert PASSWORD not in log.read()
        for log in root.glob('messages.*.log'):
            assert PASSWORD not in log.read_text(errors='replace')
        print('PASS: real PAM/HTTP CONNECT/SOCKS5/Spider veto, rejected AAA, bad reply identity and unavailable hook')
    except BaseException:
        print('Authentication observations:', observations, file=sys.stderr)
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read()[-6000:], file=sys.stderr)
        raise
    finally:
        relay.shutdown()
        relay.server_close()
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
