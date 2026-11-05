#!/usr/bin/env python3
"""Real QUIC -> Smithproxy -> Spider -> addon tests in the patch runner lab.

Install as the lab's quic-webhook-contract.py. The serve/verify entry points
preserve the existing recorder interface; exercise adds mutation/failure cases.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class ApiError(RuntimeError):
    def __init__(self, url, status, detail):
        super().__init__(f'{url}: HTTP {status}: {detail}')
        self.status = status
        self.detail = detail


TOKEN = 'isolated-quic-integration-token'
PORT = 59091


def request(url, value=None, token=False):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['X-Spider-Token'] = TOKEN
    body = None if value is None else json.dumps(value).encode()
    try:
        with urlopen(Request(url, body, headers), timeout=10) as response:
            return json.load(response)
    except HTTPError as error:
        detail = error.read().decode()
        raise ApiError(url, error.code, detail) from error


def addon(mode):
    lines = [
        '#!mitmproxy',
        'def quic_start_server(data):',
        '    assert data.conn.transport_protocol == "udp"',
    ]
    if mode == 'veto':
        lines.append('    data.conn.error = "QUIC integration veto"')
    elif mode == 'mutation':
        lines.extend([
            '    data.conn.sni = "other.example"',
            '    data.settings.alpn_protocols = ["h3"]',
            '    data.settings.cipher_suites = [0x1302]',
        ])
    elif mode == 'empty-ciphers':
        lines.append('    data.settings.cipher_suites = []')
    elif mode == 'bad-alpn':
        lines.append('    data.settings.alpn_protocols = ["unsupported-test"]')
    lines.extend([
        'def tls_established_client(data):',
        '    if data.conn.transport_protocol != "udp":',
        '        return',
        '    assert data.conn.tls_version == "TLSv1.3"',
        'def tls_established_server(data):',
        '    if data.conn.transport_protocol != "udp":',
        '        return',
        '    assert data.conn.tls_version == "TLSv1.3"',
        '    assert data.conn.alpn == b"h3"',
        '    assert data.conn.certificate_list',
    ])
    if mode == 'mutation':
        lines.append('    assert data.conn.cipher == "TLS_AES_256_GCM_SHA384"')
    return '\n'.join(lines) + '\n'


def serve(path):
    state = {'callback': None, 'mode': 'baseline', 'deployment': None}
    lock = threading.Lock()
    spider_url = f'http://127.0.0.1:{PORT}'

    def configure(value):
        revision = request(spider_url + '/api/inspection', token=True)['revision']
        return request(spider_url + '/api/inspection', {**value, 'revision': revision}, True)

    def deploy(mode):
        value = {'operation': 'deploy', 'name': 'QUIC integration', 'hook': 'content',
                 'scope': 'all', 'instancing': 'flow', 'script_api': 'mitmproxy',
                 'script': addon(mode), 'quic_start_server': mode != 'disabled'}
        if state['deployment']:
            value['id'] = state['deployment']
        result = configure(value)
        state['deployment'] = result['chain'][0]['id']
        configure({'operation': 'enable', 'id': state['deployment'], 'enabled': True})
        state['mode'] = mode

    class Relay(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            event = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            status = 200
            if self.path == '/api/authorize':
                reply = {'auth_token': 'test', 'csrf_token': 'test'}
            elif self.path == '/api/v2/webhook/lease':
                state['callback'] = event['params']['url']
                reply = {'lease_id': 'test', 'expires_at': int(time.time()) + 3600}
            elif self.path == '/scenario':
                deploy(event['mode'])
                reply = {'ready': True}
            elif event.get('action') == 'info':
                reply = {'action': 'info-response', 'protocols': {'connection-content': ['json-base64']}}
            elif event.get('action') == 'access-request':
                reply = {'access-response': 'accept'}
            else:
                try:
                    reply = request(state['callback'], event)
                except ApiError as error:
                    status = error.status
                    reply = json.loads(error.detail)
                # Corrupt only the handshake reply to exercise native availability
                # policy, while leaving setup and retirement fully functional.
                if event.get('action') == 'quic-lifecycle' and state['mode'] in ('unavailable', 'strict'):
                    reply = {'action': 'quic-lifecycle', 'id': 'wrong'}
                if event.get('action') == 'connection-start' and state['mode'] == 'strict':
                    reply.setdefault('control', {})['mode'] = 'strict'
                with lock, path.open('a') as output:
                    output.write(json.dumps({'event': event, 'reply': reply, 'status': status,
                                             'mode': state['mode']}) + '\n')
            body = json.dumps(reply).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    relay = ThreadingHTTPServer(('127.0.0.1', 59090), Relay)
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    root = path.parent / 'spider'
    root.mkdir(exist_ok=True)
    env = {**os.environ, 'SPIDER_TOKEN': TOKEN, 'SPIDER_SMITHPROXY_KEY': 'test-only',
           'SPIDER_COLLECTION_DIR': str(root / 'collection'), 'SPIDER_STORAGE_DIR': str(root / 'storage')}
    log = (root / 'process.log').open('w')
    process = subprocess.Popen([os.environ['SPIDER_INTEGRATION_BIN'], '--port', str(PORT),
                               '--bind', '127.0.0.1', '--smithproxy-url', 'http://127.0.0.1:59090'],
                              env=env, stdout=log, stderr=log)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        deadline = time.monotonic() + 20
        while state['callback'] is None:
            assert process.poll() is None, 'Spider exited before its lease'
            assert time.monotonic() < deadline, 'Spider did not acquire its lease'
            time.sleep(0.05)
        deploy('baseline')
        path.with_suffix('.ready').touch()
        while process.poll() is None:
            time.sleep(0.2)
        raise AssertionError('Spider exited unexpectedly')
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        relay.shutdown()
        log.close()


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def verify(path):
    rows = records(path)
    parents = {}
    baseline_starts = {}
    stopped = set()
    baseline_content = set()
    for row in rows:
        event = row['event']
        action = event.get('action')
        info = event.get('details', {}).get('info', {})
        identity = event.get('id')
        if action == 'connection-start' and info.get('scope') == 'transport':
            parents[identity] = []
        if action == 'connection-start' and row['mode'] == 'baseline' and info.get('scope') in ('transport', 'stream'):
            assert identity not in baseline_starts, 'duplicate setup'
            baseline_starts[identity] = info
            if info['scope'] == 'stream':
                assert info['parent_id'] in parents, 'stream preceded its parent'
        if action in ('connection-content', 'connection-stop', 'quic-lifecycle'):
            assert identity not in stopped, 'event followed retirement'
        if action == 'connection-content' and identity in baseline_starts:
            assert baseline_starts[identity]['scope'] == 'stream', 'parent received content'
            baseline_content.add(identity)
        if action == 'connection-stop':
            stopped.add(identity)
        if event.get('action') != 'quic-lifecycle':
            continue
        assert row['status'] == 200, row
        identity = event['id']
        assert identity in parents, 'QUIC hook preceded parent setup'
        envelope = event['details']['quic']['envelope']
        parents[identity].append((envelope['side'], envelope['event']))
    baseline = [row for row in rows if row['mode'] == 'baseline' and row['event'].get('action') == 'quic-lifecycle']
    assert baseline, 'no live QUIC callbacks'
    assert all(row['reply'].get('proceed') is True for row in baseline), baseline
    for identity in {row['event']['id'] for row in baseline}:
        events = parents[identity]
        assert events.count(('server', 'start')) == 1, events
        assert events.count(('server', 'established')) == 1, events
        assert events.count(('client', 'established')) == 1, events
        assert events.index(('server', 'start')) < events.index(('server', 'established')), events
    assert len(baseline_content) >= 4, 'missing independent HTTP/3 stream content'
    assert set(baseline_starts) <= stopped, 'baseline parent/streams did not retire'
    print('PASS live QUIC parent setup, start/outcome ordering, metadata and addon delivery', flush=True)


def exercise(path):
    root = path.parent.parent
    namespace = os.environ['DATA_NS']
    client = os.environ['CLIENT_NS']
    for mode, succeeds in [('mutation', True), ('veto', False), ('empty-ciphers', False),
                           ('bad-alpn', False), ('unavailable', True), ('strict', False), ('disabled', True)]:
        code = ('import json; from urllib.request import Request,urlopen; '
                f'r=Request("http://127.0.0.1:59090/scenario",json.dumps({{"mode":{mode!r}}}).encode()); '
                'assert json.load(urlopen(r))["ready"]')
        subprocess.run(['ip', 'netns', 'exec', namespace, 'python3', '-c', code], check=True)
        offset = len(records(path))
        result = subprocess.run(['ip', 'netns', 'exec', client, os.environ['QUIC_CURL_BIN'],
            '--http3-only', '--silent', '--show-error', '--fail', '--max-time', '8',
            '--cacert', str(root / 'config/certs/ca-cert.pem'),
            '--resolve', 'origin.runner.lab:443:198.18.20.2', f'https://origin.runner.lab/{mode}'],
            capture_output=True, text=True)
        assert (result.returncode == 0) == succeeds, (mode, result.returncode, result.stdout, result.stderr)
        if succeeds:
            assert f'path=/{mode}' in result.stdout, (mode, result.stdout)
        time.sleep(0.2)
        events = [row for row in records(path)[offset:] if row['event'].get('action') == 'quic-lifecycle']
        if mode == 'disabled':
            assert not events, events
        else:
            assert events, f'{mode}: missing QUIC event'
        if mode == 'mutation':
            assert all(row['status'] == 200 and row['reply'].get('proceed') is True for row in events), events
            phases = [(row['event']['details']['quic']['envelope']['side'],
                       row['event']['details']['quic']['envelope']['event']) for row in events]
            assert phases.count(('server', 'start')) == 1, phases
            assert phases.count(('server', 'established')) == 1, phases
            assert phases.count(('client', 'established')) == 1, phases
        if mode == 'mutation':
            starts = [row for row in events if row['event']['details']['quic']['envelope']['event'] == 'start']
            assert starts[0]['reply']['upstream'] == {'sni': 'other.example', 'alpn': 'h3',
                                                     'ciphers': 'TLS_AES_256_GCM_SHA384'}, starts
        if mode in ('empty-ciphers', 'bad-alpn'):
            failures = [row for row in events if row['event']['details']['quic']['envelope']['event'] == 'failed']
            sides = [row['event']['details']['quic']['envelope']['side'] for row in failures]
            assert sides.count('server') == 1, failures
            assert sides.count('client') <= 1, failures
            assert all(row['status'] == 200 and row['reply'].get('proceed') is True for row in failures), failures
        if mode == 'veto':
            assert any(row['reply'].get('proceed') is False for row in events), events
        print(f'PASS live QUIC scenario: {mode}', flush=True)


if __name__ == '__main__':
    operation, filename = sys.argv[1:]
    {'serve': serve, 'verify': verify, 'exercise': exercise}[operation](Path(filename))
