"""Real Smithproxy -> Spider -> addon CONNECT decisions and callback ordering."""

import argparse
import base64
import grp
import pwd
import re
import json
import os
from pathlib import Path
import shutil
import socket
import re
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--proxy', type=Path, required=True)
    parser.add_argument('--spider', type=Path, required=True)
    parser.add_argument('--native-source', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--starttls-only', action='store_true')
    selection.add_argument('--starttls-failures-only', action='store_true')
    selection.add_argument('--resumption-only', action='store_true')
    selection.add_argument('--clienthello-only', action='store_true')
    parser.add_argument('--broker', type=Path)
    parser.add_argument('--pam-module', type=Path)
    args = parser.parse_args()
    for executable in (args.proxy, args.spider, args.broker, args.pam_module):
        if executable is not None and not executable.is_file():
            parser.error(f'Missing test dependency: {executable}')
    sys.path.insert(0, str(args.native_source / 'tests/httpconnect'))
    from http_connect_integration import free_port, make_config, process_env, wait_for_listener

    token = 'connect-hook-test-token'
    callback = None
    exchanges = []
    mode = 'forward'
    request_held = threading.Event()
    release_request = threading.Event()

    def post(url, value, auth=None):
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['X-Spider-Token'] = auth
        request = Request(url, json.dumps(value).encode(), headers)
        with urlopen(request, timeout=8) as response:
            return json.load(response)

    class Relay(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            nonlocal callback
            event = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            status = 200
            if self.path == '/api/authorize':
                result = {'auth_token': 'test', 'csrf_token': 'test'}
            elif self.path == '/api/v2/webhook/lease':
                callback = event['params']['url']
                result = {'lease_id': 'test', 'expires_at': int(time.time()) + 60}
            elif self.path == '/relay':
                if (event['action'] == 'server-lifecycle' and mode == 'hold-server' and
                        event['details']['server']['envelope']['event'] == 'connect'):
                    request_held.set()
                    assert release_request.wait(8), 'test did not release held server hook'

                invalid = event['action'] == 'http-connect' and (
                    mode == 'invalid' or (mode == 'strict-outcome' and
                    event['details']['http_connect']['envelope']['event'] == 'connected'))
                if event['action'] == 'info':
                    # This test relay speaks JSON. Binary content transport has
                    # separate integration coverage and is not negotiated here.
                    result = {'action': 'info-response',
                              'protocols': {'connection-content': ['json-base64']}}
                elif (event['action'] == 'tls-lifecycle' and mode in ('invalid-hello', 'strict-hello')
                      and event['details']['tls']['envelope']['event'] == 'client-hello'):
                    result = {'action': 'tls-lifecycle', 'id': 'wrong',
                              'proceed': True, 'ignore_connection': True}
                elif event['action'] == 'server-lifecycle' and mode in ('invalid-server', 'strict-server'):
                    result = {'action': 'server-lifecycle', 'id': 'wrong'}
                elif invalid:
                    result = {'action': 'http-connect', 'id': 'wrong'}
                else:
                    try:
                        result = post(callback, event)
                    except HTTPError as error:
                        status = error.code
                        result = json.load(error)
                if event['action'] == 'connection-start' and mode in ('strict-outcome', 'strict-server', 'hold-server', 'strict-hello'):
                    result.setdefault('control', {})['mode'] = 'strict'
                if (event['action'] == 'tls-lifecycle' and mode == 'invalid-upstream'
                        and event['details']['tls']['envelope']['event'] == 'client-hello'):
                    # A valid SNI change must not survive an invalid ALPN offer.
                    if result.get('schema') == 2:
                        result['client_hello']['alpn_offers'] = [base64.b64encode(b'h3').decode()]
                    else:
                        result['upstream']['alpn_base64'] = base64.b64encode(bytes([2]) + b'h3').decode()
                if (event['action'] == 'http-connect' and mode == 'hold-request' and
                        event['details']['http_connect']['envelope']['event'] == 'request'):
                    request_held.set()
                    assert release_request.wait(8), 'test did not release held request'
                if event['action'] in ('http-connect', 'server-lifecycle', 'tls-lifecycle', 'connection-start', 'connection-stop', 'connection-content'):
                    exchanges.append((event, result, status))
            else:
                result = {}
            wire = json.dumps(result).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(wire)))
            self.end_headers()
            try:
                self.wfile.write(wire)
            except BrokenPipeError:
                pass

    with tempfile.TemporaryDirectory(prefix='connect-hooks-live-') as directory:
        root = Path(directory)
        certificates = root / 'etc/certs/default'
        certificates.mkdir(parents=True)
        shutil.copytree(args.native_source / 'etc/msg/en', root / 'etc/msg/en')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=connect-hook-test',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature', '-keyout', str(certificates / 'ca-key.pem'),
                        '-out', str(certificates / 'ca-cert.pem')], check=True, capture_output=True)
        for name in ('cl', 'srv', 'portal'):
            for suffix in ('key.pem', 'cert.pem'):
                shutil.copyfile(certificates / ('ca-' + suffix), certificates / (name + '-' + suffix))
        for name in ('ip', 'sni', 'cc-ip', 'cc-sni'):
            (certificates / name).mkdir()
        relay = ThreadingHTTPServer(('127.0.0.1', 0), Relay)
        threading.Thread(target=relay.serve_forever, daemon=True).start()
        relay_url = f'http://127.0.0.1:{relay.server_port}'
        spider_port, proxy_port = free_port(), free_port()
        spider_url = f'http://127.0.0.1:{spider_port}'
        processes, logs = [], []

        def launch(command, env):
            log = (root / f'process-{len(logs)}.log').open('w+')
            logs.append(log)
            process = subprocess.Popen(list(map(str, command)), env=env, stdout=log, stderr=log)
            processes.append(process)
            return process

        def configure(value):
            # A timed-out worker can finish teardown between GET and POST.
            # Retry only the API's explicit optimistic revision conflict.
            for attempt in range(3):
                request = Request(spider_url + '/api/inspection', headers={'X-Spider-Token': token})
                with urlopen(request) as response:
                    value['revision'] = json.load(response)['revision']
                try:
                    return post(spider_url + '/api/inspection', value, token)
                except HTTPError as error:
                    detail = error.read().decode()
                    if attempt == 2 or 'Backend changed; refresh before editing the chain' not in detail:
                        raise AssertionError(detail) from error

        deployment = None

        def deploy(source, tls_clienthello=False, tls_start_server=False, tls_start_client=False, native=False, tls_lifecycle=False):
            nonlocal deployment
            value = {'operation': 'deploy', 'name': 'CONNECT test', 'hook': 'content',
                     'scope': 'all', 'instancing': 'flow', 'script_api': 'spider' if native else 'mitmproxy',
                     'script': source if native else '#!mitmproxy\n' + source, 'tls_clienthello': tls_clienthello,
                     'tls_start_server': tls_start_server, 'tls_start_client': tls_start_client,
                     'tls_lifecycle': tls_lifecycle}
            if deployment:
                value['id'] = deployment
            state = configure(value)
            deployment = state['chain'][0]['id']
            configure({'operation': 'enable', 'id': deployment, 'enabled': True})

        def exchange(target, expected, fragmented=False, credentials=None):
            offset = len(exchanges)
            with socket.create_connection(('127.0.0.1', proxy_port), timeout=8) as client:
                request = f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n'.encode()
                if credentials is not None:
                    request += b'Proxy-Authorization: Basic ' + base64.b64encode(credentials.encode()) + b'\r\n'
                request += b'\r\n'
                if fragmented:
                    for fragment in (request[:3], request[3:-2], request[-2:]):
                        client.sendall(fragment)
                        time.sleep(0.01)
                else:
                    client.sendall(request)
                response = b''
                while b'\r\n\r\n' not in response:
                    part = client.recv(4096)
                    if not part:
                        break
                    response += part
                if expected is None:
                    assert not response, response
                else:
                    assert response.startswith(f'HTTP/1.1 {expected} '.encode()), response
            time.sleep(0.05)
            events = [item for item in exchanges[offset:] if item[0]['action'] == 'http-connect'
                      and item[0]['details']['http_connect']['envelope']['event'] != 'abort']
            return events

        try:
            env = {**os.environ, 'SPIDER_TOKEN': token, 'SPIDER_SMITHPROXY_KEY': 'test-only',
                   'SPIDER_COLLECTION_DIR': str(root / 'collection'), 'SPIDER_STORAGE_DIR': str(root / 'storage')}
            spider = launch([args.spider, '--port', spider_port, '--bind', '127.0.0.1',
                             '--smithproxy-url', relay_url], env)
            wait_for_listener(spider, spider_port)
            deadline = time.monotonic() + 8
            while callback is None:
                assert time.monotonic() < deadline, 'no callback lease'
                time.sleep(0.02)
            config = root / 'proxy.cfg'
            make_config(args.fixture, config, root, root, proxy_port, free_port())
            content = config.read_text().replace('settings = {',
                f'settings = {{\n webhook = {{enabled=true; url="{relay_url}/relay";}};', 1)
            content = content.replace('        write_payload = FALSE;',
                '        write_payload = FALSE; webhook_enable = TRUE; webhook_lock_traffic = FALSE;', 1)
            config.write_text(content)
            base_config_text = content

            def start_tls_proxy(target, verify_identity=False, plaintext=False, trusted_origin=False,
                                handshake_timeout=None):
                # Use the transparent listener and policy DNAT. The fixture
                # needs no host firewall changes and does not alter CONNECT behavior.
                port = free_port()
                text = base_config_text.replace('nat = "none";', 'nat = "auto";')
                if trusted_origin:
                    text = text.replace('settings = {',
                        f'settings = {{ ca_bundle_file="{certificates / "ca-cert.pem"}";', 1)
                cli_port = free_port()
                settings = {
                    'accept_tproxy': 'TRUE', 'accept_redirect': 'FALSE', 'accept_http_connect': 'FALSE',
                    'ssl_port': f'"{port}"', 'ssl_workers': '1',
                    'plaintext_workers': '-1', 'udp_workers': '-1',
                    'allow_untrusted_issuers': 'FALSE' if trusted_origin else 'TRUE',
                    'allow_invalid_certs': 'FALSE' if verify_identity else 'TRUE',
                    'allow_self_signed': 'FALSE' if trusted_origin else 'TRUE',
                    'port': str(cli_port), 'log_console': 'TRUE', 'log_level': '8',
                }
                if handshake_timeout is not None:
                    settings['handshake_timeout'] = str(handshake_timeout)

                if trusted_origin:
                    settings['ocsp_stapling'] = 'FALSE'

                if plaintext:
                    settings.update(ssl_workers='-1', plaintext_workers='1', plaintext_port=f'"{port}"')

                for name, value in settings.items():
                    text, count = re.subn(r'(\b' + name + r'\s*=\s*)[^;]+;',
                                         lambda match: match[1] + value + ';', text, count=1)
                    assert count == 1, name

                text = re.sub(r'(tls_profiles\s*=\s*\{\s*default\s*=\s*\{)',
                              r'\1 ct_enable = FALSE;', text, count=1)
                text = text.replace('address_objects = {',
                    'address_objects = { tls_origin = { type=0; cidr="127.0.0.1/32"; };', 1)
                text = text.replace('port_objects = {',
                    f'port_objects = {{ tls_origin = {{start={target}; end={target};}};', 1)
                text, count = re.subn(r'routing\s*=\s*\{\s*\}',
                    'routing = { tls_test = { dnat_address=["tls_origin"]; '
                    'dnat_port=["tls_origin"]; dnat_lb_method="round-robin"; '
                    'rewrite_sni=""; rewrite_sni_to=""; }; }', text, count=1)
                assert count == 1
                position = text.rfind('routing = "none";')
                assert position >= 0
                text = text[:position] + text[position:].replace('routing = "none";',
                    'routing = "tls_test";', 1)

                tls_config = root / f'tls-{target}.cfg'
                tls_config.write_text(text)
                tls_process = launch([args.proxy, '--config-file', tls_config, '--debug'],
                    process_env(root, f'tls-{target}.pid'))
                # A TCP readiness probe would itself create an upstream TLS
                # session and consume the one-shot origin. Inspect LISTEN only.
                deadline = time.monotonic() + 10
                while True:
                    sockets = []
                    for table in ('/proc/net/tcp', '/proc/net/tcp6'):
                        sockets.extend(Path(table).read_text().splitlines()[1:])
                    if any(line.split()[1].endswith(f':{port:04X}') and
                           line.split()[3] == '0A' for line in sockets):
                        break
                    assert tls_process.poll() is None, 'TLS proxy exited during startup'
                    assert time.monotonic() < deadline, 'TLS listener did not open'
                    time.sleep(.02)
                if trusted_origin and os.environ.get('RESUMPTION_TRACE'):
                    with socket.create_connection(('127.0.0.1', cli_port), timeout=2) as cli:
                        cli.sendall(b'enable\r\ndebug set all 7\r\nquit\r\n')
                        output = bytearray()
                        while True:
                            chunk = cli.recv(4096)
                            if not chunk:
                                break
                            output.extend(chunk)
                        (root / 'resumption-cli.log').write_bytes(output)
                return port, tls_process

            def tls_relay_mode(value):
                nonlocal mode
                mode = value

            if args.resumption_only:
                from resumption_hook_cases import run_resumption_cases
                run_resumption_cases(deploy, start_tls_proxy, certificates, exchanges)
                return

            if args.starttls_failures_only:
                from starttls_failure_cases import run_starttls_failure_cases
                run_starttls_failure_cases(deploy, start_tls_proxy, exchanges)
                return

            if args.starttls_only:
                from starttls_hook_cases import run_starttls_cases
                run_starttls_cases(deploy, start_tls_proxy, certificates, exchanges, args.native_source)
                return

            from tls_proxy_cases import run_tls_cases, run_tls_failure_cases, run_native_clienthello_cases
            if args.clienthello_only:
                run_native_clienthello_cases(deploy, start_tls_proxy, certificates, exchanges)
                return
            run_tls_cases(deploy, start_tls_proxy, certificates, exchanges, tls_relay_mode)
            run_tls_failure_cases(deploy, start_tls_proxy, certificates, exchanges, tls_relay_mode)
            run_native_clienthello_cases(deploy, start_tls_proxy, certificates, exchanges)
            mode = 'forward'

            proxy = launch([args.proxy, '--config-file', config, '--debug'], process_env(root))
            wait_for_listener(proxy, proxy_port)

            with socket.socket() as origin:
                origin.bind(('127.0.0.1', 0))
                origin.listen(10)
                target = origin.getsockname()[1]
                deploy('''def http_connect(flow):
    assert flow.response is None
    assert flow.server_conn.address is None
    flow.metadata['identity'] = (id(flow), id(flow.client_conn), id(flow.server_conn))
def http_connected(flow):
    assert flow.metadata['identity'] == (id(flow), id(flow.client_conn), id(flow.server_conn))
    assert flow.response.status_code == 200
    assert flow.server_conn.peername is not None
    flow.response.status_code = 299
''')
                events = exchange(target, 299, fragmented=True)
                assert [item[0]['details']['http_connect']['envelope']['event'] for item in events] == ['request', 'connected'], events
                assert all(item[2] == 200 for item in events), events
                connection, _ = origin.accept()
                connection.close()
                print('PASS: fragmented request, shared flow/descriptors, connected response mutation')

                deploy("""events = []
server = None
def http_connect(flow):
    global server
    server = flow.server_conn
    events.append('http_connect')
def server_connect(data):
    assert data.server is server
    assert data.server.timestamp_start is None
    assert data.server.peername is None
    events.append('server_connect')
def server_connected(data):
    assert data.server is server
    assert data.server.peername is not None
    assert data.server.sockname is not None
    events.append('server_connected')
def http_connected(flow):
    assert events == ['http_connect', 'server_connect', 'server_connected']
    assert flow.server_conn is server
    flow.response.status_code = 298
def server_disconnected(data):
    assert data.server is server
    assert data.server.timestamp_end is not None
""")
                offset = len(exchanges)
                events = exchange(target, 298)
                identity = events[0][0]['id']
                connection, _ = origin.accept()
                connection.close()
                deadline = time.monotonic() + 8
                while True:
                    lifecycle = [item for item in exchanges[offset:]
                                 if item[0]['id'] == identity and item[0]['action'] == 'server-lifecycle']
                    phases = [item[0]['details']['server']['envelope']['event'] for item in lifecycle]
                    stopped = any(item[0]['id'] == identity and item[0]['action'] == 'connection-stop'
                                  for item in exchanges[offset:])
                    if phases == ['connect', 'connected', 'disconnected'] and stopped:
                        break
                    assert time.monotonic() < deadline, phases
                    time.sleep(0.02)
                assert all(item[2] == 200 for item in lifecycle), lifecycle
                assert len({item[0]['details']['server']['envelope']['attempt'] for item in lifecycle}) == 1
                # Session teardown must not release the addon before its final server callback.
                terminal_events = []
                for event, _, status in exchanges[offset:]:
                    if event['id'] != identity:
                        continue

                    if event['action'] == 'server-lifecycle':
                        if event['details']['server']['envelope']['event'] == 'disconnected':
                            terminal_events.append(('disconnected', status))
                    elif event['action'] == 'connection-stop':
                        terminal_events.append(('stop', status))

                assert terminal_events == [('disconnected', 200), ('stop', 200)], terminal_events
                print('PASS: ordered server lifecycle shares CONNECT descriptors and terminates once')

                deploy("""events = []
def server_connect(data):
    events.append('connect')
def server_connect_error(data):
    assert data.server.error
    events.append('error')
def http_connect_error(flow):
    assert events == ['connect', 'error']
    flow.response.status_code = 597
""")
                exchange(free_port(), 597)
                print('PASS: server_connect_error precedes HTTP CONNECT failure')

                deploy("""def server_connect(data):
    data.server.error = 'Test veto'
""")
                offset = len(exchanges)
                exchange(target, 502)
                origin.settimeout(0.1)
                try:
                    connection, _ = origin.accept()
                    connection.close()
                    raise AssertionError('Server veto contacted target')
                except socket.timeout:
                    pass
                finally:
                    origin.settimeout(2)
                lifecycle = [item for item in exchanges[offset:] if item[0]['action'] == 'server-lifecycle']
                assert [item[0]['details']['server']['envelope']['event'] for item in lifecycle] == ['connect', 'error']
                print('PASS: server_connect veto prevents the upstream socket attempt')

                deploy("""def http_connected(flow):
    flow.response.status_code = 296
""")
                mode = 'invalid-server'
                exchange(target, 296)
                connection, _ = origin.accept()
                connection.close()
                print('PASS: invalid server observer reply is fail-open in regular mode')

                mode = 'strict-server'
                exchange(target, 502)
                origin.settimeout(0.1)
                try:
                    connection, _ = origin.accept()
                    connection.close()
                    raise AssertionError('Strict server observer failure contacted target')
                except socket.timeout:
                    pass
                finally:
                    origin.settimeout(2)
                    mode = 'forward'
                print('PASS: negotiated strict server observer failure prevents target contact')

                deploy('def http_connect(flow): pass')
                request_held.clear()
                release_request.clear()
                mode = 'hold-server'
                server_errors = []

                def pending_server():
                    try:
                        exchange(target, None)
                    except BaseException as error:
                        server_errors.append(error)

                pending = threading.Thread(target=pending_server)
                pending.start()
                assert request_held.wait(5), 'server hook did not reach the relay'
                deploy('def server_connect(data): raise AssertionError("new generation adopted old connection")')
                mode = 'forward'
                release_request.set()
                pending.join(8)
                assert not pending.is_alive() and not server_errors, server_errors
                origin.settimeout(0.1)
                try:
                    connection, _ = origin.accept()
                    connection.close()
                    raise AssertionError('Retired strict setup owner contacted target')
                except socket.timeout:
                    pass
                finally:
                    origin.settimeout(2)
                request_held.clear()
                release_request.clear()
                print('PASS: redeploy during a strict server hook cannot adopt or connect the old flow')

                deploy('''from mitmproxy import http
def http_connect(flow):
    flow.metadata['identity'] = id(flow)
    flow.response = http.Response.make(418, b'tea')
def http_connect_error(flow):
    assert flow.metadata['identity'] == id(flow)
    assert flow.response.status_code == 418
    flow.response.status_code = 419
''')
                events = exchange(target, 419)
                assert [item[0]['details']['http_connect']['envelope']['event'] for item in events] == ['request', 'error'], events
                origin.settimeout(0.1)
                try:
                    connection, _ = origin.accept()
                    connection.close()
                    raise AssertionError('local response contacted target')
                except socket.timeout:
                    pass
                print('PASS: local response, error callback, no target contact')

                deploy('def http_connect(flow): flow.kill()')
                events = exchange(target, None)
                assert len(events) == 1, events
                print('PASS: request kill suppresses outcomes')

                deploy(f'''def http_connect(flow):
    flow.request.host = '127.0.0.1'
    flow.request.port = {target}
''')
                exchange(free_port(), 200)
                origin.settimeout(2)
                connection, _ = origin.accept()
                connection.close()
                print('PASS: reroute changes actual native target')

                deploy('''def http_connect(flow):
    flow.metadata['identity'] = id(flow)
def http_connect_error(flow):
    assert flow.metadata['identity'] == id(flow)
    assert flow.response.status_code == 502
    assert flow.error is None
    assert flow.server_conn.peername is None
    flow.response.status_code = 598
''')
                exchange(free_port(), 598)
                print('PASS: refused target, native 502 observation, mutated wire error')
                deploy('def http_connected(flow): flow.kill()')
                exchange(target, 200)
                connection, _ = origin.accept()
                connection.close()
                deploy('def http_connect_error(flow): flow.kill()')
                exchange(free_port(), 502)
                print('PASS: late outcome kill preserves the prepared wire response')
                mode = 'invalid'
                exchange(target, 200)
                connection, _ = origin.accept()
                connection.close()
                print('PASS: invalid webhook reply is fail-open')

                mode = 'strict-outcome'
                deploy('def http_connect(flow): pass')
                exchange(target, None)
                connection, _ = origin.accept()
                connection.close()
                print('PASS: invalid outcome cannot bypass negotiated strict mode')

                mode = 'forward'
                for body in ('raise ValueError("test callback failure")', 'import time; time.sleep(4)'):
                    deploy('def http_connect(flow): ' + body)
                    exchange(target, 200)
                    connection, _ = origin.accept()
                    connection.close()
                print('PASS: addon exception and worker timeout retain native decision')

                # Hold the already accepted prelude while a deployment changes.
                # Neither setup nor the outcome may attach to the new generation.
                deploy('def http_connect(flow): pass')
                mode = 'hold-request'
                thread_errors = []
                def pending_connect():
                    try:
                        exchange(target, 200)
                    except BaseException as error:
                        thread_errors.append(error)
                pending = threading.Thread(target=pending_connect)
                pending.start()
                assert request_held.wait(5), 'CONNECT did not reach its prelude'
                deploy("""calls = 0
def http_connect(flow):
    global calls
    calls += 1
    flow.metadata['call'] = calls
def http_connected(flow):
    assert 'call' in flow.metadata
    flow.response.status_code = 299
""")
                mode = 'forward'
                release_request.set()
                pending.join(8)
                assert not pending.is_alive() and not thread_errors, thread_errors
                connection, _ = origin.accept()
                connection.close()
                exchange(target, 299)
                connection, _ = origin.accept()
                connection.close()
                print('PASS: redeploy cannot adopt an old CONNECT; new generation handles new flow')

                def concurrent_connect():
                    try:
                        exchange(target, 299)
                    except BaseException as error:
                        thread_errors.append(error)
                workers = [threading.Thread(target=concurrent_connect) for _ in range(8)]
                for worker in workers:
                    worker.start()
                accepted = []
                for _ in workers:
                    connection, _ = origin.accept()
                    accepted.append(connection)
                for worker in workers:
                    worker.join(8)
                for connection in accepted:
                    connection.close()
                assert not thread_errors and all(not worker.is_alive() for worker in workers), thread_errors
                print('PASS: concurrent CONNECT identities remain separate')

                deploy("""connected = False
def http_connect(flow):
    flow.metadata['client'] = id(flow.client_conn)
def http_connected(flow):
    global connected
    connected = True
def request(flow):
    assert connected
    flow.request.headers['x-connect-checked'] = 'yes'
def response(flow):
    flow.response.headers['x-addon-checked'] = 'yes'
""")
                origin_errors = []
                def serve_http():
                    try:
                        upstream, _ = origin.accept()
                        with upstream:
                            upstream.settimeout(5)
                            data = b''
                            while b'\r\n\r\n' not in data:
                                chunk = upstream.recv(4096)
                                assert chunk, data
                                data += chunk
                            assert b'x-connect-checked: yes' in data.lower(), data
                            upstream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDATA')
                    except BaseException as error:
                        origin_errors.append(error)
                http_origin = threading.Thread(target=serve_http)
                http_origin.start()
                with socket.create_connection(('127.0.0.1', proxy_port), timeout=8) as client:
                    client.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\n\r\n'.encode() +
                                   b'GET /inner HTTP/1.1\r\nHost: example.test\r\n\r\n')
                    data = b''
                    while not data.endswith(b'DATA'):
                        chunk = client.recv(4096)
                        assert chunk, data
                        data += chunk
                    assert data.startswith(b'HTTP/1.1 200 '), data
                    assert b'x-addon-checked: yes' in data.lower(), data
                http_origin.join(8)
                assert not http_origin.is_alive() and not origin_errors, origin_errors
                print('PASS: pipelined tunnel bytes reach ordinary HTTP addon hooks after CONNECT')

                if args.broker and args.pam_module:
                    # Authentication remains native authority even when both
                    # request and error hooks explicitly try to replace a 407.
                    proxy.terminate()
                    proxy.wait(timeout=5)
                    user = pwd.getpwuid(os.getuid()).pw_name
                    group = grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name
                    (root / 'test-auth').write_text(
                        f'auth required {args.pam_module}\naccount required {args.pam_module}\n')
                    auth_socket = root / 'auth.sock'
                    broker_config = root / 'broker.cfg'
                    broker_config.write_text(
                        f'socket="{auth_socket}"; pam={{enabled=true; service="test-auth"; '
                        f'allowed_group="{group}"; config_directory="{root}";}};')
                    broker = launch([args.broker, '--config', broker_config], os.environ.copy())
                    deadline = time.monotonic() + 8
                    while not auth_socket.exists():
                        assert broker.poll() is None and time.monotonic() < deadline
                        time.sleep(0.02)
                    # The daemon may save normalized libconfig formatting.
                    # Reuse the original fixture text for this second launch.
                    content = re.sub(r'proxy_authorization\s*=\s*(TRUE|FALSE);', '', content)
                    content = re.sub(r'http_connect\s*=\s*\{\s*\}', '', content)
                    content = content.replace('settings = {',
                        'settings = { http_connect = { proxy_authorization = TRUE; };', 1)
                    config.write_text(content)
                    proxy = launch([args.proxy, '--config-file', config, '--debug',
                                    '--comm-auth', auth_socket], process_env(root))
                    wait_for_listener(proxy, proxy_port)
                    source = """from mitmproxy import http
def http_connect(flow):
    if flow.response is None:
        assert 'proxy-authorization' not in flow.request.headers
    else:
        assert flow.response.status_code == 407
        flow.response = http.Response.make(200)
def http_connect_error(flow):
    assert flow.response.status_code == 407
    flow.response = http.Response.make(200)
def http_connected(flow):
    flow.response.status_code = 299
"""
                    deploy(source)
                    for credentials in (None, user + ':wrong'):
                        events = exchange(target, 407, credentials=credentials)
                        assert all(item[2] == 200 for item in events), events
                        assert [item[0]['details']['http_connect']['envelope']['event'] for item in events] == ['request', 'error']
                        origin.settimeout(0.1)
                        try:
                            connection, _ = origin.accept()
                            connection.close()
                            raise AssertionError('AAA rejection contacted target')
                        except socket.timeout:
                            pass
                    exchange(target, 299, credentials=user + ':test-only-password')
                    origin.settimeout(2)
                    connection, _ = origin.accept()
                    connection.close()
                    print('PASS: missing/wrong AAA cannot be upgraded; accepted credentials are stripped')

                    deploy("""def http_connect(flow):
    if flow.response is not None:
        raise ValueError('Rejected prelude must still be released')
""")
                    events = exchange(target, 407)
                    identity = events[0][0]['id']
                    deadline = time.monotonic() + 8
                    while True:
                        cleanup = [item for item in exchanges if item[0]['id'] == identity and
                                   item[0]['action'] == 'http-connect' and
                                   item[0]['details']['http_connect']['envelope']['event'] == 'abort']
                        if cleanup:
                            assert len(cleanup) == 1 and cleanup[0][2] == 200, cleanup
                            break
                        assert time.monotonic() < deadline, 'Failed prelude was not released'
                        time.sleep(0.05)
                    print('PASS: failed prelude without setup still receives one native cleanup')

        except BaseException:
            if args.starttls_only:
                request = Request(spider_url + '/api/inspection', headers={'X-Spider-Token': token})
                with urlopen(request) as response:
                    (root / 'inspection-failure.json').write_bytes(response.read())
            if os.environ.get('TLS_TEST_DIAGNOSTICS'):
                shutil.copytree(root, os.environ['TLS_TEST_DIAGNOSTICS'], dirs_exist_ok=True)
            for log in logs:
                log.flush()
                log.seek(0)
                print(log.read()[-16000:], file=sys.stderr)
            for native_log in root.glob('messages*'):
                print(native_log.read_text(errors='replace')[-18000:], file=sys.stderr)
            print(json.dumps(exchanges[-12:], indent=2), file=sys.stderr)
            if 'origin_errors' in locals():
                print('Origin errors:', origin_errors, file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            relay.shutdown()
            relay.server_close()
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
