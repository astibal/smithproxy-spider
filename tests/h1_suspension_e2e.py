#!/usr/bin/env python3
"""Exercise H1 interception through real Smithproxy and Spider processes.

Only management lease discovery is simulated. Native producer annotations,
content webhooks, addon execution and forwarded bytes use the real processes.
All listeners and configuration belong to a temporary loopback test instance.
"""

import argparse
import contextlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

from fake_smithproxy import Handler
from integration_chain import get_json, post_json
from translate_e2e import receive, stop, wait_until


ADDON = '''#!mitmproxy
waiting = None
responding = None

def request(flow):
    global waiting

    print('request ' + flow.request.path)

    if flow.request.path == '/wait':
        waiting = flow
        flow.intercept()
    elif flow.request.path == '/release':
        waiting.request.headers['x-resumed'] = 'yes'
        waiting.resume()
        responding.resume()

def responseheaders(flow):
    global responding

    if MODE == 'both' and flow.request.path == '/first':
        responding = flow
        flow.intercept()
        print('response paused')

def response(flow):
    print('response ' + flow.request.path)

    if flow.request.path != '/first':
        return

    if MODE == 'peer':
        waiting.request.headers['x-resumed'] = 'yes'
        waiting.resume()
    elif MODE == 'kill':
        waiting.kill()
'''

RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'


def request(path, resumed=False):
    wire = b'GET ' + path.encode('ascii') + b' HTTP/1.1\r\nHost: test\r\n'
    if resumed:
        wire += b'x-resumed: yes\r\n'
    return wire + b'\r\n'


def expect_silent(sock):
    # Called only after the host confirms that the relevant hook completed.
    sock.settimeout(0.15)
    try:
        data = sock.recv(1)
    except socket.timeout:
        return
    raise AssertionError(f'Paused lane leaked or closed: {data!r}')


def expect_closed(sock):
    sock.settimeout(5)
    try:
        data = sock.recv(1)
    except ConnectionResetError:
        return
    assert data == b'', f'Killed connection leaked bytes: {data!r}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--smithproxy-source', type=Path, required=True)
    parser.add_argument('--smithproxy', type=Path, required=True)
    parser.add_argument('--spider', type=Path, required=True)
    parser.add_argument('--scenario', choices=('peer', 'both', 'kill'), default='peer')
    args = parser.parse_args()
    source = args.smithproxy_source.resolve()
    sys.path.insert(0, str(source / 'tests/tls'))
    from starttls_socks_integration import ADDRESSES, free_port, make_config, socks_connect

    with tempfile.TemporaryDirectory(prefix='h1-suspension-e2e-') as directory:
        with contextlib.ExitStack() as cleanup:
            runtime = Path(directory)
            processes = []
            logs = []
            discovery = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            cleanup.callback(discovery.server_close)
            cleanup.callback(discovery.shutdown)
            Handler.callback = None
            threading.Thread(target=discovery.serve_forever, daemon=True).start()
            spider_port = free_port()
            proxy_port = free_port()
            base = f'http://127.0.0.1:{spider_port}'
            inspection = base + '/api/inspection'

            def launch(command, name, environment, cwd):
                log = cleanup.enter_context(open(runtime / (name + '.log'), 'w+'))
                logs.append((name, log))
                process = subprocess.Popen(
                    command, cwd=cwd, env=environment, stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                cleanup.callback(stop, process)

            def wait_for_log(message):
                def observed():
                    state = get_json(inspection, 'frontend-key')['chain'][0]
                    assert state['errors'] == 0, state['last_result']
                    return message in state['last_result'].get('logs', [])

                wait_until(observed, processes)

            try:
                launch([
                    str(args.spider.resolve()), '--bind', '127.0.0.1',
                    '--port', str(spider_port), '--smithproxy-url',
                    f'http://127.0.0.1:{discovery.server_port}',
                ], 'spider', {
                    **os.environ,
                    'SPIDER_TOKEN': 'frontend-key',
                    'SPIDER_SMITHPROXY_KEY': 'integration-key',
                    'SPIDER_COLLECTION_DIR': str(runtime / 'collections'),
                }, runtime)
                wait_until(lambda: Handler.callback and get_json(base + '/api/health'), processes)

                state = get_json(inspection, 'frontend-key')
                script = ADDON.replace('waiting = None', f'MODE = {args.scenario!r}\nwaiting = None', 1)
                _, state = post_json(inspection, {
                    'revision': state['revision'], 'operation': 'deploy',
                    'name': 'H1 suspension E2E', 'script': script,
                    'script_api': 'mitmproxy', 'scope': 'all', 'instancing': 'flow',
                }, 'frontend-key')
                post_json(inspection, {
                    'revision': state['revision'], 'operation': 'enable',
                    'id': state['chain'][-1]['id'], 'enabled': True,
                }, 'frontend-key')

                config = runtime / 'smithproxy.cfg'
                make_config(source / 'etc/smithproxy.cfg', config, source, runtime, proxy_port, free_port())
                text = config.read_text().replace(
                    'settings = {',
                    'settings = {\n webhook = { enabled = true; tls_verify = false; '
                    f'url = "{Handler.callback}"; }};', 1)
                text = text.replace(
                    '        write_payload = FALSE;',
                    '        write_payload = FALSE; webhook_enable = TRUE; webhook_lock_traffic = FALSE;', 1)
                config.write_text(text)
                launch([
                    str(args.smithproxy.resolve()), '--config-file', str(config), '--diagnose',
                ], 'proxy', {
                    **os.environ, 'SMITHPROXY_PID_FILE': str(runtime / 'proxy.pid'),
                }, source)

                def listening():
                    with socket.create_connection(('127.0.0.1', proxy_port), timeout=0.1):
                        return True

                wait_until(listening, processes)
                listener = cleanup.enter_context(socket.socket())
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                listener.settimeout(5)
                target_port = listener.getsockname()[1]
                client = cleanup.enter_context(
                    socks_connect(proxy_port, target_port, ADDRESSES['ipv4-ip']))
                origin = cleanup.enter_context(listener.accept()[0])

                # Establish a real outstanding response before pausing a later
                # request. That response supplies a valid peer callback.
                client.sendall(request('/first'))
                assert receive(origin, len(request('/first'))) == request('/first')
                client.sendall(request('/wait') + request('/younger'))
                wait_for_log('request /wait')
                expect_silent(origin)
                origin.sendall(RESPONSE)

                if args.scenario == 'kill':
                    expect_closed(client)
                    expect_closed(origin)
                else:
                    expected_requests = request('/wait', resumed=True) + request('/younger')
                    if args.scenario == 'both':
                        wait_for_log('response paused')
                        expect_silent(client)
                        expect_silent(origin)

                        # Another connection changes public resume intent only.
                        # Publication still needs a callback on the owning one.
                        controller = cleanup.enter_context(
                            socks_connect(proxy_port, target_port, ADDRESSES['ipv4-ip']))
                        control_origin = cleanup.enter_context(listener.accept()[0])
                        controller.sendall(request('/release'))
                        assert receive(control_origin, len(request('/release'))) == request('/release')
                        expect_silent(client)
                        expect_silent(origin)
                        client.sendall(request('/after'))
                        expected_requests += request('/after')

                    assert receive(client, len(RESPONSE)) == RESPONSE
                    assert receive(origin, len(expected_requests)) == expected_requests
                    count = 3 if args.scenario == 'both' else 2
                    replies = RESPONSE * count
                    origin.sendall(replies)
                    assert receive(client, len(replies)) == replies

                state = get_json(inspection, 'frontend-key')['chain'][0]
                assert state['errors'] == 0, state['last_result']
                print(f'PASS: real H1 {args.scenario} suspension, native annotations and peer-visible output')
            except BaseException:
                for name, log in logs:
                    log.flush()
                    log.seek(0)
                    print(f'--- {name} ---\n{log.read()[-16000:]}', file=sys.stderr)
                raise


if __name__ == '__main__':
    main()
