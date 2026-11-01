#!/usr/bin/env python3
"""Exercise H1 interception through real Smithproxy and Spider processes.

Only management lease discovery is simulated. Native producer annotations,
content webhooks, addon execution and forwarded bytes use the real processes.
All listeners and configuration belong to a temporary loopback test instance.
"""

import argparse
import contextlib
import gzip
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


ENCODED_ADDON = '''#!mitmproxy
saved = None

def responseheaders(flow):
    print('response headers ' + flow.request.path)

def response(flow):
    global saved

    print('response ' + flow.request.path)
    if flow.request.path == '/first':
        assert flow.response.content == b'original compressed body'
        assert flow.response.trailers['x-end'] == 'original'
        saved = flow
        flow.intercept()

def request(flow):
    print('request ' + flow.request.path)
    if flow.request.path == '/release':
        # The old trailer describes the old entity and cannot survive an edit.
        saved.response.trailers = None
        saved.response.content = b'edited compressed body with a different length'
        saved.resume()
'''

RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'


def request(path, resumed=False):
    wire = b'GET ' + path.encode('ascii') + b' HTTP/1.1\r\nHost: test\r\n'
    if resumed:
        wire += b'x-resumed: yes\r\n'
    return wire + b'\r\n'


def expect_silent(sock, context='Paused lane'):
    # Complete messages wait for hook completion; incomplete fragments have no hook.
    sock.settimeout(0.15)
    try:
        data = sock.recv(1)
    except socket.timeout:
        return
    raise AssertionError(f'{context} leaked or closed: {data!r}')


def expect_closed(sock):
    sock.settimeout(5)
    try:
        data = sock.recv(1)
    except ConnectionResetError:
        return
    assert data == b'', f'Killed connection leaked bytes: {data!r}'


def read_line(sock):
    line = bytearray()
    while not line.endswith(b'\r\n'):
        line.extend(receive(sock, 1))
        assert len(line) <= 8192, 'HTTP line exceeded the test limit'
    return bytes(line)


def check_encoded_response(client):
    # Read exactly one response so a reordered or duplicated pipeline member
    # cannot disappear into a buffered reader used only for this assertion.
    assert read_line(client) == b'HTTP/1.1 200 OK\r\n'
    headers = {}
    while True:
        line = read_line(client)
        if line == b'\r\n':
            break
        name, value = line.rstrip(b'\r\n').split(b':', 1)
        headers[name.lower()] = value.strip().lower()

    assert headers[b'content-encoding'] == b'gzip', headers
    assert headers[b'transfer-encoding'] == b'chunked', headers
    assert b'content-length' not in headers, headers
    assert b'trailer' not in headers, headers

    body = bytearray()
    while True:
        size = int(read_line(client).split(b';', 1)[0].strip(), 16)
        if size == 0:
            break
        assert 0 < size <= 65536, 'Unexpected response chunk size'
        body.extend(receive(client, size))
        assert receive(client, 2) == b'\r\n'

    assert read_line(client) == b'\r\n', 'Obsolete trailers survived the edit'
    assert gzip.decompress(body) == b'edited compressed body with a different length'


def exercise_encoded(client, origin, wait_for_log):
    requests = request('/first') + request('/second')
    client.sendall(requests)
    assert receive(origin, len(requests)) == requests

    compressed = gzip.compress(b'original compressed body', mtime=0)
    head = (b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n'
            b'Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n')
    size = format(len(compressed), 'x').encode('ascii')
    chunk = size + b';source=test\r\n' + compressed
    wire = head + chunk + b'\r\n0\r\nX-End: original\r\n'
    origin.sendall(wire)
    wait_for_log('response headers /first')
    expect_silent(client)

    # The zero chunk alone cannot complete a message with pending trailers.
    origin.sendall(b'\r\n' + RESPONSE)
    wait_for_log('response /first')
    expect_silent(client)

    # A request callback releases the edited response and the younger response
    # together through the native reverse output path.
    release = request('/release')
    client.sendall(release)
    assert receive(origin, len(release)) == release
    check_encoded_response(client)
    assert receive(client, len(RESPONSE)) == RESPONSE

    origin.sendall(RESPONSE)
    assert receive(client, len(RESPONSE)) == RESPONSE
    expect_silent(client)


def exercise_suspension(client, origin, scenario, wait_for_log, connect):
    # Establish a real outstanding response before pausing a later
    # request. That response supplies a valid peer callback.
    client.sendall(request('/first'))
    assert receive(origin, len(request('/first'))) == request('/first')

    held = request('/wait')
    if scenario == 'fragmented':
        # Keep the message incomplete at the start line, header
        # name and final CRLF boundaries across separate writes.
        header_split = held.index(b'Host:') + 2
        fragments = (held[:2], held[2:header_split], held[header_split:-1])
        for fragment in fragments:
            client.sendall(fragment)
            expect_silent(origin, context='Incomplete request header')
        client.sendall(held[-1:] + request('/younger'))
    else:
        suffix = request('/younger')
        if scenario == 'pipeline':
            suffix += request('/third') + request('/fourth')
        client.sendall(held + suffix)

    wait_for_log('request /wait')
    expect_silent(origin)
    origin.sendall(RESPONSE)

    if scenario == 'kill':
        expect_closed(client)
        expect_closed(origin)
    else:
        expected_requests = request('/wait', resumed=True) + request('/younger')
        if scenario == 'pipeline':
            expected_requests += request('/third') + request('/fourth')

        if scenario == 'both':
            wait_for_log('response paused')
            expect_silent(client)
            expect_silent(origin)

            # Another connection changes public resume intent only.
            # Publication still needs a callback on the owning one.
            controller, control_origin = connect()
            controller.sendall(request('/release'))
            assert receive(control_origin, len(request('/release'))) == request('/release')
            expect_silent(client)
            expect_silent(origin)
            client.sendall(request('/after'))
            expected_requests += request('/after')

        assert receive(client, len(RESPONSE)) == RESPONSE
        assert receive(origin, len(expected_requests)) == expected_requests
        count = 3 if scenario == 'both' else 2
        if scenario == 'pipeline':
            count = 4

        # Distinct bodies make response swaps and duplication visible.
        replies = b''
        for index in range(count):
            body = str(index).encode('ascii')
            replies += b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n' + body
        origin.sendall(replies)
        assert receive(client, len(replies)) == replies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--smithproxy-source', type=Path, required=True)
    parser.add_argument('--smithproxy', type=Path, required=True)
    parser.add_argument('--spider', type=Path, required=True)
    parser.add_argument(
        '--scenario', default='peer',
        choices=('peer', 'both', 'kill', 'fragmented', 'pipeline', 'encoded'))
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
                mode = args.scenario
                if mode in ('fragmented', 'pipeline'):
                    mode = 'peer'
                script = ADDON.replace('waiting = None', f'MODE = {mode!r}\nwaiting = None', 1)
                if args.scenario == 'encoded':
                    script = ENCODED_ADDON
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
                def connect():
                    client = cleanup.enter_context(
                        socks_connect(proxy_port, target_port, ADDRESSES['ipv4-ip']))
                    origin = cleanup.enter_context(listener.accept()[0])
                    return client, origin

                client, origin = connect()

                if args.scenario == 'encoded':
                    exercise_encoded(client, origin, wait_for_log)
                else:
                    exercise_suspension(client, origin, args.scenario, wait_for_log, connect)

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
