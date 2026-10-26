#!/usr/bin/env python3
"""Real SOCKS proxy + Spider + controlled cleartext H2 peers on loopback.

Only lease discovery uses the existing fake management API. Content callbacks
travel directly from the real Smithproxy process to the real Spider process.
No live configuration, external endpoints or lab instance are used.
"""
import argparse
import contextlib
import os
from pathlib import Path
import socket
import select
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

import hpack

from fake_smithproxy import Handler
from inspection_h2_test import Oracle, frame
from integration_chain import get_json, post_json


SCRIPT = '''
api.state['callbacks'] = api.state.get('callbacks', 0) + 1
control = api.info['webhook_control']
assert control['version'] == 1
assert control['sequence'] == api.state['callbacks']
assert control['mode'] == ('regular' if control['sequence'] == 1 else 'strict')
for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break
    if part.type != PartType.Http2.Header:
        continue
    if any(field.name == b'x-fail' for field in part.headers.entries):
        raise ValueError('intentional E2E failure')
    key = 'headers_' + api.side
    count = api.state.get(key, 0) + 1
    api.state[key] = count
    if count == 2:
        part.headers.set_header(b'x-lab', b'changed-' + api.side.encode())
api.print(api.side, api.state['callbacks'])
return api.message.translate()
'''


def receive(sock, count):
    data = bytearray()
    sock.settimeout(5)
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            raise AssertionError(f'Unexpected EOF: {len(data)}/{count}')
        data.extend(block)
    return bytes(data)


def receive_frame(sock):
    head = receive(sock, 9)
    return head, receive(sock, int.from_bytes(head[:3], 'big'))


def receive_headers(sock):
    head, data = receive_frame(sock)
    last = head

    while not last[4] & 4:
        last, tail = receive_frame(sock)
        assert last[3] == 9 and last[5:] == head[5:]
        data += tail

    return head, data


def wait_until(check, processes):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        assert all(p.poll() is None for p in processes), 'Child process exited'
        try:
            if check():
                return
        except OSError:
            pass
        time.sleep(.05)
    raise AssertionError('Startup timeout')


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def windows_exchange(client, origin):
    """Real peers enforce flow control; only their WINDOW_UPDATEs release queues."""
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, StreamEnded

    sockets = {'L': client, 'R': origin}
    peers = {side: H2Connection(H2Configuration(client_side=side == 'L')) for side in sockets}
    received = {'L': {}, 'R': {}}
    ended = set()

    def send(side):
        data = peers[side].data_to_send()
        if data:
            sockets[side].sendall(data)

    def progress(done):
        deadline = time.monotonic() + 10
        while not done():
            if time.monotonic() > deadline:
                raise AssertionError('Window translation stalled without new source DATA')
            ready, _, _ = select.select(list(sockets.values()), [], [], .1)
            for sock in ready:
                side = next(key for key, value in sockets.items() if value is sock)
                data = sock.recv(65536)
                assert data, 'Unexpected EOF during window translation'
                for event in peers[side].receive_data(data):
                    if isinstance(event, DataReceived):
                        received[side].setdefault(event.stream_id, bytearray()).extend(event.data)
                        peers[side].acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if isinstance(event, StreamEnded):
                        ended.add((side, event.stream_id))
                send(side)

    for side, peer in peers.items():
        peer.initiate_connection()
        send(side)

    for stream, value, expected in ((1, b'secret', b'z' * 160000), (3, b'delete', b''),
                                     (5, b'unchanged', b'unchanged')):
        for side, target in (('L', 'R'), ('R', 'L')):
            fields = ([(b':method', b'POST'), (b':scheme', b'http'),
                       (b':authority', b'lab.test'), (b':path', b'/')]
                      if side == 'L' else [(b':status', b'200')])
            fields.append((b'content-length', str(len(value)).encode()))
            peers[side].send_headers(stream, fields)
            peers[side].send_data(stream, value, end_stream=True)
            send(side)
            progress(lambda: (target, stream) in ended)
            assert bytes(received[target].get(stream, b'')) == expected

    print('PASS: real H2 peers, both directions, expansion beyond windows, shrink-to-zero, '
          'Content-Length repair, subsequent stream and reverse-only progress')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--smithproxy-source', type=Path, required=True)
    parser.add_argument('--smithproxy', type=Path, required=True)
    parser.add_argument('--spider', type=Path, required=True)
    parser.add_argument('--failure', choices=('exception', 'missing-translate'), default='exception')
    parser.add_argument('--fragmented', action='store_true', help='Split HEADERS/CONTINUATION into single-byte callbacks')
    parser.add_argument('--settings', action='store_true', help='Exercise acknowledged table eviction and growth in both directions')
    parser.add_argument('--policy', action='store_true', help='Enforce zero capacity after handshake, including synthetic ACK consumption')
    parser.add_argument('--data', action='store_true', help='Rewrite padded same-length DATA in both directions')
    parser.add_argument('--windows', action='store_true', help='Real H2 peers with length-changing bodies and reverse credit')
    parser.add_argument('--safety', choices=('easy', 'expert'), default='easy')
    args = parser.parse_args()
    source = args.smithproxy_source.resolve()
    sys.path.insert(0, str(source / 'tests/tls'))
    from starttls_socks_integration import ADDRESSES, free_port, make_config, socks_connect

    with tempfile.TemporaryDirectory(prefix='translate-e2e-') as directory, contextlib.ExitStack() as cleanup:
        runtime = Path(directory)
        processes = []
        logs = []
        discovery = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cleanup.callback(discovery.server_close)
        cleanup.callback(discovery.shutdown)
        threading.Thread(target=discovery.serve_forever, daemon=True).start()
        Handler.callback = None
        spider_port, proxy_port = free_port(), free_port()
        base = f'http://127.0.0.1:{spider_port}'

        def launch(command, name, env, cwd):
            log = cleanup.enter_context(open(runtime / (name + '.log'), 'w+'))
            logs.append((name, log))
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            cleanup.callback(stop, process)
            return process

        try:
            launch([str(args.spider.resolve()), '--bind', '127.0.0.1', '--port', str(spider_port),
                    '--smithproxy-url', f'http://127.0.0.1:{discovery.server_port}'], 'spider',
                   {**os.environ, 'SPIDER_TOKEN': 'frontend-key', 'SPIDER_SMITHPROXY_KEY': 'integration-key',
                    'SPIDER_COLLECTION_DIR': str(runtime / 'collections')}, runtime)
            wait_until(lambda: Handler.callback and get_json(base + '/api/health'), processes)
            inspection = base + '/api/inspection'
            state = get_json(inspection, 'frontend-key')
            script = ("if api.phase == 'setup':\n"
                      "    api.connection.request_rewrite()\n"
                      "    return\n" + SCRIPT)
            script = script.replace('return api.message.translate()',
                                    f'return api.message.translate(safety=Safety.{args.safety.title()})')
            if args.windows:
                script = ("if api.phase == 'setup':\n"
                          "    api.connection.request_rewrite()\n    return\n"
                          "assert api.info['webhook_control']['content-reverse']\n"
                          "for part in api.message.parts:\n"
                          "    if not part.complete or (part.type == PartType.Http2.Header and part.content.complete is False):\n"
                          "        api.message.parts.hold_from(part)\n        break\n"
                          "    if part.type == PartType.Http2.Data:\n"
                          "        if part.get_bytes() == b'secret':\n            part.set_bytes(b'z' * 160000)\n"
                          "        elif part.get_bytes() == b'delete':\n            part.set_bytes(b'')\n"
                          f"return api.message.translate(safety=Safety.{args.safety.title()})\n")
            if args.data:
                script = script.replace('    if part.type != PartType.Http2.Header:',
                    '    if part.type == PartType.Http2.Data:\n'
                    '        part.set_bytes(part.get_bytes().replace(b"secret", b"******"))\n'
                    '    if part.type != PartType.Http2.Header:')
            if args.policy:
                script = script.replace("control = api.info", "api.connection.set_mode(Mode.Translate)\n"
                    "if api.state['callbacks'] >= 5:\n"
                    "    api.connection.http2.enforce_header_table_limit(0)\ncontrol = api.info")
            if args.failure == 'missing-translate':
                script = script.replace("raise ValueError('intentional E2E failure')", 'return None')
            _, state = post_json(inspection, {
                'revision': state['revision'], 'operation': 'deploy', 'name': 'H2 E2E',
                'script': script, 'scope': 'all', 'instancing': 'flow',
            }, 'frontend-key')
            post_json(inspection, {'revision': state['revision'], 'operation': 'enable',
                                  'id': state['chain'][-1]['id'], 'enabled': True}, 'frontend-key')

            config = runtime / 'smithproxy.cfg'
            make_config(source / 'etc/smithproxy.cfg', config, source, runtime, proxy_port, free_port())
            text = config.read_text().replace('settings = {',
                'settings = {\n webhook = { enabled = true; tls_verify = false; '
                f'url = "{Handler.callback}"; }};', 1)
            text = text.replace('        write_payload = FALSE;',
                                '        write_payload = FALSE; webhook_enable = TRUE; webhook_lock_traffic = FALSE;', 1)
            config.write_text(text)
            launch([str(args.smithproxy.resolve()), '--config-file', str(config), '--diagnose'],
                   'proxy', {**os.environ, 'SMITHPROXY_PID_FILE': str(runtime / 'proxy.pid')}, source)

            def listening():
                with socket.create_connection(('127.0.0.1', proxy_port), timeout=.1):
                    return True

            wait_until(listening, processes)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen()
                listener.settimeout(5)
                with socks_connect(proxy_port, listener.getsockname()[1], ADDRESSES['ipv4-ip']) as client:
                    origin, _ = listener.accept()
                    with origin:
                        if args.windows:
                            windows_exchange(client, origin)
                            status = get_json(inspection, 'frontend-key')
                            state = status['chain'][0]
                            assert state['errors'] == 0, state
                            assert state['last_result']['flow_control']['pending_bytes'] == 0, state
                            assert 'replacement_reverse' not in state['last_result']
                            assert all('replacement_reverse' not in item and 'translate_control' not in item
                                       for item in status['recent'])
                            return
                        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                        settings = frame(b'', 4, 0, 0)
                        client.sendall(preface + settings)
                        assert receive(origin, len(preface)) == preface
                        assert b''.join(receive_frame(origin)) == settings
                        origin.sendall(settings)
                        assert b''.join(receive_frame(client)) == settings
                        ack = frame(b'', 4, 1, 0)
                        for sender, receiver in ((client, origin), (origin, client)):
                            sender.sendall(ack)
                            assert b''.join(receive_frame(receiver)) == ack

                        encoders = [hpack.Encoder(), hpack.Encoder()]
                        decoders = [Oracle(), Oracle()]
                        header_callbacks = 0
                        settings_callbacks = 0

                        if args.policy:
                            trigger = frame(b'policy00', 6, 0, 0)
                            zero = frame(b'\x00\x01\x00\x00\x00\x00', 4, 0, 0)
                            client.sendall(trigger)
                            assert b''.join(receive_frame(origin)) == trigger
                            assert b''.join(receive_frame(origin)) == zero
                            origin.sendall(ack)
                            # The synthetic ACK disappears; only opposite SETTINGS arrives.
                            assert b''.join(receive_frame(client)) == zero
                            client.sendall(ack)
                            wait_until(lambda: get_json(inspection, 'frontend-key')['chain'][0]['runs'] == 8,
                                       processes)
                            for encoder in encoders:
                                encoder.header_table_size = 0
                            settings_callbacks += 3

                        def send_headers(sender, receiver, block, stream):
                            nonlocal header_callbacks
                            end_stream = 0 if args.data else 1
                            if not args.fragmented:
                                header_callbacks += 1
                                sender.sendall(frame(block, 1, 4 | end_stream, stream))
                                return

                            # Emit a complete prefix while retaining a partial frame.
                            split = max(1, len(block) // 2)
                            wire = frame(block[:split], 1, end_stream, stream) + frame(block[split:], 9, 4, stream)
                            header_callbacks += len(wire) + 1  # First byte, remainder, opposite ACK.
                            prefix = frame(b'12345678', 6, 0, 0)
                            sender.sendall(prefix + wire[:1])
                            assert b''.join(receive_frame(receiver)) == prefix

                            # The other direction still runs while this one holds.
                            reply = frame(b'12345678', 6, 1, 0)
                            receiver.sendall(reply)
                            assert b''.join(receive_frame(sender)) == reply

                            # Wait for each callback before the next byte so TCP
                            # coalescing cannot turn this into a whole-frame test.
                            for index in range(1, len(wire)):
                                before = get_json(inspection, 'frontend-key')['chain'][0]['runs']
                                sender.sendall(wire[index:index + 1])
                                wait_until(lambda: get_json(inspection, 'frontend-key')['chain'][0]['runs'] > before,
                                           processes)

                                if index < len(wire) - 1:
                                    receiver.settimeout(.01)
                                    try:
                                        leaked = receiver.recv(1)
                                    except socket.timeout:
                                        continue
                                    raise AssertionError(f'Incomplete header block leaked {leaked!r}')

                        for turn in range(1, 5):
                            if args.settings and turn > 1:
                                capacity = {2: 0, 3: 128, 4: 8192}[turn]
                                update = frame(b'\x00\x01' + capacity.to_bytes(4, 'big'), 4, 0, 0)

                                for sender, receiver, encoder, decoder in zip(
                                        (client, origin), (origin, client), encoders, decoders):
                                    receiver.sendall(update)
                                    assert b''.join(receive_frame(sender)) == update
                                    sender.sendall(ack)
                                    assert b''.join(receive_frame(receiver)) == ack
                                    encoder.header_table_size = capacity
                                    decoder.resize(capacity)
                                    settings_callbacks += 2

                            stream = 2 * turn - 1
                            for side, sender, receiver, encoder, decoder in zip(
                                    ('L', 'R'), (client, origin), (origin, client), encoders, decoders):
                                fields = ([(b':method', b'GET'), (b':scheme', b'http'),
                                           (b':authority', b'lab.test'), (b':path', b'/')]
                                          if side == 'L' else [(b':status', b'200')])
                                if args.data:
                                    fields += [(b'content-length', b'6')]
                                fields += [(b'x-lab', b'original')]
                                block = encoder.encode(fields, huffman=False)
                                if turn > 1 and not args.settings and not args.policy:
                                    assert block[-1:] == b'\xbe', 'Expected indexed x-lab'
                                send_headers(sender, receiver, block, stream)
                                head, body = receive_headers(receiver)
                                assert head[3] == 1 and bool(head[4] & 1) == (not args.data)
                                assert int.from_bytes(head[5:], 'big') == stream
                                expected = fields[:-1] + [(b'x-lab', b'changed-' + side.encode()
                                                           if turn == 2 else b'original')]
                                assert decoder.decode(body) == expected
                                if args.data:
                                    sender.sendall(frame(b'\x02secretpp', 0, 9, stream))
                                    assert b''.join(receive_frame(receiver)) == frame(b'\x02******pp', 0, 9, stream)
                                    # END_STREAM needs connection credit only; no stream grant.
                                    assert b''.join(receive_frame(sender)) == frame((9).to_bytes(4, 'big'), 8, 0, 0)

                        # Control-only callbacks must execute too, not just HEADERS.
                        ping = frame(b'12345678', 6, 0, 0)
                        client.sendall(ping)
                        assert b''.join(receive_frame(origin)) == ping
                        pong = frame(b'12345678', 6, 1, 0)
                        origin.sendall(pong)
                        assert b''.join(receive_frame(client)) == pong
                        state = get_json(inspection, 'frontend-key')['chain'][0]
                        expected_runs = 4 + header_callbacks + settings_callbacks + 2 + (8 if args.data else 0)
                        assert state['runs'] == expected_runs + 1, state  # Plus setup.
                        assert state['errors'] == 0, state
                        assert state['last_result']['logs'] == [f'R {expected_runs}'], state

                        # Failure must be observed at the peer socket, not just in logs.
                        fields = [(b':method', b'GET'), (b':scheme', b'http'),
                                  (b':authority', b'lab.test'), (b':path', b'/'), (b'x-fail', b'yes')]
                        client.sendall(frame(encoders[0].encode(fields), 1, 5, 9))
                        origin.settimeout(5)
                        try:
                            leaked = origin.recv(1)
                        except ConnectionResetError:
                            leaked = b''
                        assert leaked == b'', f'Failed callback leaked {leaked!r}'
                        state = get_json(inspection, 'frontend-key')
                        assert state['chain'][0]['errors'] == 1
                        assert state['chain'][0]['runs'] == expected_runs + 2
                        print(f'PASS: bidirectional indices, {expected_runs} explicit callbacks, strict {args.failure} with no leak')
        except BaseException:
            for name, log in logs:
                log.flush()
                log.seek(0)
                print(f'--- {name} ---\n{log.read()[-16000:]}', file=sys.stderr)
            raise


if __name__ == '__main__':
    main()
