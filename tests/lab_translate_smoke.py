#!/usr/bin/env python3
"""Opt-in live lab smoke: a port-scoped deployment, removed on exit.

Uses an existing lab and its real SOCKS/CONNECT proxy. Never changes traffic
rules or existing deployments; refuses to run alongside enabled scripts.
"""
import argparse
from pathlib import Path
import socket

import hpack
from integration_chain import get_json, post_json
from inspection_h2_test import Oracle, frame
from inspection_translate_push_test import FIELDS, push, header_block
from translate_e2e import receive, receive_frame


SCRIPT = '''
api.state['calls'] = api.state.get('calls', 0) + 1
control = api.info['webhook_control']
assert control['version'] == 1
assert control['sequence'] == api.state['calls']
assert control['mode'] == ('regular' if api.state['calls'] == 1 else 'strict')
for part in api.message.parts:
    if not part.complete:
        api.message.parts.hold_from(part)
        break
    if part.type == PartType.Http2.Header:
        if any(field.name == b'x-fail' for field in part.headers.entries):
            raise ValueError('intentional lab smoke failure')
        if part.frame_type == 5:
            part.headers.set_header(b'x-lab', b'changed')
    if part.type == PartType.Http2.Data:
        part.set_bytes(part.get_bytes().replace(b'secret', b'******'))
return api.message.translate(safety=Safety.MODE)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--backend', default='http://127.0.0.1:18080')
    parser.add_argument('--origin-address', default='10.254.77.1')
    parser.add_argument('--transport', choices=('socks', 'connect'), default='socks')
    parser.add_argument('--proxy-address', default='10.254.77.2')
    parser.add_argument('--proxy-port', type=int, default=1080)
    args = parser.parse_args()
    values = dict(line.split('=', 1) for line in
                  (args.lab / 'state/state.env').read_text().splitlines() if '=' in line)
    token = values['SPIDER_TOKEN'].strip('"\'')
    endpoint = args.backend + '/api/inspection'
    initial = get_json(endpoint, token)
    assert not initial.get('enabled') and not any(x['enabled'] for x in initial.get('chain', [])), \
        'Refusing to alter a lab with enabled inspection scripts'

    for mode in ('Easy', 'Expert'):
        deployment = None
        try:
            with socket.socket() as listener:
                listener.bind((args.origin_address, 0))
                listener.listen(1)
                listener.settimeout(10)
                port = listener.getsockname()[1]
                state = get_json(endpoint, token)
                _, state = post_json(endpoint, {
                    'revision': state['revision'], 'operation': 'deploy',
                    'name': 'Temporary lab Translate ' + mode,
                    'script': SCRIPT.replace('Safety.MODE', 'Safety.' + mode),
                    'scope': 'all', 'instancing': 'flow', 'filter': f'dst port {port}',
                }, token)
                deployment = state['chain'][-1]['id']
                post_json(endpoint, {'revision': state['revision'], 'operation': 'enable',
                                     'id': deployment, 'enabled': True}, token)

                with socket.create_connection((args.proxy_address, args.proxy_port), timeout=10) as client:
                    if args.transport == 'socks':
                        client.sendall(b'\x05\x01\x00')
                        assert receive(client, 2) == b'\x05\x00'
                        client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(args.origin_address) + port.to_bytes(2, 'big'))
                        reply = receive(client, 4)
                        assert reply[:2] == b'\x05\x00', reply
                        assert reply[3] in (1, 4), reply
                        receive(client, (4 if reply[3] == 1 else 16) + 2)
                    else:
                        target = f'{args.origin_address}:{port}'
                        client.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
                        response = bytearray()
                        while not response.endswith(b'\r\n\r\n'):
                            response.extend(receive(client, 1))
                            assert len(response) < 8192
                        assert b' 200 ' in response, bytes(response)
                    origin, _ = listener.accept()
                    with origin:
                        origin.settimeout(10)
                        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                        settings = frame(b'', 4, 0, 0)
                        ack = frame(b'', 4, 1, 0)
                        client.sendall(preface + settings)
                        assert receive(origin, len(preface) + len(settings)) == preface + settings
                        current = get_json(endpoint, token)
                        entry = next(x for x in current['chain'] if x['id'] == deployment)
                        assert entry['runs'] > 0, 'First content did not enter the scoped deployment'
                        assert entry['errors'] == 0, entry.get('last_error', entry)
                        origin.sendall(settings)
                        assert b''.join(receive_frame(client)) == settings
                        client.sendall(ack)
                        assert b''.join(receive_frame(origin)) == ack
                        origin.sendall(ack)
                        assert b''.join(receive_frame(client)) == ack
                        sender, decoder = hpack.Encoder(), Oracle()
                        client.sendall(frame(hpack.Encoder().encode(FIELDS), 1, 5, 1))
                        receive_frame(origin)

                        wire = push(sender.encode(FIELDS), 2, 3)
                        # One incomplete PUSH_PROMISE callback must emit nothing.
                        origin.sendall(wire[:12])
                        client.settimeout(.5)
                        try:
                            leaked = client.recv(1)
                        except socket.timeout:
                            leaked = None
                        assert leaked is None, ('hold leaked bytes', leaked)
                        client.settimeout(10)
                        origin.sendall(wire[12:])
                        first = receive_frame(client)
                        output = b''.join(first)
                        last = first[0]
                        while not last[4] & 4:
                            last, tail = receive_frame(client)
                            output += last + tail
                        assert dict(decoder.decode(header_block(output)))[b'x-lab'] == b'changed'

                        # Real dynamic index after the changed push, same direction.
                        response_fields = [(b':status', b'200'), (b'x-lab', b'original')]
                        indexed = sender.encode(response_fields)
                        assert len(indexed) < 10
                        origin.sendall(frame(indexed, 1, 4, 2))
                        output = b''.join(receive_frame(client))
                        assert decoder.decode(header_block(output)) == response_fields
                        origin.sendall(frame(b'\x02secretpp', 0, 9, 2))
                        assert b''.join(receive_frame(client)) == frame(b'\x02******pp', 0, 9, 2)

                        # Strict failure: no current bytes may reach the client.
                        origin.sendall(frame(sender.encode([(b'x-fail', b'yes')]), 1, 4, 1))
                        try:
                            assert client.recv(1) == b''
                        except ConnectionResetError:
                            pass

                state = get_json(endpoint, token)
                item = next(x for x in state['chain'] if x['id'] == deployment)
                assert item['errors'] == 1, item['errors']
                assert item['runs'] >= 10, item['runs']
                print(f'{mode}: real lab {args.transport}, strict sequence, PUSH_PROMISE/hold/indexes/DATA '
                      f'and fail-closed OK ({item["runs"]} runs, 1 intentional error)', flush=True)
        finally:
            if deployment is not None:
                state = get_json(endpoint, token)
                post_json(endpoint, {'revision': state['revision'], 'operation': 'remove',
                                     'id': deployment}, token)


if __name__ == '__main__':
    main()
