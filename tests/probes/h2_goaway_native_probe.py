"""Exercise native GOAWAY replacement between independent TLS/ALPN H2 peers.

This optional loopback probe uses the production Translate model as a byte
bridge. It does not import mitmproxy or use its runtime. The caller supplies a
disposable certificate and private key.
"""

import argparse
import json
from pathlib import Path
import select
import socket
import ssl
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))

from inspection_api import Connection
from inspection_translate_windows_test import Bridge
from probes.h2_goaway_probe import goaway_frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--private-key', required=True)
    args = parser.parse_args()

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(args.certificate, args.private_key)
    server_context.set_alpn_protocols(['h2'])
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.set_alpn_protocols(['h2'])

    failures = []
    origin_requests = []
    selected_streams = []

    with socket.socket() as origin_listener, socket.socket() as bridge_listener:
        for listener in (origin_listener, bridge_listener):
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(6)
        origin_port = origin_listener.getsockname()[1]
        bridge_port = bridge_listener.getsockname()[1]

        def serve_origin():
            try:
                raw, _ = origin_listener.accept()
                with server_context.wrap_socket(raw, server_side=True) as connection:
                    if connection.selected_alpn_protocol() != 'h2':
                        raise AssertionError('Origin ALPN did not negotiate h2')
                    peer = h2.connection.H2Connection(
                        h2.config.H2Configuration(client_side=False))
                    peer.initiate_connection()
                    connection.sendall(peer.data_to_send())
                    ended = []
                    while len(ended) < 2:
                        for event in peer.receive_data(connection.recv(65535)):
                            if isinstance(event, h2.events.RequestReceived):
                                origin_requests.append(event.stream_id)
                            elif isinstance(event, h2.events.StreamEnded):
                                ended.append(event.stream_id)
                        pending = peer.data_to_send()
                        if pending:
                            connection.sendall(pending)
                    peer.send_headers(1, [(b':status', b'200')], end_stream=True)
                    wire = peer.data_to_send() + goaway_frame(1, 0)
                    connection.sendall(wire)
                    time.sleep(.25)
            except BaseException as error:
                failures.append(('origin', repr(error)))

        def serve_bridge():
            try:
                client_raw, _ = bridge_listener.accept()
                with server_context.wrap_socket(client_raw, server_side=True) as client_side:
                    if client_side.selected_alpn_protocol() != 'h2':
                        raise AssertionError('Client-facing ALPN did not negotiate h2')
                    origin_raw = socket.create_connection(
                        ('127.0.0.1', origin_port), timeout=4)
                    with client_context.wrap_socket(
                            origin_raw, server_hostname='localhost') as origin_side:
                        if origin_side.selected_alpn_protocol() != 'h2':
                            raise AssertionError('Origin-facing ALPN did not negotiate h2')
                        client_side.setblocking(False)
                        origin_side.setblocking(False)
                        bridge = Bridge()
                        sockets = {client_side: 'L', origin_side: 'R'}
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            readable, _, _ = select.select(tuple(sockets), (), (), .1)
                            if not readable:
                                continue
                            for source in readable:
                                try:
                                    wire = source.recv(65535)
                                except ssl.SSLWantReadError:
                                    continue
                                if not wire:
                                    return
                                side = sockets[source]

                                def replace_goaway(message):
                                    anchors = [part for part in message.parts
                                               if part.complete and part.frame_type == 7]
                                    if not anchors:
                                        return
                                    selected_streams.extend(
                                        Connection(message).http2.fail_pending_requests(
                                            anchors[0],
                                            status=502,
                                            headers=[(b'content-type', b'text/plain')],
                                            body=b'upstream connection closed',
                                        )
                                    )

                                edit = replace_goaway if side == 'R' else None
                                forward, reverse = bridge.feed(side, wire, edit)
                                target = origin_side if side == 'L' else client_side
                                if forward:
                                    target.sendall(forward)
                                if reverse:
                                    source.sendall(reverse)
            except BaseException as error:
                failures.append(('bridge', repr(error)))

        origin_thread = threading.Thread(target=serve_origin, daemon=True)
        bridge_thread = threading.Thread(target=serve_bridge, daemon=True)
        origin_thread.start()
        bridge_thread.start()

        raw = socket.create_connection(('127.0.0.1', bridge_port), timeout=4)
        statuses = []
        bodies = {}
        terminations = []
        with client_context.wrap_socket(raw, server_hostname='localhost') as connection:
            assert connection.selected_alpn_protocol() == 'h2'
            connection.settimeout(4)
            peer = h2.connection.H2Connection()
            peer.initiate_connection()
            for stream in (1, 3):
                peer.send_headers(stream, [
                    (b':method', b'GET'),
                    (b':scheme', b'https'),
                    (b':authority', b'origin.test'),
                    (b':path', f'/{stream}'.encode('ascii')),
                ], end_stream=True)
            connection.sendall(peer.data_to_send())
            ended = set()
            while len(ended) < 2:
                data = connection.recv(65535)
                if not data:
                    break
                for event in peer.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        statuses.append([
                            event.stream_id,
                            dict(event.headers)[b':status'].decode('ascii'),
                        ])
                    elif isinstance(event, h2.events.DataReceived):
                        bodies.setdefault(event.stream_id, bytearray()).extend(event.data)
                        peer.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        ended.add(event.stream_id)
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        terminations.append(int(event.error_code))
                pending = peer.data_to_send()
                if pending:
                    connection.sendall(pending)

        origin_thread.join(6)
        bridge_thread.join(6)

    result = {
        'alpn': 'h2',
        'origin_requests': origin_requests,
        'selected_streams': selected_streams,
        'client_statuses': statuses,
        'client_bodies': [
            [stream, bytes(body).decode('latin-1')]
            for stream, body in sorted(bodies.items())
        ],
        'client_terminations': terminations,
        'failures': failures,
    }
    assert not failures, result
    assert origin_requests == [1, 3], result
    assert selected_streams == [3], result
    assert statuses == [[3, '502'], [1, '200']], result
    assert terminations == [], result
    assert result['client_bodies'] == [[3, 'upstream connection closed']], result
    print(json.dumps(result, indent=2, sort_keys=True))
    print('PASS: native GOAWAY replacement over independent TLS/ALPN H2 peers')


if __name__ == '__main__':
    main()
