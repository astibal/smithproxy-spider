"""Exercise native H2 informational policy over independent TLS/ALPN peers.

This optional loopback probe uses Spider's production Translate model as the
byte bridge. It verifies the reusable native operations, not the mitmproxy
runtime: a waiting client receives a local 100, the forwarded request no longer
contains Expect, and an upstream 103 is hidden before the final response.

The caller supplies a disposable certificate and private key.
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


def _header_pairs(part):
    if part.headers is None:
        return []
    return [
        (field.name, field.value)
        for field in part.headers.entries
        if field.name is not None and field.value is not None
    ]


def _apply_policy(side, message):
    if side == 'L':
        for part in message.parts:
            if not part.complete or part.frame_type != 1:
                continue
            fields = _header_pairs(part)
            if not any(name == b':method' for name, _ in fields):
                continue
            expectations = [
                value for name, value in fields
                if name.lower() == b'expect'
            ]
            if len(expectations) != 1:
                continue
            if expectations[0].lower() != b'100-continue':
                continue

            # The policy remains outside the protocol primitive. Native
            # Translate owns retention, HPACK and reverse publication.
            part.headers.entries[:] = [
                field for field in part.headers.entries
                if field.name is None or field.name.lower() != b'expect'
            ]
            message.parts.hold_from(part)
            connection = Connection(message)
            connection.http2.reserve_body(part, 4)
            connection.http2.emit_informational_response(part)
        return

    for part in message.parts:
        if not part.complete or part.frame_type != 1 or part.flags & 1:
            continue
        statuses = [
            value for name, value in _header_pairs(part)
            if name == b':status'
        ]
        if len(statuses) != 1:
            continue
        status = statuses[0]
        if len(status) == 3 and status.isdigit() and 100 <= int(status) <= 199:
            if status != b'101':
                Connection(message).http2.suppress_informational_response(part)


def _contexts(certificate, private_key):
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(certificate, private_key)
    server.set_alpn_protocols(['h2'])

    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.set_alpn_protocols(['h2'])
    return server, client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--private-key', required=True)
    args = parser.parse_args()

    server_context, client_context = _contexts(
        args.certificate,
        args.private_key,
    )
    failures = []
    origin_headers = []
    origin_body = bytearray()

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
                        h2.config.H2Configuration(client_side=False)
                    )
                    peer.initiate_connection()
                    connection.sendall(peer.data_to_send())

                    ended = False
                    while not ended:
                        wire = connection.recv(65535)
                        if not wire:
                            raise AssertionError('Client request ended before END_STREAM')
                        for event in peer.receive_data(wire):
                            if isinstance(event, h2.events.RequestReceived):
                                origin_headers.extend(event.headers)
                            elif isinstance(event, h2.events.DataReceived):
                                origin_body.extend(event.data)
                                peer.acknowledge_received_data(
                                    event.flow_controlled_length,
                                    event.stream_id,
                                )
                            elif isinstance(event, h2.events.StreamEnded):
                                ended = True
                        pending = peer.data_to_send()
                        if pending:
                            connection.sendall(pending)

                    peer.send_headers(1, [
                        (b':status', b'103'),
                        (b'link', b'</style.css>; rel=preload'),
                    ])
                    connection.sendall(peer.data_to_send())
                    time.sleep(.05)
                    peer.send_headers(1, [(b':status', b'200')])
                    peer.send_data(1, b'ok', end_stream=True)
                    connection.sendall(peer.data_to_send())
                    time.sleep(.25)
            except BaseException as error:
                failures.append(('origin', repr(error)))

        def serve_bridge():
            try:
                client_raw, _ = bridge_listener.accept()
                with server_context.wrap_socket(
                        client_raw, server_side=True) as client_side:
                    if client_side.selected_alpn_protocol() != 'h2':
                        raise AssertionError('Client-facing ALPN did not negotiate h2')
                    origin_raw = socket.create_connection(
                        ('127.0.0.1', origin_port), timeout=4
                    )
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
                                forward, reverse = bridge.feed(
                                    side,
                                    wire,
                                    lambda message, source_side=side:
                                        _apply_policy(source_side, message),
                                )
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
        informational = []
        final_statuses = []
        response_body = bytearray()
        sent_body = False
        with client_context.wrap_socket(raw, server_hostname='localhost') as connection:
            if connection.selected_alpn_protocol() != 'h2':
                raise AssertionError('Client ALPN did not negotiate h2')
            connection.settimeout(4)
            peer = h2.connection.H2Connection()
            peer.initiate_connection()
            peer.send_headers(1, [
                (b':method', b'POST'),
                (b':scheme', b'https'),
                (b':authority', b'origin.test'),
                (b':path', b'/upload'),
                (b'expect', b'100-continue'),
                (b'content-length', b'4'),
            ])
            connection.sendall(peer.data_to_send())

            ended = False
            while not ended:
                wire = connection.recv(65535)
                if not wire:
                    break
                for event in peer.receive_data(wire):
                    if isinstance(event, h2.events.InformationalResponseReceived):
                        informational.append(
                            dict(event.headers)[b':status'].decode('ascii')
                        )
                        if not sent_body:
                            peer.send_data(1, b'body', end_stream=True)
                            sent_body = True
                    elif isinstance(event, h2.events.ResponseReceived):
                        final_statuses.append(
                            dict(event.headers)[b':status'].decode('ascii')
                        )
                    elif isinstance(event, h2.events.DataReceived):
                        response_body.extend(event.data)
                        peer.acknowledge_received_data(
                            event.flow_controlled_length,
                            event.stream_id,
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        ended = True
                pending = peer.data_to_send()
                if pending:
                    connection.sendall(pending)

        origin_thread.join(6)
        bridge_thread.join(6)

    result = {
        'alpn': 'h2',
        'client_informational': informational,
        'client_final': final_statuses,
        'client_body': bytes(response_body).decode('latin-1'),
        'origin_expect': [
            value.decode('latin-1')
            for name, value in origin_headers
            if name.lower() == b'expect'
        ],
        'origin_body': bytes(origin_body).decode('latin-1'),
        'failures': failures,
    }
    assert not failures, result
    assert informational == ['100'], result
    assert final_statuses == ['200'], result
    assert bytes(response_body) == b'ok', result
    assert result['origin_expect'] == [], result
    assert bytes(origin_body) == b'body', result
    print(json.dumps(result, indent=2, sort_keys=True))
    print('PASS: native informational policy over independent TLS/ALPN H2 peers')


if __name__ == '__main__':
    main()
