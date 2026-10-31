"""Opt-in loopback black-box probe; never loads reference implementation source.

Requires an independently installed mitmdump executable and a disposable TLS
certificate/key supplied by the caller. It is not a runtime dependency or part
of the offline CTest suite. Only local sockets are used.
"""

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

import h2.connection
import h2.config
import h2.events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True, help='Path to reference mitmdump')
    parser.add_argument('--certificate', required=True, help='Disposable PEM test certificate')
    parser.add_argument('--private-key', required=True, help='Disposable PEM test key')
    parser.add_argument('--output', help='Optional JSON corpus destination')
    parser.add_argument('--expect', help='Optional checked-in corpus to verify')
    parser.add_argument(
        '--case',
        choices=('baseline', 'mixed-case', 'duplicate', 'invalid', 'absent', 'bodyless'),
        default='baseline',
        help='Request Expect shape to observe',
    )
    parser.add_argument('--observe-only', action='store_true',
                        help='Record a non-baseline case without enforcing its contract')
    args = parser.parse_args()
    if args.case != 'baseline' and not args.observe_only and not args.expect:
        parser.error('Non-baseline cases require --observe-only or --expect')

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(args.certificate,
                                   args.private_key)
    server_context.set_alpn_protocols(['h2'])
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.set_alpn_protocols(['h2'])

    with socket.socket() as origin, socket.socket() as reservation:
        origin.bind(('127.0.0.1', 0))
        origin.listen(1)
        origin.settimeout(10)
        reservation.bind(('127.0.0.1', 0))
        proxy_port = reservation.getsockname()[1]
        reservation.close()
        origin_port = origin.getsockname()[1]
        server_errors = []
        origin_requests = []
        client_statuses = []
        client_body = bytearray()
        request_body = b'' if args.case == 'bodyless' else b'test'
        wait_for_continue = args.case in ('baseline', 'mixed-case')
        expect_fields = {
            'baseline': [('expect', '100-continue')],
            'mixed-case': [('expect', '100-Continue')],
            'duplicate': [('expect', '100-continue'), ('expect', '100-continue')],
            'invalid': [('expect', 'something-else')],
            'absent': [],
            'bodyless': [('expect', '100-continue')],
        }[args.case]

        def serve():
            try:
                raw, _ = origin.accept()
                raw.settimeout(5)
                with server_context.wrap_socket(raw, server_side=True) as connection:
                    assert connection.selected_alpn_protocol() == 'h2'
                    h2_server = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
                    h2_server.initiate_connection()
                    connection.sendall(h2_server.data_to_send())
                    while True:
                        data = connection.recv(65535)
                        if not data:
                            return
                        for event in h2_server.receive_data(data):
                            if isinstance(event, h2.events.RequestReceived):
                                origin_requests.append(event.headers)
                            if isinstance(event, h2.events.StreamEnded):
                                for status in ('103', '100', '200'):
                                    h2_server.send_headers(event.stream_id, [(':status', status)])
                                h2_server.send_data(event.stream_id, b'done', end_stream=True)
                                connection.sendall(h2_server.data_to_send())
                                time.sleep(.2)
                                return
                        connection.sendall(h2_server.data_to_send())
            except Exception as error:
                server_errors.append(repr(error))

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        process = subprocess.Popen([
            args.reference, '--listen-host', '127.0.0.1',
            '--listen-port', str(proxy_port), '-s', str(Path(__file__).with_name('h2_expect_addon.py')),
            '--ssl-insecure', '--set', 'connection_strategy=lazy'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    client = socket.create_connection(('127.0.0.1', proxy_port), timeout=1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.05)
            client.settimeout(5)
            client.sendall((f'CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n'
                            f'Host: 127.0.0.1:{origin_port}\r\n\r\n').encode())
            response = b''
            while b'\r\n\r\n' not in response:
                chunk = client.recv(4096)
                if not chunk:
                    raise RuntimeError('Reference closed the CONNECT handshake')
                response += chunk
            assert response.startswith(b'HTTP/1.1 200 '), response
            print('CONNECT', repr(response))
            with client_context.wrap_socket(client, server_hostname='localhost') as connection:
                print('ALPN', connection.selected_alpn_protocol())
                assert connection.selected_alpn_protocol() == 'h2'
                h2_client = h2.connection.H2Connection()
                h2_client.initiate_connection()
                request_headers = [
                    (':method', 'POST'),
                    (':scheme', 'https'),
                    (':authority', f'127.0.0.1:{origin_port}'),
                    (':path', '/'),
                    *expect_fields,
                    ('content-length', str(len(request_body))),
                ]
                h2_client.send_headers(
                    1,
                    request_headers,
                    end_stream=not request_body,
                )
                body_sent = not request_body
                if request_body and not wait_for_continue:
                    h2_client.send_data(1, request_body, end_stream=True)
                    body_sent = True
                connection.sendall(h2_client.data_to_send())
                done = False
                while not done:
                    data = connection.recv(65535)
                    if not data:
                        break
                    for event in h2_client.receive_data(data):
                        print(type(event).__name__, repr(event))
                        if isinstance(event, (h2.events.InformationalResponseReceived, h2.events.ResponseReceived)):
                            client_statuses.append(dict(event.headers)[b':status'].decode())
                        if isinstance(event, h2.events.DataReceived):
                            client_body.extend(event.data)
                        if isinstance(event, h2.events.InformationalResponseReceived):
                            if ((b':status', b'100') in event.headers and
                                    wait_for_continue and not body_sent):
                                print('CLIENT RECEIVED CONTINUE', flush=True)
                                h2_client.send_data(1, request_body, end_stream=True)
                                body_sent = True
                                connection.sendall(h2_client.data_to_send())
                        if isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                            done = True
            server.join(2)
            print('SERVER ERRORS', server_errors)
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate()
            print(output)

        hooks = [json.loads(line.removeprefix('PROBE '))
                 for line in output.splitlines() if line.startswith('PROBE ')]
        assert process.returncode in (0, -15), output
        assert not server_errors, server_errors
        if args.case == 'baseline' and not args.observe_only:
            assert client_statuses == ['100', '200'], client_statuses
        assert bytes(client_body) == b'done', client_body
        assert len(origin_requests) == 1, origin_requests
        if args.case == 'baseline' and not args.observe_only:
            assert b'expect' not in dict(origin_requests[0]), origin_requests
        expected_hooks = [
            ['requestheaders', '100-continue', True],
            ['request', None, 'test'],
            ['responseheaders', 200],
            ['response', 200, 'done'],
        ]
        if args.case == 'baseline' and not args.observe_only:
            assert hooks == expected_hooks, hooks

        result = {
            'reference': 'mitmproxy 12.3.1',
            'request': {
                'case': args.case,
                'method': 'POST',
                'expect_fields': [value for _, value in expect_fields],
                'body': request_body.decode('latin-1'),
            },
            'client': {
                'statuses': client_statuses,
                'body': bytes(client_body).decode('latin-1'),
            },
            'origin': {
                'headers': [
                    [
                        name.decode('latin-1'),
                        ('<origin>' if name == b':authority'
                         else value.decode('latin-1')),
                    ]
                    for name, value in origin_requests[0]
                ],
                'expect_forwarded': b'expect' in dict(origin_requests[0]),
            },
            'hooks': hooks,
        }
        if args.expect:
            expected = json.loads(Path(args.expect).read_text())
            assert result == expected, 'Reference Expect behavior changed'
        rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.output:
            Path(args.output).write_text(rendered)
        print(rendered, end='')
        print('PASS: H2 Expect and informational-response observation')


if __name__ == '__main__':
    main()
