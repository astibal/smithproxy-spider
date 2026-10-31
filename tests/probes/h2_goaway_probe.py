"""Observe a separate reference proxy over loopback without reading its source.

The origin accepts two requests, completes the first, then sends GOAWAY with
that request's stream ID (or RST_STREAM for the second with --reset-stream).
Observe callback errors, client frames, and whether
the proxy opens another upstream connection. No reference package is imported.
Disposable TLS files must be provided by the caller.
"""

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

import h2.config
import h2.connection
import h2.events
import h2.errors


def goaway_frame(last_stream_id, error_code):
    """Encode one control frame without closing the origin's h2 state machine."""
    payload = last_stream_id.to_bytes(4, 'big') + error_code.to_bytes(4, 'big')
    return (len(payload).to_bytes(3, 'big') + b'\x07\x00' + bytes(4) + payload)


def reset_frame(stream_id, error_code):
    """Encode one RST_STREAM without changing the origin's h2 state machine."""
    payload = error_code.to_bytes(4, 'big')
    return (len(payload).to_bytes(3, 'big') + b'\x03\x00' +
            stream_id.to_bytes(4, 'big') + payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--private-key', required=True)
    parser.add_argument('--error-code', type=int, default=0)
    parser.add_argument('--method', default='GET')
    parser.add_argument('--leave-first-pending', action='store_true')
    parser.add_argument('--leave-first-request-open', action='store_true')
    parser.add_argument('--send-late-first-data', action='store_true')
    parser.add_argument('--informational-first-before-goaway', action='store_true')
    parser.add_argument('--complete-first-after-goaway', action='store_true')
    parser.add_argument('--reset-stream', action='store_true',
                        help='Send RST_STREAM for the second request instead of GOAWAY')
    parser.add_argument('--second-before-reset',
                        choices=('informational', 'final', 'final-separated'),
                        help='Send response headers for stream 3 immediately before its reset')
    parser.add_argument('--reset-goaway-order', choices=('before', 'after'),
                        help='Send stream 3 RST_STREAM adjacent to GOAWAY in this order')
    parser.add_argument('--observe-only', action='store_true',
                        help='Print observations without enforcing a checked contract')
    parser.add_argument('--output', help='Optional JSON corpus destination')
    parser.add_argument('--expect', help='Optional checked-in corpus to verify')
    args = parser.parse_args()
    if args.reset_stream and args.reset_goaway_order:
        parser.error('--reset-stream and --reset-goaway-order are mutually exclusive')
    if args.second_before_reset and not args.reset_stream:
        parser.error('--second-before-reset requires --reset-stream')
    if args.reset_stream and args.leave_first_pending:
        parser.error('--reset-stream requires a completed first response')
    if args.complete_first_after_goaway and (args.leave_first_pending or args.reset_stream):
        parser.error('--complete-first-after-goaway requires the GOAWAY scenario')
    if args.leave_first_request_open and (
            args.leave_first_pending or args.complete_first_after_goaway or args.reset_stream):
        parser.error('--leave-first-request-open requires its own GOAWAY scenario')
    if args.send_late_first_data and not args.leave_first_request_open:
        parser.error('--send-late-first-data requires --leave-first-request-open')
    if args.informational_first_before_goaway and (
            args.leave_first_pending or args.leave_first_request_open or
            args.complete_first_after_goaway or args.reset_stream):
        parser.error('--informational-first-before-goaway requires its own GOAWAY scenario')

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(args.certificate, args.private_key)
    server_context.set_alpn_protocols(['h2'])
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.set_alpn_protocols(['h2'])
    origin_requests = []
    origin_errors = []
    retries = []
    client_statuses = []
    client_headers = []
    client_informational = []
    client_resets = []
    client_ended = []
    client_terminations = []
    client_bodies = {}
    late_first_data_sent = False

    with socket.socket() as origin, socket.socket() as reservation:
        origin.bind(('127.0.0.1', 0))
        origin.listen(4)
        origin.settimeout(4)
        origin_port = origin.getsockname()[1]
        reservation.bind(('127.0.0.1', 0))
        proxy_port = reservation.getsockname()[1]
        reservation.close()

        def serve():
            try:
                raw, _ = origin.accept()
                raw.settimeout(4)
                with server_context.wrap_socket(raw, server_side=True) as connection:
                    peer = h2.connection.H2Connection(
                        h2.config.H2Configuration(client_side=False))
                    peer.initiate_connection()
                    connection.sendall(peer.data_to_send())
                    requested = []
                    ended = []
                    while len(requested) < 2 or (
                            not args.leave_first_request_open and len(ended) < 2):
                        data = connection.recv(65535)
                        if not data:
                            raise RuntimeError('Upstream closed before both requests')
                        for event in peer.receive_data(data):
                            if isinstance(event, h2.events.RequestReceived):
                                path = dict(event.headers)[b':path'].decode()
                                origin_requests.append([event.stream_id, path])
                                requested.append(event.stream_id)
                            if isinstance(event, h2.events.StreamEnded):
                                ended.append(event.stream_id)
                        connection.sendall(peer.data_to_send())
                    if args.reset_goaway_order:
                        frames = {
                            'before': reset_frame(ended[1], args.error_code) +
                                      goaway_frame(ended[0], args.error_code),
                            'after': goaway_frame(ended[0], args.error_code) +
                                     reset_frame(ended[1], args.error_code),
                        }
                        connection.sendall(frames[args.reset_goaway_order])
                    elif args.informational_first_before_goaway:
                        peer.send_headers(
                            ended[0],
                            [(':status', '103'), ('link', '</asset>; rel=preload')],
                            end_stream=False,
                        )
                    elif not (args.leave_first_pending or args.complete_first_after_goaway or
                              args.leave_first_request_open):
                        peer.send_headers(ended[0], [(':status', '200')], end_stream=True)
                    if args.reset_stream:
                        if args.second_before_reset == 'informational':
                            peer.send_headers(
                                ended[1],
                                [(':status', '103'), ('x-state', 'retained')],
                                end_stream=False,
                            )
                        elif args.second_before_reset in ('final', 'final-separated'):
                            peer.send_headers(
                                ended[1],
                                [(':status', '200'), ('x-state', 'retained')],
                                end_stream=False,
                            )
                            if args.second_before_reset == 'final-separated':
                                connection.sendall(peer.data_to_send())
                                time.sleep(.1)
                        peer.reset_stream(ended[1], error_code=args.error_code)
                    elif args.complete_first_after_goaway:
                        connection.sendall(goaway_frame(ended[0], args.error_code))
                    else:
                        peer.close_connection(error_code=args.error_code,
                                              last_stream_id=requested[0])
                    connection.sendall(peer.data_to_send())
                    if args.complete_first_after_goaway:
                        time.sleep(.1)
                        peer.send_headers(ended[0], [(':status', '200')], end_stream=True)
                        connection.sendall(peer.data_to_send())
                    # Leave TLS open briefly so GOAWAY, not EOF, drives handling.
                    time.sleep(.5)
                try:
                    retry, address = origin.accept()
                except socket.timeout:
                    return
                retries.append(address[0])
                retry.close()
            except Exception as error:
                origin_errors.append(repr(error))

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        command = [
            args.reference, '--listen-host', '127.0.0.1',
            '--listen-port', str(proxy_port), '--ssl-insecure',
            '--set', 'connection_strategy=lazy',
        ]
        if args.leave_first_request_open:
            command.extend(['--set', 'stream_large_bodies=1'])
        command.extend([
            '-s',
            str(Path(__file__).with_name('h2_goaway_addon.py')),
        ])
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + 8
            while True:
                try:
                    client = socket.create_connection(('127.0.0.1', proxy_port), timeout=1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.05)
            client.settimeout(6)
            client.sendall((f'CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n'
                            f'Host: 127.0.0.1:{origin_port}\r\n\r\n').encode())
            handshake = b''
            while b'\r\n\r\n' not in handshake:
                chunk = client.recv(4096)
                if not chunk:
                    raise RuntimeError('CONNECT handshake closed')
                handshake += chunk
            assert handshake.startswith(b'HTTP/1.1 200 '), handshake
            with client_context.wrap_socket(client, server_hostname='localhost') as connection:
                assert connection.selected_alpn_protocol() == 'h2'
                peer = h2.connection.H2Connection()
                peer.initiate_connection()
                for stream_id in (1, 3):
                    peer.send_headers(stream_id, [(':method', args.method),
                        (':scheme', 'https'), (':authority', f'127.0.0.1:{origin_port}'),
                        (':path', f'/{stream_id}')],
                        end_stream=stream_id != 1 or not args.leave_first_request_open)
                if args.leave_first_request_open:
                    peer.send_data(1, b'partial request body', end_stream=False)
                connection.sendall(peer.data_to_send())
                while True:
                    try:
                        data = connection.recv(65535)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    for event in peer.receive_data(data):
                        if isinstance(event, h2.events.ResponseReceived):
                            status = dict(event.headers)[b':status'].decode()
                            client_statuses.append([event.stream_id, status])
                            client_headers.append([
                                event.stream_id,
                                [[name.decode('latin-1'), value.decode('latin-1')]
                                 for name, value in event.headers],
                            ])
                        if isinstance(event, h2.events.InformationalResponseReceived):
                            client_informational.append([
                                event.stream_id,
                                [[name.decode('latin-1'), value.decode('latin-1')]
                                 for name, value in event.headers],
                            ])
                        if isinstance(event, h2.events.DataReceived):
                            body = client_bodies.setdefault(event.stream_id, bytearray())
                            body.extend(event.data)
                            peer.acknowledge_received_data(
                                event.flow_controlled_length,
                                event.stream_id,
                            )
                        if isinstance(event, h2.events.StreamReset):
                            client_resets.append([event.stream_id, int(event.error_code)])
                        if isinstance(event, h2.events.StreamEnded):
                            client_ended.append(event.stream_id)
                            if (args.send_late_first_data and event.stream_id == 1 and
                                    not late_first_data_sent):
                                peer.send_data(1, b'late request body', end_stream=True)
                                late_first_data_sent = True
                        if isinstance(event, h2.events.ConnectionTerminated):
                            client_terminations.append([
                                int(event.error_code),
                                event.last_stream_id,
                                event.additional_data.decode('latin-1'),
                            ])
                    pending = peer.data_to_send()
                    if pending:
                        connection.sendall(pending)
            server.join(6)
            assert not server.is_alive(), 'Origin observation did not finish'
        finally:
            process.terminate()
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate()

    hooks = [json.loads(line[6:]) for line in output.splitlines()
             if line.startswith('PROBE ')]
    if args.reset_goaway_order:
        response_timing = f'reset-{args.reset_goaway_order}-goaway'
    elif args.second_before_reset:
        response_timing = f'{args.second_before_reset}-before-reset'
    elif args.leave_first_pending:
        response_timing = 'pending'
    elif args.leave_first_request_open:
        response_timing = 'request-open'
    elif args.informational_first_before_goaway:
        response_timing = 'informational-before-goaway'
    elif args.complete_first_after_goaway:
        response_timing = 'after-goaway'
    else:
        response_timing = 'before-goaway'
    result = {'reference': 'mitmproxy 12.3.1',
              'error_code': args.error_code,
              'method': args.method,
              'reset_stream': args.reset_stream,
              'response_timing': response_timing,
              'origin_requests': origin_requests,
              'origin_errors': origin_errors, 'retry_connections': retries,
              'client_bodies': [
                  [stream, bytes(body).decode('latin-1')]
                  for stream, body in sorted(client_bodies.items())
              ],
              'client_headers': client_headers,
              'client_statuses': client_statuses,
              'client_resets': client_resets,
              'client_ended': client_ended,
              'client_terminations': client_terminations,
              'hooks': hooks}
    if args.reset_goaway_order:
        result['reset_goaway_order'] = args.reset_goaway_order
    if args.second_before_reset:
        result['second_before_reset'] = args.second_before_reset
        result['client_informational'] = client_informational
    if args.send_late_first_data:
        result['late_first_data_sent'] = late_first_data_sent
    if args.informational_first_before_goaway:
        result['client_informational'] = client_informational
    assert not origin_errors, origin_errors
    assert len(origin_requests) == 2, output
    assert process.returncode in (0, -15), output
    assert not retries, result
    reason = ('HTTP/2 connection closed: <ConnectionTerminated '
              f'error_code:{args.error_code}, last_stream_id:1, additional_data:None>')
    if args.reset_stream:
        try:
            label = h2.errors.ErrorCodes(args.error_code).name
        except ValueError:
            label = str(args.error_code)
        reason = f'stream reset by client ({label})'
    expected_hooks = [
        ['requestheaders', '/1'],
        ['requestheaders', '/3'],
        ['request', '/1'],
        ['request', '/3'],
    ]
    if args.reset_goaway_order == 'before':
        reset_reason = 'stream reset by client (NO_ERROR)'
        expected_hooks.extend([
            ['error', '/3', reset_reason],
            ['error', '/1', reason],
        ])
        expected_statuses = [[3, '502'], [1, '502']]
    elif args.reset_goaway_order == 'after':
        protocol_reason = (
            'HTTP/2 protocol error: Invalid input '
            'ConnectionInputs.RECV_RST_STREAM in state ConnectionState.CLOSED'
        )
        expected_hooks.extend([
            ['error', '/1', protocol_reason],
            ['error', '/3', protocol_reason],
        ])
        expected_statuses = [[1, '502'], [3, '502']]
    elif args.second_before_reset == 'informational':
        expected_hooks.extend([
            ['responseheaders', '/1', 200],
            ['error', '/3', reason],
            ['response', '/1', 200],
        ])
        expected_statuses = [[3, '502'], [1, '200']]
        assert client_informational == [], result
    elif args.second_before_reset in ('final', 'final-separated'):
        expected_hooks.extend([
            ['responseheaders', '/1', 200],
            ['responseheaders', '/3', 200],
            ['response', '/1', 200],
            ['error', '/3', reason],
        ])
        expected_statuses = [[1, '200'], [3, '502']]
    elif args.leave_first_request_open:
        expected_hooks = [
            ['requestheaders', '/1'],
            ['requestheaders', '/3'],
            ['request', '/3'],
            ['error', '/1', reason],
            ['error', '/3', reason],
        ]
        expected_statuses = [[1, '502'], [3, '502']]
    elif (args.leave_first_pending or args.complete_first_after_goaway or
          args.informational_first_before_goaway):
        expected_hooks.extend([['error', '/1', reason], ['error', '/3', reason]])
        expected_statuses = [[1, '502'], [3, '502']]
    else:
        expected_hooks.extend([
            ['responseheaders', '/1', 200],
            ['error', '/3', reason],
            ['response', '/1', 200],
        ])
        expected_statuses = [[3, '502'], [1, '200']]
    expected_resets = []
    if args.reset_stream and args.error_code == 8:
        expected_statuses = [[1, '200']]
        expected_resets = [[3, 8]]
    if not args.observe_only:
        assert hooks == expected_hooks, result
        assert client_statuses == expected_statuses, result
        assert client_resets == expected_resets, result

    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        assert result == expected, 'Reference GOAWAY behavior changed'
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end='')
    print('PASS: reference termination callbacks and client response contract')


if __name__ == '__main__':
    main()
