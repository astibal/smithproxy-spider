"""Observe local H2 response interception using an isolated reference binary.

Only the public addon interface and an independent hyper-h2 client are used.
No reference implementation code is imported into the project.
"""

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess

import h2.config
import h2.connection
import h2.events

from addon_local_response_h2_probe import reserve_port, wait_for_proxy


def exchange(port):
    raw = socket.create_connection(('127.0.0.1', port), timeout=5)
    raw.sendall(b'CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n')
    response = bytearray()
    while b'\r\n\r\n' not in response:
        data = raw.recv(4096)
        if not data:
            raise RuntimeError('Reference closed CONNECT')
        response.extend(data)
    if not response.startswith(b'HTTP/1.1 200 '):
        raise RuntimeError('Reference rejected CONNECT')

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(['h2'])
    results = {}

    with context.wrap_socket(raw, server_hostname='example.invalid') as connection:
        client = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        client.initiate_connection()

        # Sequential cases keep hook order stable without relying on timer
        # precision. The timer only supplies the reference's external resume.
        paths = (
            '/headers/resume', '/headers/kill',
            '/response/resume', '/response/kill',
            '/headers/resume-kill', '/response/resume-kill',
            '/headers/kill-resume', '/response/kill-resume',
        )
        for index, path in enumerate(paths):
            stream = index * 2 + 1
            client.send_headers(stream, [
                (':method', 'GET'), (':scheme', 'https'),
                (':authority', 'example.invalid'), (':path', path),
            ], end_stream=True)
            connection.sendall(client.data_to_send())
            result = {'body': '', 'reset': None, 'ended': False}

            while not result['ended'] and result['reset'] is None:
                try:
                    data = connection.recv(65535)
                except TimeoutError:
                    result['pending'] = True
                    break
                if not data:
                    raise RuntimeError('Reference closed an unfinished response')
                for event in client.receive_data(data):
                    if getattr(event, 'stream_id', None) != stream:
                        continue
                    if isinstance(event, h2.events.DataReceived):
                        result['body'] += event.data.decode('ascii')
                        client.acknowledge_received_data(event.flow_controlled_length, stream)
                    elif isinstance(event, h2.events.StreamReset):
                        result['reset'] = int(event.error_code)
                    elif isinstance(event, h2.events.StreamEnded):
                        result['ended'] = True
                pending = client.data_to_send()
                if pending:
                    connection.sendall(pending)
            results[path] = result
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--output')
    args = parser.parse_args()
    port = reserve_port()
    addon = Path(__file__).with_name('addon_local_intercept_addon.py')
    process = subprocess.Popen([
        args.reference, '--listen-host', '127.0.0.1', '--listen-port', str(port),
        '--set', 'connection_strategy=lazy', '--set', 'termlog_verbosity=error',
        '-s', str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(port, process)
        responses = exchange(port)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    hooks = [json.loads(line.removeprefix('PROBE '))
             for line in output.splitlines() if line.startswith('PROBE ')]
    result = {'reference': 'mitmproxy 12.3.1', 'responses': responses, 'hooks': hooks}
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end='')


if __name__ == '__main__':
    main()
