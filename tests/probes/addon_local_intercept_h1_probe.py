"""Measure HTTP/1 local response interception through the public reference API."""

import argparse
import json
from pathlib import Path
import socket
import subprocess

from addon_local_response_h2_probe import reserve_port, wait_for_proxy


PATHS = (
    '/headers/resume', '/headers/kill',
    '/response/resume', '/response/kill',
    '/headers/resume-kill', '/response/resume-kill',
    '/headers/kill-resume', '/response/kill-resume',
)


def exchange(port, path):
    # A separate connection per case prevents a killed connection from
    # contaminating the next observation. No upstream server is involved.
    with socket.create_connection(('127.0.0.1', port), timeout=2) as connection:
        connection.sendall((
            f'GET http://example.invalid{path} HTTP/1.1\r\n'
            'Host: example.invalid\r\n\r\n').encode())
        wire = bytearray()
        while True:
            try:
                data = connection.recv(65535)
            except TimeoutError:
                return {'body': '', 'closed': False, 'pending': True}

            if not data:
                return {'body': '', 'closed': True, 'pending': False}
            wire.extend(data)
            if b'\r\n\r\n' not in wire:
                continue

            head, body = bytes(wire).split(b'\r\n\r\n', 1)
            length = next(int(line.split(b':', 1)[1]) for line in head.split(b'\r\n')
                          if line.lower().startswith(b'content-length:'))
            if len(body) >= length:
                return {'body': body[:length].decode(), 'closed': False, 'pending': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--output', required=True)
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
        responses = {path: exchange(port, path) for path in PATHS}
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
    Path(args.output).write_text(rendered)
    print(rendered, end='')


if __name__ == '__main__':
    main()
