"""Black-box TLS failure observations from the pinned mitmproxy executable."""

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

from addon_tls_transport_probe import read_head, reserve_port, wait_for_proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    result = {}

    for side in ('server', 'client'):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(10)
        target = listener.getsockname()[1]
        origin_errors = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.certificate, args.key)

        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with raw:
                        if side == 'server':
                            assert raw.recv(1), 'Origin did not receive a ClientHello'
                            raw.sendall(b'HTTP/1.1 400 Not TLS\r\n\r\n')
                        else:
                            with context.wrap_socket(raw, server_side=True) as tls:
                                tls.recv(4096)
            except (ssl.SSLError, ConnectionError):
                pass
            except Exception as error:
                origin_errors.append(repr(error))

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port = reserve_port()
        addon = Path(__file__).with_name('addon_tls_transport_addon.py')
        process = subprocess.Popen([
            args.reference, '--listen-host', '127.0.0.1', '--listen-port', str(port),
            '--set', 'connection_strategy=eager', '--set', 'ssl_insecure=true',
            '--set', 'termlog_verbosity=error', '-s', str(addon),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            wait_for_proxy(port, process)
            with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
                raw.sendall(f'CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
                assert read_head(raw).startswith(b'HTTP/1.1 200 ')
                client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if side == 'server':
                    client.check_hostname = False
                    client.verify_mode = ssl.CERT_NONE
                try:
                    with client.wrap_socket(raw, server_hostname='localhost') as tls:
                        tls.sendall(b'GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                        tls.recv(4096)
                except (ssl.SSLError, ConnectionError):
                    pass
            time.sleep(.2)
        finally:
            process.terminate()
            output, _ = process.communicate(timeout=10)
            listener.close()
        thread.join(12)
        assert not thread.is_alive() and not origin_errors, origin_errors
        result[side] = [json.loads(line.removeprefix('PROBE ')) for line in output.splitlines()
                        if line.startswith('PROBE ')]

    rendered = json.dumps({'reference': 'mitmproxy 12.3.1', 'cases': result}, indent=2) + '\n'
    Path(args.output).write_text(rendered)
    print(rendered, end='')


if __name__ == '__main__':
    main()
