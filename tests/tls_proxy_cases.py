"""Live TLS cases shared with the disposable CONNECT integration fixture."""

import socket
import ssl
import subprocess
import threading
import time


ADDON = '''events = []
server = None
client = None

def tls_established_server(data):
    global server
    server = data.conn
    assert server is data.context.server
    assert server.tls_established
    assert server.cipher
    assert server.tls_version in ('TLSv1.2', 'TLSv1.3')
    events.append('server')

def tls_established_client(data):
    global client
    client = data.conn
    assert client is data.context.client
    assert client.tls_established
    assert data.context.server is server
    events.append('client')

def request(flow):
    assert events == ['server', 'client'], events
    assert flow.server_conn is server
    assert flow.client_conn is client
    flow.request.headers['X-TLS-Hooks'] = 'observed'

def tls_failed_server(data):
    assert not data.conn.tls_established
    assert data.conn.error

def tls_failed_client(data):
    assert not data.conn.tls_established
    assert data.conn.error
'''


def read_headers(connection):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        part = connection.recv(4096)
        if not part:
            break
        data.extend(part)
    return bytes(data)


class FragmentedTlsClient:
    """Drive real OpenSSL while splitting the first ClientHello across writes."""

    def __init__(self, context, raw):
        self.raw = raw
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.ssl = context.wrap_bio(self.incoming, self.outgoing, server_hostname='localhost')
        self.first_write = True
        self.call(self.ssl.do_handshake)

    def flush(self):
        data = self.outgoing.read()
        if not data:
            return
        if self.first_write:
            self.first_write = False
            for fragment in (data[:2], data[2:5], data[5:]):
                self.raw.sendall(fragment)
                time.sleep(.02)
        else:
            self.raw.sendall(data)

    def call(self, operation):
        while True:
            try:
                result = operation()
                self.flush()
                return result
            except ssl.SSLWantReadError:
                self.flush()
                data = self.raw.recv(16384)
                if not data:
                    self.incoming.write_eof()
                else:
                    self.incoming.write(data)

    def sendall(self, data):
        offset = 0
        while offset < len(data):
            offset += self.call(lambda: self.ssl.write(data[offset:]))

    def recv(self, size):
        try:
            return self.call(lambda: self.ssl.read(size))
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b''

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.raw.close()


def run_tls_cases(deploy, start_proxy, certificates, exchanges):
    # The origin name must match SNI; TLS verification policy stays meaningful.
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-keyout', str(certificates / 'origin-key.pem'),
        '-out', str(certificates / 'origin-cert.pem'),
    ], check=True, capture_output=True)

    cases = (
        (ssl.TLSVersion.TLSv1_2, False),
        (ssl.TLSVersion.TLSv1_3, False),
        (ssl.TLSVersion.TLSv1_3, True),
    )
    for version, fragmented in cases:
        deploy(ADDON)
        offset = len(exchanges)
        errors = []
        requests = []
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(10)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(certificates / 'origin-cert.pem', certificates / 'origin-key.pem')
        context.set_alpn_protocols(['http/1.1'])

        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with context.wrap_socket(raw, server_side=True) as tls:
                        requests.append(read_headers(tls))
                        tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        target = listener.getsockname()[1]
        proxy_port, process = start_proxy(target)
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=10) as raw:

            client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client.check_hostname = False
            client.verify_mode = ssl.CERT_NONE
            client.minimum_version = client.maximum_version = version
            client.set_alpn_protocols(['http/1.1'])
            stream = (FragmentedTlsClient(client, raw) if fragmented else
                      client.wrap_socket(raw, server_hostname='localhost'))
            with stream as tls:
                tls.sendall(b'GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                response = bytearray()
                while True:
                    part = tls.recv(4096)
                    if not part:
                        break
                    response.extend(part)
                assert response.startswith(b'HTTP/1.1 200 '), response
                assert response.endswith(b'ok'), response

        thread.join(12)
        assert not thread.is_alive(), 'TLS origin did not finish'
        assert not errors, errors
        assert b'x-tls-hooks: observed' in requests[0].lower(), requests

        deadline = time.monotonic() + 5
        while not any(event['action'] == 'connection-stop' for event, _, _ in exchanges[offset:]):
            assert time.monotonic() < deadline, 'TLS session did not retire'
            time.sleep(.02)

        events = [entry for entry in exchanges[offset:] if entry[0]['action'] == 'tls-lifecycle']
        assert all(status == 200 for _, _, status in events), events
        outcomes = [entry[0]['details']['tls']['envelope'] for entry in events]
        assert [(e['side'], e['event']) for e in outcomes] == [
            ('server', 'established'), ('client', 'established'),
        ], outcomes
        process.terminate()
        process.wait(timeout=5)
        print(f'PASS: {version.name} fragmented={fragmented} TLS outcomes before HTTP, shared identity, no false failure at close')


def run_tls_failure_cases(deploy, start_proxy, certificates, exchanges):
    for failure in ('server', 'client'):
        deploy(ADDON)
        offset = len(exchanges)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(10)
        target = listener.getsockname()[1]
        origin_finished = threading.Event()
        origin_errors = []

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificates / 'origin-cert.pem', certificates / 'origin-key.pem')

        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with raw:
                        if failure == 'server':
                            # TCP succeeds, but the upstream cannot speak TLS.
                            assert raw.recv(1), 'Origin did not receive a ClientHello'
                            raw.sendall(b'HTTP/1.1 400 Not TLS\r\n\r\n')
                        else:
                            with context.wrap_socket(raw, server_side=True) as tls:
                                tls.recv(4096)
            except (ssl.SSLError, ConnectionError):
                pass
            except Exception as error:
                origin_errors.append(error)
            finally:
                origin_finished.set()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        proxy_port, process = start_proxy(target)
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if failure == 'server':
            client.check_hostname = False
            client.verify_mode = ssl.CERT_NONE
        # For the client failure, keep verification enabled with no trusted CA.

        try:
            with socket.create_connection(('127.0.0.1', proxy_port), timeout=10) as raw:
                with client.wrap_socket(raw, server_hostname='localhost') as tls:
                    tls.sendall(b'GET /must-not-pass HTTP/1.1\r\nHost: localhost\r\n\r\n')
                    assert not tls.recv(4096), 'A failed handshake delivered application data'
        except (ssl.SSLError, ConnectionError):
            pass

        deadline = time.monotonic() + 8
        while True:
            events = [entry for entry in exchanges[offset:] if entry[0]['action'] == 'tls-lifecycle']
            outcomes = [entry[0]['details']['tls']['envelope'] for entry in events]
            if any(e['side'] == failure and e['event'] == 'failed' for e in outcomes):
                break
            assert time.monotonic() < deadline, outcomes
            time.sleep(.02)

        assert all(status == 200 for _, _, status in events), events
        keys = [(e['side'], e['attempt']) for e in outcomes]
        assert len(keys) == len(set(keys)), 'One TLS attempt reported more than one outcome'
        assert not any(e['side'] == failure and e['event'] == 'established' for e in outcomes), outcomes
        if failure == 'client':
            assert any(e['side'] == 'server' and e['event'] == 'established' for e in outcomes), outcomes

        process.terminate()
        process.wait(timeout=5)
        assert origin_finished.wait(12), 'Failed TLS origin did not finish'
        assert not origin_errors, origin_errors
        print(f'PASS: TLS {failure} handshake failure, once-only outcome, no application traffic')
