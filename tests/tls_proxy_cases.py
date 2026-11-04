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


def run_tls_cases(deploy, start_proxy, certificates, exchanges, set_relay_mode):
    # The origin name must match SNI; TLS verification policy stays meaningful.
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
        '-keyout', str(certificates / 'origin-key.pem'),
        '-out', str(certificates / 'origin-cert.pem'),
    ], check=True, capture_output=True)

    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=upstream.test', '-addext', 'subjectAltName=DNS:upstream.test',
        '-keyout', str(certificates / 'upstream-key.pem'),
        '-out', str(certificates / 'upstream-cert.pem'),
    ], check=True, capture_output=True)

    cases = (
        (ssl.TLSVersion.TLSv1_2, False, 'disabled'),
        (ssl.TLSVersion.TLSv1_3, False, 'disabled'),
        (ssl.TLSVersion.TLSv1_3, True, 'disabled'),
        (ssl.TLSVersion.TLSv1_2, False, 'observe'),
        (ssl.TLSVersion.TLSv1_3, True, 'observe'),
        (ssl.TLSVersion.TLSv1_3, False, 'bypass'),
        (ssl.TLSVersion.TLSv1_3, False, 'unavailable'),
        (ssl.TLSVersion.TLSv1_3, False, 'upstream'),
        (ssl.TLSVersion.TLSv1_3, False, 'upstream-invalid'),
        (ssl.TLSVersion.TLSv1_2, False, 'cipher'),
        (ssl.TLSVersion.TLSv1_3, False, 'cipher'),
        (ssl.TLSVersion.TLSv1_2, False, 'cipher-default'),
    )
    for version, fragmented, mode in cases:
        hello_hook = """
def tls_clienthello(data):
    assert data.client_hello.sni == 'localhost'
    assert data.client_hello.alpn_protocols == [b'http/1.1']
    events.append('hello')
"""
        source = ADDON + hello_hook
        if mode in ('observe', 'upstream', 'upstream-invalid', 'cipher', 'cipher-default'):
            source = source.replace("events == ['server', 'client']", "events == ['hello', 'server', 'client']")
        elif mode == 'bypass':
            source += "    data.ignore_connection = True\n"

        if mode in ('upstream', 'upstream-invalid'):
            source = source.replace(
                "data.client_hello.alpn_protocols == [b'http/1.1']",
                "data.client_hello.alpn_protocols == [b'h2', b'http/1.1']",
            )
            source += (
                "    assert data.context.client.sni == 'localhost'\n"
                "    data.context.server.sni = 'upstream.test'\n"
                "    data.context.server.alpn_offers = [b'http/1.1']\n"
            )

        if mode == 'cipher':
            source += "    data.context.server.cipher_list = ['ECDHE-RSA-AES128-GCM-SHA256']\n"
        elif mode == 'cipher-default':
            source += "    data.context.server.cipher_list = []\n"

        set_relay_mode('invalid-hello' if mode == 'unavailable' else 'forward')
        if mode == 'upstream-invalid':
            set_relay_mode('invalid-upstream')
        deploy(source, tls_clienthello=mode != 'disabled')
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
        if mode == 'upstream':
            context.load_cert_chain(certificates / 'upstream-cert.pem', certificates / 'upstream-key.pem')
            context.set_alpn_protocols(['h2', 'http/1.1'])
        negotiated_ciphers = []
        if mode == 'cipher':
            context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
        server_names = []
        context.set_servername_callback(lambda connection, name, context: server_names.append(name))

        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    raw.settimeout(10)
                    with context.wrap_socket(raw, server_side=True) as tls:
                        negotiated_ciphers.append(tls.cipher()[0])
                        requests.append(read_headers(tls))
                        tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        target = listener.getsockname()[1]
        proxy_port, process = start_proxy(target, verify_identity=mode == 'upstream')
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=10) as raw:

            client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client.check_hostname = False
            client.verify_mode = ssl.CERT_NONE
            client.minimum_version = client.maximum_version = version
            client.set_alpn_protocols(['http/1.1'])
            if mode in ('upstream', 'upstream-invalid'):
                client.set_alpn_protocols(['h2', 'http/1.1'])
            stream = (FragmentedTlsClient(client, raw) if fragmented else
                      client.wrap_socket(raw, server_hostname='localhost'))
            with stream as tls:
                if mode == 'upstream':
                    assert tls.selected_alpn_protocol() == 'http/1.1'
                if mode == 'bypass':
                    expected = ssl.PEM_cert_to_DER_cert((certificates / 'origin-cert.pem').read_text())
                    assert tls.getpeercert(binary_form=True) == expected, 'Bypass still intercepted TLS'
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
        if mode == 'cipher' and version == ssl.TLSVersion.TLSv1_2:
            assert negotiated_ciphers == ['ECDHE-RSA-AES128-GCM-SHA256'], negotiated_ciphers
        if mode == 'cipher' and version == ssl.TLSVersion.TLSv1_3:
            assert negotiated_ciphers[0].startswith('TLS_'), negotiated_ciphers
        if mode == 'upstream':
            assert server_names == ['upstream.test'], server_names
        if mode == 'upstream-invalid':
            assert server_names == ['localhost'], server_names
        assert (b'x-tls-hooks: observed' in requests[0].lower()) == (mode != 'bypass'), requests

        deadline = time.monotonic() + 5
        while not any(event['action'] == 'connection-stop' for event, _, _ in exchanges[offset:]):
            assert time.monotonic() < deadline, 'TLS session did not retire'
            time.sleep(.02)

        events = [entry for entry in exchanges[offset:] if entry[0]['action'] == 'tls-lifecycle']
        assert all(status == 200 for _, _, status in events), events
        outcomes = [entry[0]['details']['tls']['envelope'] for entry in events]
        expected = [('server', 'established'), ('client', 'established')]
        if mode in ('observe', 'unavailable', 'upstream', 'upstream-invalid', 'cipher', 'cipher-default'):
            expected.insert(0, ('client', 'client-hello'))
        elif mode == 'bypass':
            expected = [('client', 'client-hello')]

        assert [(e['side'], e['event']) for e in outcomes] == expected, outcomes
        if mode in ('observe', 'upstream', 'upstream-invalid', 'cipher', 'cipher-default'):
            assert outcomes[0]['attempt'] == outcomes[-1]['attempt'], outcomes
        process.terminate()
        process.wait(timeout=5)
        print(f'PASS: {version.name} fragmented={fragmented} ClientHello={mode} TLS outcomes before HTTP, shared identity, no false failure at close')


def run_tls_failure_cases(deploy, start_proxy, certificates, exchanges, set_relay_mode):
    for failure in ('server', 'client', 'hello', 'strict-hello', 'cipher-invalid', 'cipher-empty', 'cipher-tls13-name'):
        source = ADDON
        if failure == 'hello':
            source += "\ndef tls_clienthello(data):\n    data.context.client.error = 'denied by addon'\n"
        if failure.startswith('cipher-'):
            value = {'cipher-invalid': 'UNKNOWN-CIPHER', 'cipher-empty': '',
                     'cipher-tls13-name': 'TLS_AES_256_GCM_SHA384'}[failure]
            source += f'\ndef tls_clienthello(data):\n    data.context.server.cipher_list = [{value!r}]\n'
        set_relay_mode('strict-hello' if failure == 'strict-hello' else 'forward')
        deploy(source, tls_clienthello=failure in ('hello', 'strict-hello') or failure.startswith('cipher-'))
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
                        if failure in ('hello', 'strict-hello') or failure.startswith('cipher-'):
                            assert not raw.recv(1), 'ClientHello veto sent TLS bytes upstream'
                        elif failure == 'server':
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
        if failure in ('server', 'hello', 'strict-hello') or failure.startswith('cipher-'):
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

        failed_side = 'client' if failure in ('client', 'hello', 'strict-hello') else 'server'
        deadline = time.monotonic() + 8
        while True:
            events = [entry for entry in exchanges[offset:] if entry[0]['action'] == 'tls-lifecycle']
            outcomes = [entry[0]['details']['tls']['envelope'] for entry in events]
            if any(e['side'] == failed_side and e['event'] == 'failed' for e in outcomes):
                break
            assert time.monotonic() < deadline, outcomes
            time.sleep(.02)

        assert all(status == 200 for _, _, status in events), events
        keys = [(e['side'], e['attempt']) for e in outcomes if e['event'] != 'client-hello']
        assert len(keys) == len(set(keys)), 'One TLS attempt reported more than one outcome'
        assert not any(e['side'] == failed_side and e['event'] == 'established' for e in outcomes), outcomes
        if failure == 'client':
            assert any(e['side'] == 'server' and e['event'] == 'established' for e in outcomes), outcomes

        process.terminate()
        process.wait(timeout=5)
        assert origin_finished.wait(12), 'Failed TLS origin did not finish'
        assert not origin_errors, origin_errors
        print(f'PASS: TLS {failure} handshake failure, once-only outcome, no application traffic')
