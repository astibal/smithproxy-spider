"""Prove upstream session reuse with an independent OpenSSL origin."""
import socket
import ssl
import subprocess
import threading
import time

from tls_proxy_cases import read_headers


ADDON = '''
attempts = 0
connections = set()

def tls_start_server(data):
    global attempts
    attempts += 1
    assert data.conn.id not in connections
    connections.add(data.conn.id)
    if attempts == 3:
        data.conn.sni = 'alternate.test'

def tls_established_server(data):
    assert data.conn.tls_established
    assert data.conn.cipher
    assert data.conn.certificate_list

def tls_established_client(data):
    assert data.conn.tls_established
'''


def run_resumption_cases(deploy, start_proxy, certificates, exchanges):
    key = certificates / 'resume-key.pem'
    cert = certificates / 'resume-cert.pem'
    csr = certificates / 'resume.csr'
    extensions = certificates / 'resume.ext'
    extensions.write_text('subjectAltName=DNS:localhost,DNS:alternate.test\n')
    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                    '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(csr)],
                   check=True, capture_output=True)
    subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-days', '1',
                    '-CA', str(certificates / 'ca-cert.pem'),
                    '-CAkey', str(certificates / 'ca-key.pem'), '-CAcreateserial',
                    '-extfile', str(extensions), '-out', str(cert)],
                   check=True, capture_output=True)

    cases = [(version, baseline)
             for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)
             for baseline in (True, False)]
    for version, baseline in cases:
        deploy('' if baseline else ADDON, tls_clienthello=not baseline,
               tls_start_server=not baseline, tls_start_client=not baseline)

        offset = len(exchanges)
        reused = []
        errors = []
        listener = socket.create_server(('127.0.0.1', 0))
        listener.settimeout(15)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(cert, key)

        def serve():
            try:
                with listener:
                    for _ in range(3):
                        raw, _ = listener.accept()
                        raw.settimeout(15)
                        with context.wrap_socket(raw, server_side=True) as tls:
                            reused.append(tls.session_reused)
                            assert read_headers(tls).startswith(b'GET /resume ')
                            tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
                            tls.unwrap().close()
            except Exception as error:
                errors.append(error)

        target = listener.getsockname()[1]
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port, process = start_proxy(target, verify_identity=True, trusted_origin=True)
        downstream = []

        try:
            client = ssl.create_default_context(cafile=str(certificates / 'ca-cert.pem'))
            client.minimum_version = client.maximum_version = version
            session = None
            for index in range(3):
                with socket.create_connection(('127.0.0.1', port), timeout=15) as raw:
                    with client.wrap_socket(raw, server_hostname='localhost', session=session) as tls:
                        downstream.append(tls.session_reused)
                        tls.sendall(b'GET /resume HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                        response = bytearray()
                        while True:
                            chunk = tls.recv(4096)
                            if not chunk:
                                break

                            response.extend(chunk)
                        assert response.endswith(b'ok'), response
                        session = tls.session
                        tls.unwrap().close()

                # Complete retirement before opening the next connection, while
                # keeping the native process, origin context and addon alive.
                deadline = time.monotonic() + 8
                while sum(e['action'] == 'connection-stop' for e, _, _ in exchanges[offset:]) < index + 1:
                    assert time.monotonic() < deadline, 'Resumption session did not retire'
                    time.sleep(.02)

            thread.join(15)
            assert not thread.is_alive(), 'Resumption origin did not finish'
            assert not errors, errors
            expected_upstream = [False, True, True] if baseline else [False, True, False]
            assert reused == expected_upstream, (version.name, reused, downstream)
            assert downstream == [False, True, True], (version.name, downstream)

            events = exchanges[offset:]
            assert all(status == 200 for _, _, status in events), events
            for event, reply, _ in events:
                if event['action'] in ('server-lifecycle', 'tls-lifecycle'):
                    draft = reply.get('outcome') or reply.get('start') or reply.get('client_hello') or {}
                    assert reply.get('proceed') is True or draft.get('decision') == 'continue', reply

            identities = {e['id'] for e, _, _ in events}
            assert len(identities) == 3, identities

            for identity in identities:
                actions = [e['action'] for e, _, _ in events if e['id'] == identity]
                assert actions.count('connection-start') == actions.count('connection-stop') == 1
                servers = [e['details']['server']['envelope']['event'] for e, _, _ in events
                           if e['id'] == identity and e['action'] == 'server-lifecycle']
                assert servers == ['connect', 'connected', 'disconnected'], servers

                tls_events = [e['details']['tls']['envelope'] for e, reply, _ in events
                              if e['id'] == identity and e['action'] == 'tls-lifecycle']
                for side in ('client', 'server'):
                    phases = [e['event'] for e in tls_events if e['side'] == side]
                    assert phases.count('established') == 1, phases
                    assert phases.count('start') == (0 if baseline else 1), phases
                    if not baseline:
                        assert phases.index('start') < phases.index('established'), phases
                    assert len({e['attempt'] for e in tls_events if e['side'] == side}) == 1

            print('PASS resumption hooks:', version.name, 'baseline' if baseline else 'subscribed',
                  'upstream=', reused, 'downstream=', downstream, flush=True)
        finally:
            process.terminate()
            process.wait(timeout=5)
            listener.close()
