"""Our STARTTLS extension: preserve TCP identity while adding a TLS layer."""
import base64
import importlib.util
import socket
import ssl
import threading
import time


ADDON = '''
client = None
server = None
tcp_setup = None

def client_connected(data):
    global client
    assert client is None, 'STARTTLS invented a second client connection'
    client = data

def server_connected(data):
    global server, tcp_setup
    assert server is None, 'STARTTLS invented a second TCP completion'
    server = data.server
    tcp_setup = server.timestamp_tcp_setup
    assert not server.tls_established

def check(data):
    assert data.context.client is client
    assert data.context.server is server
    assert server.timestamp_tcp_setup == tcp_setup

def tls_clienthello(data):
    check(data)

def tls_start_server(data):
    check(data)
    assert data.conn is server
    assert server.timestamp_tcp_setup is not None

def tls_start_client(data):
    check(data)
    assert data.conn is client

def tls_established_server(data):
    check(data)
    assert data.conn is server and server.tls_established

def tls_established_client(data):
    check(data)
    assert data.conn is client and client.tls_established
'''


def receive_line(connection):
    # Application reads may split even these small payloads across TLS records.
    data = bytearray()
    while not data.endswith(b'\r\n'):
        chunk = connection.recv(1024)
        assert chunk, 'EOF before the protected line completed'
        data.extend(chunk)
        assert len(data) <= 1024, 'Unexpected protected payload'
    return bytes(data)


def run_starttls_cases(deploy, start_proxy, certificates, exchanges, native_source):
    # Reuse the actual signature-suite plaintext exchanges, not approximations.
    path = native_source / 'tests/patch-runner/harness/suites/starttls/run.py'
    spec = importlib.util.spec_from_file_location('starttls_dialogs', path)
    dialogs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dialogs)

    cases = [(name, version) for name in dialogs.CASES
             for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3)]
    for name, version in cases:
        deploy(ADDON, tls_clienthello=True, tls_start_server=True, tls_start_client=True)
        offset = len(exchanges)
        errors = []
        listener = socket.create_server(('127.0.0.1', 0))
        listener.settimeout(12)
        target = listener.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = version
        context.load_cert_chain(certificates / 'ca-cert.pem', certificates / 'ca-key.pem')

        def serve():
            try:
                with listener:
                    raw, _ = listener.accept()
                    raw.settimeout(12)
                    with raw:
                        stream = raw.makefile('rwb', buffering=0)
                        dialogs.server_dialog(name, stream)
                        stream.close()
                        with context.wrap_socket(raw, server_side=True) as tls:
                            assert receive_line(tls) == b'protected ping\r\n'
                            tls.sendall(b'protected pong\r\n')
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port, process = start_proxy(target, plaintext=True)
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=12) as raw:
                stream = raw.makefile('rwb', buffering=0)
                dialogs.client_dialog(name, stream)
                stream.close()
                client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client.minimum_version = client.maximum_version = version
                client.check_hostname = False
                client.verify_mode = ssl.CERT_NONE
                with client.wrap_socket(raw, server_hostname='localhost') as tls:
                    tls.sendall(b'protected ping\r\n')
                    assert receive_line(tls) == b'protected pong\r\n'

            thread.join(14)
            assert not thread.is_alive(), 'STARTTLS origin did not finish'
            assert not errors, errors
            deadline = time.monotonic() + 8
            while not any(e['action'] == 'connection-stop' for e, _, _ in exchanges[offset:]):
                assert time.monotonic() < deadline, 'STARTTLS session did not retire'
                time.sleep(.02)

            events = exchanges[offset:]
            assert all(status == 200 for _, _, status in events), events
            assert len({event['id'] for event, _, _ in events}) == 1, events
            actions = [event['action'] for event, _, _ in events]
            assert actions.count('connection-start') == actions.count('connection-stop') == 1
            for event, reply, _ in events:
                if event['action'] in ('server-lifecycle', 'tls-lifecycle'):
                    assert reply.get('proceed') is True, reply
            servers = [e['details']['server']['envelope']['event'] for e, _, _ in events
                       if e['action'] == 'server-lifecycle']
            assert servers == ['connect', 'connected', 'disconnected'], servers
            tls_events = [e['details']['tls']['envelope'] for e, _, _ in events
                          if e['action'] == 'tls-lifecycle']
            observed = [(e['side'], e['event']) for e in tls_events]
            for side in ('client', 'server'):
                assert observed.count((side, 'start')) == 1, observed
                assert observed.count((side, 'established')) == 1, observed
                assert observed.index((side, 'start')) < observed.index((side, 'established')), observed
                attempts = {e['attempt'] for e in tls_events if e['side'] == side}
                assert len(attempts) == 1, tls_events
            assert observed.count(('client', 'client-hello')) == 1, observed
            # Protected application bytes must follow both successful outcomes.
            established = [index for index, (event, _, _) in enumerate(events)
                           if event['action'] == 'tls-lifecycle'
                           and event['details']['tls']['envelope']['event'] == 'established']
            protected = [index for index, (event, _, _) in enumerate(events)
                         if event['action'] == 'connection-content'
                         and base64.b64decode(event['details']['info']['content']).startswith(b'protected ')]
            assert protected and max(established) < min(protected), events
            print('PASS STARTTLS hooks:', name, version.name, observed, flush=True)
        finally:
            process.terminate()
            process.wait(timeout=5)
            listener.close()
