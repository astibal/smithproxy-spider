"""Negative SMTP STARTTLS paths without changing native transport behavior."""
import socket
import ssl
import threading
import time

from starttls_hook_cases import ADDON


FAILURE_ADDON = ADDON + '''
def tls_failed_client(data):
    check(data)
    assert data.conn is client and not client.tls_established

def tls_failed_server(data):
    check(data)
    assert data.conn is server and not server.tls_established
'''


def smtp_upgrade(connection, accepted):
    stream = connection.makefile('rwb', buffering=0)
    try:
        stream.write(b'220 origin.test ESMTP ready\r\n')
        assert stream.readline() == b'EHLO client.test\r\n'
        stream.write(b'250-origin.test\r\n250 STARTTLS\r\n')
        assert stream.readline() == b'STARTTLS\r\n'
        response = b'220 Ready to start TLS\r\n' if accepted else b'454 TLS unavailable\r\n'
        stream.write(response)
    finally:
        stream.close()


def request_upgrade(connection, accepted):
    stream = connection.makefile('rwb', buffering=0)
    try:
        assert stream.readline().startswith(b'220 ')
        stream.write(b'EHLO client.test\r\n')
        assert stream.readline().startswith(b'250-')
        assert stream.readline() == b'250 STARTTLS\r\n'
        stream.write(b'STARTTLS\r\n')
        expected = b'220 ' if accepted else b'454 '
        assert stream.readline().startswith(expected)
    finally:
        stream.close()


def run_starttls_failure_cases(deploy, start_proxy, exchanges):
    cases = ('rejected', 'disconnect', 'truncated-hello',
             'upstream-timeout-wakeup', 'upstream-timeout')
    for case in cases:
        deploy(FAILURE_ADDON, tls_clienthello=True, tls_start_server=True, tls_start_client=True)
        offset = len(exchanges)
        accepted = case != 'rejected'
        errors = []
        release = threading.Event()
        listener = socket.create_server(('127.0.0.1', 0))
        listener.settimeout(10)

        def serve():
            try:
                with listener:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(10)
                        smtp_upgrade(connection, accepted)
                        if case.startswith('upstream-timeout'):
                            # Receive the real upstream ClientHello, then deliberately
                            # remain silent until native timeout retires the session.
                            assert connection.recv(4096), 'Missing upstream ClientHello'
                            if case == 'upstream-timeout-wakeup':
                                time.sleep(2)
                                connection.sendall(b'\x16')
                            assert release.wait(12), 'Native handshake did not time out'
                        else:
                            while connection.recv(4096):
                                pass
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        port, process = start_proxy(listener.getsockname()[1], plaintext=True,
                                    handshake_timeout=1000)
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=10) as connection:
                request_upgrade(connection, accepted)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                if case == 'truncated-hello':
                    outgoing = ssl.MemoryBIO()
                    tls = context.wrap_bio(ssl.MemoryBIO(), outgoing,
                                           server_hostname='localhost')
                    try:
                        tls.do_handshake()
                    except ssl.SSLWantReadError:
                        pass
                    hello = outgoing.read()
                    assert len(hello) > 8
                    connection.sendall(hello[:8])

                elif case.startswith('upstream-timeout'):
                    try:
                        with context.wrap_socket(connection, server_hostname='localhost'):
                            raise AssertionError('Silent upstream completed TLS')
                    except ssl.SSLError:
                        pass

            # Closing the client is the stimulus for the early-abort cases.
            # Never terminate the proxy to manufacture a connection-stop event.
            deadline = time.monotonic() + 10
            while not any(e['action'] == 'connection-stop' for e, _, _ in exchanges[offset:]):
                assert time.monotonic() < deadline, f'{case}: session did not retire'
                time.sleep(.02)
            release.set()
            thread.join(3)
            assert not thread.is_alive(), case
            assert not errors, errors

            events = exchanges[offset:]
            assert all(status == 200 for _, _, status in events), events
            for event, reply, _ in events:
                if event['action'] == 'tls-lifecycle':
                    draft = reply.get('outcome') or reply.get('start') or reply.get('client_hello') or {}
                    assert reply.get('proceed') is True or draft.get('decision') == 'continue', reply

            assert len({e['id'] for e, _, _ in events}) == 1, events
            actions = [e['action'] for e, _, _ in events]
            assert actions.count('connection-start') == actions.count('connection-stop') == 1
            assert actions[-1] == 'connection-stop', actions

            servers = [e['details']['server']['envelope']['event'] for e, _, _ in events
                       if e['action'] == 'server-lifecycle']
            assert servers == ['connect', 'connected', 'disconnected'], servers
            tls_events = [e['details']['tls']['envelope'] for e, _, _ in events
                          if e['action'] == 'tls-lifecycle']
            observed = [(e['side'], e['event']) for e in tls_events]
            assert not any(event == 'established' for _, event in observed), observed
            for side in ('client', 'server'):
                assert observed.count((side, 'failed')) <= 1, observed
                attempts = {e['attempt'] for e in tls_events if e['side'] == side}
                assert len(attempts) <= 1, attempts

            if case == 'rejected':
                assert not tls_events, observed
            if case == 'disconnect':
                # Upgrade acceptance creates native TLS attempts before a
                # complete ClientHello can reach the subscribed start hooks.
                assert set(observed) == {('client', 'failed'), ('server', 'failed')}, observed
            if case.startswith('upstream-timeout'):
                assert ('server', 'start') in observed, observed
                assert ('server', 'failed') in observed, observed
                assert observed.index(('server', 'start')) < observed.index(('server', 'failed'))
            print('PASS STARTTLS failure:', case, observed, flush=True)
        finally:
            release.set()
            process.terminate()
            process.wait(timeout=5)
            listener.close()
            thread.join(3)
