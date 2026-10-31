"""Record one end-to-end HTTP/2 addon mutation from mitmproxy 12.3.1."""

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import h2.config
import h2.connection
import h2.events


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_live_http_contract import (
    ADDON_SOURCE, PIPELINE_SOURCE, TRAILER_SOURCE, selected_headers,
)


def reserve_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError("Reference proxy exited before accepting connections\n" + output)
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not start within five seconds")


def make_certificate(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "origin.test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("origin.test")]), False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = Path(directory) / "origin.pem"
    key_path = Path(directory) / "origin.key"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return certificate_path, key_path


def exchange(proxy_port, origin_port):
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
    raw.settimeout(5)
    authority = f"127.0.0.1:{origin_port}".encode()
    raw.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n")
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = raw.recv(4096)
        if not chunk:
            raise RuntimeError("Reference closed the CONNECT handshake")
        response.extend(chunk)
    if not response.startswith(b"HTTP/1.1 200 "):
        raise RuntimeError("Reference rejected CONNECT: " + repr(bytes(response)))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with context.wrap_socket(raw, server_hostname="origin.test") as connection:
        if connection.selected_alpn_protocol() != "h2":
            raise RuntimeError("Reference did not negotiate HTTP/2")
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        client.initiate_connection()
        client.send_headers(1, [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", authority),
            (b":path", b"/original-h2"),
            (b"x-client", b"1"),
            (b"content-type", b"application/octet-stream"),
            (b"content-length", b"7"),
        ], end_stream=False)
        client.send_data(1, b"old-one", end_stream=True)
        connection.sendall(client.data_to_send())

        headers = []
        body = bytearray()
        complete = False
        while not complete:
            data = connection.recv(65535)
            if not data:
                raise RuntimeError("Reference closed the HTTP/2 response")
            for event in client.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    headers = event.headers
                elif isinstance(event, h2.events.DataReceived):
                    body.extend(event.data)
                    client.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    complete = True
            pending = client.data_to_send()
            if pending:
                connection.sendall(pending)

    status = next(value for name, value in headers if name == b":status")
    regular = [(name.decode("latin-1"), value.decode("latin-1"))
               for name, value in headers if not name.startswith(b":")]
    return {
        "status": int(status),
        "headers": selected_headers(regular),
        "body": body.decode("latin-1"),
    }


def exchange_multiplex(proxy_port, origin_port):
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
    raw.settimeout(5)
    authority = f"127.0.0.1:{origin_port}".encode()
    raw.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n")
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = raw.recv(4096)
        if not chunk:
            raise RuntimeError("Reference closed the CONNECT handshake")
        response.extend(chunk)
    if not response.startswith(b"HTTP/1.1 200 "):
        raise RuntimeError("Reference rejected CONNECT: " + repr(bytes(response)))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with context.wrap_socket(raw, server_hostname="origin.test") as connection:
        if connection.selected_alpn_protocol() != "h2":
            raise RuntimeError("Reference did not negotiate HTTP/2")
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        client.initiate_connection()
        for stream_id, original in ((1, b"first"), (3, b"second")):
            client.send_headers(stream_id, [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", authority),
                (b":path", b"/" + original),
                (b"content-length", b"0"),
            ], end_stream=True)
        connection.sendall(client.data_to_send())

        responses = {
            1: {"headers": [], "body": bytearray()},
            3: {"headers": [], "body": bytearray()},
        }
        completed = set()
        while len(completed) < 2:
            data = connection.recv(65535)
            if not data:
                raise RuntimeError("Reference closed the HTTP/2 response")
            for event in client.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    responses[event.stream_id]["headers"] = event.headers
                elif isinstance(event, h2.events.DataReceived):
                    responses[event.stream_id]["body"].extend(event.data)
                    client.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    completed.add(event.stream_id)
            pending = client.data_to_send()
            if pending:
                connection.sendall(pending)

    result = []
    for stream_id in (1, 3):
        headers = responses[stream_id]["headers"]
        status = next(value for name, value in headers if name == b":status")
        regular = [(name.decode("latin-1"), value.decode("latin-1"))
                   for name, value in headers if not name.startswith(b":")]
        result.append({
            "stream": stream_id,
            "status": int(status),
            "headers": selected_headers(regular),
            "body": responses[stream_id]["body"].decode("latin-1"),
        })
    return result


def trailer_values(fields):
    return [
        [name.decode("latin-1"), value.decode("latin-1")]
        for name, value in fields
        if name in (b"x-addon-trailer", b"x-input-trailer", b"x-remove")
    ]


def exchange_trailers(proxy_port, origin_port):
    raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
    raw.settimeout(5)
    authority = f"127.0.0.1:{origin_port}".encode()
    raw.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n")
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = raw.recv(4096)
        if not chunk:
            raise RuntimeError("Reference closed the CONNECT handshake")
        response.extend(chunk)
    if not response.startswith(b"HTTP/1.1 200 "):
        raise RuntimeError("Reference rejected CONNECT: " + repr(bytes(response)))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    with context.wrap_socket(raw, server_hostname="origin.test") as connection:
        if connection.selected_alpn_protocol() != "h2":
            raise RuntimeError("Reference did not negotiate HTTP/2")
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        client.initiate_connection()
        client.send_headers(1, [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", authority),
            (b":path", b"/trailers"),
            (b"content-length", b"7"),
        ], end_stream=False)
        client.send_data(1, b"old-one", end_stream=False)
        client.send_headers(1, [
            (b"x-input-trailer", b"request"),
            (b"x-remove", b"request"),
        ], end_stream=True)
        connection.sendall(client.data_to_send())

        headers = []
        trailers = []
        body = bytearray()
        complete = False
        while not complete:
            data = connection.recv(65535)
            if not data:
                raise RuntimeError("Reference closed the HTTP/2 response")
            for event in client.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    headers = event.headers
                elif isinstance(event, h2.events.DataReceived):
                    body.extend(event.data)
                    client.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.TrailersReceived):
                    trailers = event.headers
                elif isinstance(event, h2.events.StreamEnded):
                    complete = True
            pending = client.data_to_send()
            if pending:
                connection.sendall(pending)

    status = next(value for name, value in headers if name == b":status")
    return {
        "status": int(status),
        "body": body.decode("latin-1"),
        "trailers": trailer_values(trailers),
    }


def serve_origin(listener, context, observed, errors):
    try:
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as connection:
            if connection.selected_alpn_protocol() != "h2":
                raise RuntimeError("Reference did not negotiate HTTP/2 upstream")
            server = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=False, header_encoding=None)
            )
            server.initiate_connection()
            connection.sendall(server.data_to_send())
            headers = []
            body = bytearray()
            stream_id = None
            complete = False
            while not complete:
                data = connection.recv(65535)
                if not data:
                    raise RuntimeError("Reference closed the upstream HTTP/2 request")
                for event in server.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        headers = event.headers
                        stream_id = event.stream_id
                    elif isinstance(event, h2.events.DataReceived):
                        body.extend(event.data)
                        server.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        complete = True
                pending = server.data_to_send()
                if pending:
                    connection.sendall(pending)

            pseudo = dict((name, value) for name, value in headers
                          if name.startswith(b":"))
            regular = [(name.decode("latin-1"), value.decode("latin-1"))
                       for name, value in headers if not name.startswith(b":")]
            observed.append({
                "method": pseudo[b":method"].decode("latin-1"),
                "path": pseudo[b":path"].decode("latin-1"),
                "headers": selected_headers(regular),
                "body": body.decode("latin-1"),
            })
            server.send_headers(stream_id, [
                (b":status", b"201"),
                (b"content-type", b"text/plain"),
                (b"x-origin", b"1"),
                (b"content-length", b"8"),
            ], end_stream=False)
            server.send_data(stream_id, b"origin-1", end_stream=True)
            connection.sendall(server.data_to_send())
    except Exception as error:
        errors.append(error)


def serve_origin_multiplex(listener, context, observed, errors):
    try:
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as connection:
            if connection.selected_alpn_protocol() != "h2":
                raise RuntimeError("Reference did not negotiate HTTP/2 upstream")
            server = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=False, header_encoding=None)
            )
            server.initiate_connection()
            connection.sendall(server.data_to_send())
            requests = {}
            completed = set()
            while len(completed) < 2:
                data = connection.recv(65535)
                if not data:
                    raise RuntimeError("Reference closed the upstream HTTP/2 request")
                for event in server.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        requests[event.stream_id] = event.headers
                    elif isinstance(event, h2.events.DataReceived):
                        server.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        completed.add(event.stream_id)
                pending = server.data_to_send()
                if pending:
                    connection.sendall(pending)

            ordered = sorted(requests)
            for sequence, stream_id in enumerate(ordered, 1):
                headers = requests[stream_id]
                pseudo = dict((name, value) for name, value in headers
                              if name.startswith(b":"))
                regular = [(name.decode("latin-1"), value.decode("latin-1"))
                           for name, value in headers if not name.startswith(b":")]
                observed.append({
                    "method": pseudo[b":method"].decode("latin-1"),
                    "path": pseudo[b":path"].decode("latin-1"),
                    "headers": selected_headers(regular),
                })

            # Reverse completion order to prove response hooks retain the flow
            # selected by stream identity, not by callback arrival order.
            for sequence, stream_id in reversed(tuple(enumerate(ordered, 1))):
                body = f"origin-{sequence}".encode()
                server.send_headers(stream_id, [
                    (b":status", b"200"),
                    (b"x-origin", str(sequence).encode()),
                    (b"content-length", str(len(body)).encode()),
                ], end_stream=False)
                server.send_data(stream_id, body, end_stream=True)
            connection.sendall(server.data_to_send())
    except Exception as error:
        errors.append(error)


def serve_origin_trailers(listener, context, observed, errors):
    try:
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as connection:
            if connection.selected_alpn_protocol() != "h2":
                raise RuntimeError("Reference did not negotiate HTTP/2 upstream")
            server = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=False, header_encoding=None)
            )
            server.initiate_connection()
            connection.sendall(server.data_to_send())
            headers = []
            trailers = []
            body = bytearray()
            stream_id = None
            complete = False
            while not complete:
                data = connection.recv(65535)
                if not data:
                    raise RuntimeError("Reference closed the upstream HTTP/2 request")
                for event in server.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        headers = event.headers
                        stream_id = event.stream_id
                    elif isinstance(event, h2.events.DataReceived):
                        body.extend(event.data)
                        server.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.TrailersReceived):
                        trailers = event.headers
                    elif isinstance(event, h2.events.StreamEnded):
                        complete = True
                pending = server.data_to_send()
                if pending:
                    connection.sendall(pending)

            pseudo = dict((name, value) for name, value in headers
                          if name.startswith(b":"))
            observed.append({
                "method": pseudo[b":method"].decode("latin-1"),
                "path": pseudo[b":path"].decode("latin-1"),
                "body": body.decode("latin-1"),
                "trailers": trailer_values(trailers),
            })
            server.send_headers(stream_id, [
                (b":status", b"201"),
                (b"content-length", b"8"),
            ], end_stream=False)
            server.send_data(stream_id, b"origin-1", end_stream=False)
            server.send_headers(stream_id, [
                (b"x-input-trailer", b"response"),
                (b"x-remove", b"response"),
            ], end_stream=True)
            connection.sendall(server.data_to_send())
    except Exception as error:
        errors.append(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output")
    parser.add_argument("--expect")
    parser.add_argument("--multiplex", action="store_true")
    parser.add_argument("--trailers", action="store_true")
    arguments = parser.parse_args()
    if arguments.multiplex and arguments.trailers:
        parser.error("--multiplex and --trailers are mutually exclusive")

    observed = []
    origin_errors = []

    with tempfile.TemporaryDirectory(prefix="addon-live-h2-") as directory:
        certificate, key = make_certificate(directory)
        origin = socket.socket()
        origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        origin_port = origin.getsockname()[1]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        context.set_alpn_protocols(["h2"])
        origin_handler = serve_origin
        if arguments.multiplex:
            origin_handler = serve_origin_multiplex
        elif arguments.trailers:
            origin_handler = serve_origin_trailers
        server = threading.Thread(
            target=origin_handler,
            args=(origin, context, observed, origin_errors),
            daemon=True,
        )
        server.start()

        addon = Path(directory) / "addon.py"
        addon_source = ADDON_SOURCE
        if arguments.multiplex:
            addon_source = PIPELINE_SOURCE
        elif arguments.trailers:
            addon_source = TRAILER_SOURCE
        addon.write_text(addon_source)
        proxy_port = reserve_port()
        process = subprocess.Popen([
            arguments.reference,
            "--listen-host", "127.0.0.1",
            "--listen-port", str(proxy_port),
            "--set", "ssl_insecure=true",
            "--set", "termlog_verbosity=error",
            "-s", str(addon),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            wait_for_proxy(proxy_port, process)
            if arguments.multiplex:
                response = exchange_multiplex(proxy_port, origin_port)
            elif arguments.trailers:
                response = exchange_trailers(proxy_port, origin_port)
            else:
                response = exchange(proxy_port, origin_port)
        finally:
            origin.close()
            process.terminate()
            try:
                output, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    server.join(5)
    if server.is_alive():
        raise TimeoutError("Upstream HTTP/2 server did not finish")
    if origin_errors:
        raise origin_errors[0]
    if arguments.multiplex:
        result = {
            "reference": "mitmproxy 12.3.1",
            "requests": observed,
            "responses": response,
        }
    elif arguments.trailers:
        result = {
            "reference": "mitmproxy 12.3.1",
            "request": observed[0],
            "response": response,
        }
    else:
        result = {
            "reference": "mitmproxy 12.3.1",
            "request": observed[0],
            "response": response,
        }
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference live HTTP/2 behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
