"""Observe flow.kill isolation between two HTTP/2 streams in mitmproxy 12.3.1.

The opt-in black-box probe invokes an independently installed mitmdump and a
disposable TLS H2 origin. It never imports reference implementation source.
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


def reserve_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


def wait_for_proxy(port, process):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Reference proxy exited before accepting connections")
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not start within five seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--certificate", required=True, help="Disposable PEM certificate")
    parser.add_argument("--private-key", required=True, help="Disposable PEM private key")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    parser.add_argument(
        "--late-data",
        action="store_true",
        help="Kill at requestheaders and send a fragmented body already in flight",
    )
    args = parser.parse_args()

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(args.certificate, args.private_key)
    server_context.set_alpn_protocols(["h2"])
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    client_context.set_alpn_protocols(["h2"])

    origin = socket.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    origin.settimeout(5)
    origin_port = origin.getsockname()[1]
    origin_paths = []
    origin_error = []

    def serve():
        try:
            raw, _ = origin.accept()
            raw.settimeout(5)
            with server_context.wrap_socket(raw, server_side=True) as connection:
                if connection.selected_alpn_protocol() != "h2":
                    raise RuntimeError("Proxy did not negotiate HTTP/2 with origin")
                server = h2.connection.H2Connection(
                    h2.config.H2Configuration(client_side=False, header_encoding=None)
                )
                server.initiate_connection()
                connection.sendall(server.data_to_send())
                done = False
                while not done:
                    data = connection.recv(65535)
                    if not data:
                        break
                    for event in server.receive_data(data):
                        if isinstance(event, h2.events.RequestReceived):
                            path = dict(event.headers)[b":path"].decode("latin-1")
                            origin_paths.append(path)
                        elif isinstance(event, h2.events.DataReceived):
                            server.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id)
                        elif isinstance(event, h2.events.StreamEnded):
                            server.send_headers(event.stream_id, [
                                (b":status", b"200"),
                                (b"content-length", b"8"),
                            ])
                            server.send_data(event.stream_id, b"survived", end_stream=True)
                            done = True
                    pending = server.data_to_send()
                    if pending:
                        connection.sendall(pending)
        except Exception as error:
            origin_error.append(repr(error))

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_kill_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--ssl-insecure",
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_events = []
    client_late_data = []
    try:
        wait_for_proxy(proxy_port, process)
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
        raw.settimeout(5)
        raw.sendall((
            f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n\r\n"
        ).encode("ascii"))
        handshake = bytearray()
        while b"\r\n\r\n" not in handshake:
            chunk = raw.recv(4096)
            if not chunk:
                raise RuntimeError("Reference closed the CONNECT handshake")
            handshake.extend(chunk)
        if not handshake.startswith(b"HTTP/1.1 200 "):
            raise RuntimeError("Reference rejected CONNECT: " + repr(bytes(handshake)))

        with client_context.wrap_socket(raw, server_hostname="localhost") as connection:
            if connection.selected_alpn_protocol() != "h2":
                raise RuntimeError("Reference did not negotiate HTTP/2 with client")
            client = h2.connection.H2Connection(
                h2.config.H2Configuration(client_side=True, header_encoding=None)
            )
            client.initiate_connection()
            authority = f"127.0.0.1:{origin_port}".encode("ascii")
            if args.late_data:
                client.send_headers(1, [
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", authority),
                    (b":path", b"/kill-headers"),
                    (b"content-length", b"8"),
                ], end_stream=False)
                connection.sendall(client.data_to_send())

                # Do not receive the reset before sending these frames. This
                # models body bytes already in flight when requestheaders kills
                # the stream while keeping the local H2 state writable.
                time.sleep(.1)
                for chunk, end_stream in ((b"late", False), (b"body", True)):
                    client.send_data(1, chunk, end_stream=end_stream)
                    connection.sendall(client.data_to_send())
                    client_late_data.append({
                        "body": chunk.decode("ascii"),
                        "end_stream": end_stream,
                    })

                requests = ((3, b"/survive"),)
            else:
                requests = ((1, b"/kill-h2"), (3, b"/survive"))

            for stream, path in requests:
                client.send_headers(stream, [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", authority),
                    (b":path", path),
                ], end_stream=True)
            connection.sendall(client.data_to_send())

            reset = ended = False
            while not (reset and ended):
                data = connection.recv(65535)
                if not data:
                    break
                for event in client.receive_data(data):
                    if isinstance(event, h2.events.StreamReset):
                        client_events.append({
                            "type": "StreamReset",
                            "stream": event.stream_id,
                            "error": int(event.error_code),
                        })
                        reset = event.stream_id == 1
                    elif isinstance(event, h2.events.ResponseReceived):
                        client_events.append({
                            "type": "ResponseReceived",
                            "stream": event.stream_id,
                            "status": dict(event.headers)[b":status"].decode("ascii"),
                        })
                    elif isinstance(event, h2.events.DataReceived):
                        client_events.append({
                            "type": "DataReceived",
                            "stream": event.stream_id,
                            "body": event.data.decode("latin-1"),
                        })
                        client.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        client_events.append({
                            "type": "StreamEnded",
                            "stream": event.stream_id,
                        })
                        ended = event.stream_id == 3
                pending = client.data_to_send()
                if pending:
                    connection.sendall(pending)
        server_thread.join(5)
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
    if origin_error:
        raise RuntimeError("Origin failed: " + repr(origin_error))
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        "origin_paths": origin_paths,
        "client_events": client_events,
        "hooks": hooks,
    }
    if args.late_data:
        result["client_late_data"] = client_late_data
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference multiplexed flow.kill behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
