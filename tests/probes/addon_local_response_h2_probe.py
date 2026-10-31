"""Observe an HTTP/2 local response in an isolated mitmproxy 12.3.1.

The probe uses a CONNECT tunnel only to establish the reference proxy's client
side TLS session. The addon answers locally, so no origin server is contacted.
Reference implementation source is never imported.
"""

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
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


def exchange(port):
    raw = socket.create_connection(("127.0.0.1", port), timeout=2)
    raw.settimeout(5)
    raw.sendall(
        b"CONNECT example.invalid:443 HTTP/1.1\r\n"
        b"Host: example.invalid:443\r\n\r\n"
    )
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

    requests = (
        (1, "/headers"),
        (3, "/h2"),
        (5, "/empty"),
        (7, "/trailers"),
    )
    responses = {
        path: {
            "headers": None,
            "body": bytearray(),
            "trailers": None,
            "events": [],
        }
        for _, path in requests
    }
    paths = {stream_id: path for stream_id, path in requests}
    connection_events = []
    with context.wrap_socket(raw, server_hostname="example.invalid") as connection:
        if connection.selected_alpn_protocol() != "h2":
            raise RuntimeError("Reference did not negotiate HTTP/2")
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(
                client_side=True,
                header_encoding=None,
                validate_inbound_headers=False,
                normalize_inbound_headers=False,
            )
        )
        client.initiate_connection()
        for stream_id, path in requests:
            client.send_headers(stream_id, [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"example.invalid"),
                (b":path", path.encode("ascii")),
                (b"content-length", b"4"),
            ], end_stream=False)
            client.send_data(stream_id, b"test", end_stream=True)
        connection.sendall(client.data_to_send())

        completed = set()
        while len(completed) != len(requests):
            data = connection.recv(65535)
            if not data:
                break
            for event in client.receive_data(data):
                name = type(event).__name__
                stream_id = getattr(event, "stream_id", 0)
                if stream_id in paths:
                    observed = responses[paths[stream_id]]
                    observed["events"].append(name)
                else:
                    connection_events.append(name)
                if isinstance(event, h2.events.ResponseReceived):
                    observed["headers"] = [
                        [header.decode("latin-1"), value.decode("latin-1")]
                        for header, value in event.headers
                    ]
                elif isinstance(event, h2.events.DataReceived):
                    observed["body"].extend(event.data)
                    client.acknowledge_received_data(event.flow_controlled_length,
                                                     event.stream_id)
                elif isinstance(event, h2.events.TrailersReceived):
                    observed["trailers"] = [
                        [header.decode("latin-1"), value.decode("latin-1")]
                        for header, value in event.headers
                    ]
                elif isinstance(event, h2.events.StreamEnded):
                    completed.add(event.stream_id)
            pending = client.data_to_send()
            if pending:
                connection.sendall(pending)

    if len(completed) != len(requests):
        raise RuntimeError("Reference did not complete every local response")
    for observed in responses.values():
        observed["body"] = observed["body"].decode("latin-1")
    return {"connection_events": connection_events, "responses": responses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    port = reserve_port()
    addon = Path(__file__).with_name("addon_local_response_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(port, process)
        exchange_result = exchange(port)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    result = {
        "reference": "mitmproxy 12.3.1",
        **exchange_result,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference HTTP/2 local-response behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
