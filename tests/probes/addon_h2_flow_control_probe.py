"""Observe multiplexed HTTP/2 local responses across flow-control windows.

The probe treats mitmproxy 12.3.1 as a black box.  The addon answers locally,
so the CONNECT target is never contacted.  The large response exceeds both the
initial stream and connection windows while a small sibling shares the same
client-side HTTP/2 connection.
"""

import argparse
import hashlib
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
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError(
                "Reference proxy exited before accepting connections\n" + output
            )
        try:
            connection = socket.create_connection(("127.0.0.1", port), timeout=.2)
        except OSError:
            time.sleep(.05)
            continue
        connection.close()
        return
    raise TimeoutError("Reference proxy did not start within five seconds")


def summarize(status, headers, body, ended):
    selected = [
        [name.decode("latin-1"), value.decode("latin-1")]
        for name, value in headers
        if name in (b"content-length", b"x-flow-case")
    ]
    return {
        "status": status,
        "headers": selected,
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "ended": ended,
    }


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

    streams = ((1, "/large"), (3, "/small"))
    observed = {
        stream_id: {"status": None, "headers": [], "body": bytearray(), "ended": False}
        for stream_id, _ in streams
    }
    with context.wrap_socket(raw, server_hostname="example.invalid") as connection:
        if connection.selected_alpn_protocol() != "h2":
            raise RuntimeError("Reference did not negotiate HTTP/2")
        client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True, header_encoding=None)
        )
        client.initiate_connection()
        for stream_id, path in streams:
            client.send_headers(stream_id, [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", b"example.invalid"),
                (b":path", path.encode("ascii")),
            ], end_stream=True)
        connection.sendall(client.data_to_send())

        completed = set()
        while len(completed) < len(streams):
            data = connection.recv(65535)
            if not data:
                raise RuntimeError("Reference closed before both streams completed")
            for event in client.receive_data(data):
                stream_id = getattr(event, "stream_id", None)
                if stream_id not in observed:
                    continue
                current = observed[stream_id]
                if isinstance(event, h2.events.ResponseReceived):
                    current["headers"] = event.headers
                    current["status"] = int(dict(event.headers)[b":status"])
                elif isinstance(event, h2.events.DataReceived):
                    current["body"].extend(event.data)
                    client.acknowledge_received_data(
                        event.flow_controlled_length,
                        event.stream_id,
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    current["ended"] = True
                    completed.add(event.stream_id)
            pending = client.data_to_send()
            if pending:
                connection.sendall(pending)

    paths = {stream_id: path for stream_id, path in streams}
    return {
        paths[stream_id]: summarize(
            current["status"],
            current["headers"],
            bytes(current["body"]),
            current["ended"],
        )
        for stream_id, current in observed.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    arguments = parser.parse_args()

    port = reserve_port()
    addon = Path(__file__).with_name("addon_h2_flow_control_addon.py")
    process = subprocess.Popen([
        arguments.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    try:
        wait_for_proxy(port, process)
        responses = exchange(port)
    finally:
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    result = {
        "reference": "mitmproxy 12.3.1",
        "responses": responses,
    }
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference HTTP/2 flow-control behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
