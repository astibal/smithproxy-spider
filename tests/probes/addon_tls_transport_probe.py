"""Observe live TLS addon hooks in mitmproxy 12.3.1.

The opt-in black-box probe places an independently installed mitmdump between a
local TLS client and a disposable local TLS origin. It records only public hook
arguments and stable connection state, never reference implementation source.
"""

import argparse
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time


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


def read_head(connection):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before complete HTTP headers")
        data.extend(chunk)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--certificate", required=True, help="Disposable origin certificate")
    parser.add_argument("--key", required=True, help="Disposable origin private key")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    origin = socket.socket()
    origin.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    origin_port = origin.getsockname()[1]
    origin_error = []
    origin_observation = {}

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(args.certificate, args.key)
    server_context.set_alpn_protocols(["http/1.1"])

    def serve():
        try:
            raw, _ = origin.accept()
            with raw:
                with server_context.wrap_socket(raw, server_side=True) as connection:
                    request = read_head(connection)
                    origin_observation["request_line"] = request.split(b"\r\n", 1)[0].decode("latin-1")
                    origin_observation["alpn"] = connection.selected_alpn_protocol()
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 2\r\n"
                        b"Connection: close\r\n\r\nok"
                    )
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve, daemon=True)
    server.start()

    proxy_port = reserve_port()
    addon = Path(__file__).with_name("addon_tls_transport_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=eager",
        "--set", "ssl_insecure=true",
        "--set", "termlog_verbosity=error",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    client_observation = {}
    try:
        wait_for_proxy(proxy_port, process)
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
        raw.settimeout(5)
        connect_request = (
            f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n\r\n"
        )
        raw.sendall(connect_request.encode("ascii"))
        connect_response = read_head(raw)
        client_observation["connect_status"] = connect_response.split(b"\r\n", 1)[0].decode("latin-1")

        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.set_alpn_protocols(["http/1.1"])
        with client_context.wrap_socket(raw, server_hostname="probe.invalid") as connection:
            client_observation["alpn"] = connection.selected_alpn_protocol()
            connection.sendall(b"GET /tls HTTP/1.1\r\nHost: probe.invalid\r\nConnection: close\r\n\r\n")
            response = bytearray()
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            client_observation["status_line"] = bytes(response).split(b"\r\n", 1)[0].decode("latin-1")
            client_observation["body"] = bytes(response).partition(b"\r\n\r\n")[2].decode("latin-1")
        server.join(5)
        time.sleep(.1)
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
        "origin": origin_observation,
        "client": client_observation,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference TLS behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
