"""Observe request destination changes in an isolated mitmproxy 12.3.1.

The opt-in black-box probe uses two disposable loopback origins and an
independently installed mitmdump. It never imports reference source.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading
import time


def reserve_listener():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(5)
    return listener


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


def request(port, origin_port, path):
    wire = (
        f"GET http://127.0.0.1:{origin_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{origin_port}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    received = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(5)
        connection.sendall(wire)
        while True:
            chunk = connection.recv(65535)
            if not chunk:
                break
            received.extend(chunk)
    head, body = bytes(received).split(b"\r\n\r\n", 1)
    return {
        "status_line": head.split(b"\r\n", 1)[0].decode("latin-1"),
        "body": body.decode("latin-1"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output", help="Optional JSON corpus destination")
    parser.add_argument("--expect", help="Optional checked-in corpus to verify")
    args = parser.parse_args()

    original = reserve_listener()
    destination = reserve_listener()
    original_port = original.getsockname()[1]
    destination_port = destination.getsockname()[1]
    destination_requests = []
    origin_error = []

    def serve_destination():
        try:
            for _ in range(2):
                connection, _ = destination.accept()
                with connection:
                    connection.settimeout(5)
                    data = bytearray()
                    while b"\r\n\r\n" not in data:
                        chunk = connection.recv(4096)
                        if not chunk:
                            raise RuntimeError("Destination received incomplete headers")
                        data.extend(chunk)
                    head = bytes(data).split(b"\r\n\r\n", 1)[0]
                    lines = head.split(b"\r\n")
                    host = next(
                        line.partition(b":")[2].strip().decode("latin-1")
                        for line in lines[1:]
                        if line.partition(b":")[0].lower() == b"host"
                    )
                    path = lines[0].split(b" ")[1].decode("latin-1")
                    destination_requests.append({"path": path, "host": host})
                    body = path.encode("latin-1")
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
        except Exception as error:
            origin_error.append(repr(error))

    server = threading.Thread(target=serve_destination, daemon=True)
    server.start()

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]
    addon = Path(__file__).with_name("addon_reroute_addon.py")
    process = subprocess.Popen([
        args.reference,
        "--listen-host", "127.0.0.1",
        "--listen-port", str(proxy_port),
        "--set", "connection_strategy=lazy",
        "--set", "termlog_verbosity=error",
        "--set", f"probe_destination_port={destination_port}",
        "-s", str(addon),
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    clients = {}
    try:
        wait_for_proxy(proxy_port, process)
        for path in ("/headers", "/request"):
            clients[path] = request(proxy_port, original_port, path)
        server.join(5)
        original.setblocking(False)
        try:
            leaked, _ = original.accept()
        except BlockingIOError:
            original_contacts = 0
        else:
            leaked.close()
            original_contacts = 1
    finally:
        original.close()
        destination.close()
        process.terminate()
        try:
            output, _ = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()

    if process.returncode not in (0, -15):
        raise RuntimeError(output)
    if origin_error:
        raise RuntimeError("Destination failed: " + repr(origin_error))
    hooks = [
        json.loads(line.removeprefix("PROBE "))
        for line in output.splitlines()
        if line.startswith("PROBE ")
    ]
    # Ephemeral ports are represented by their logical role in the corpus.
    def normalize_endpoint(value):
        value = value.replace(f":{original_port}", ":original")
        return value.replace(f":{destination_port}", ":destination")

    for event in hooks:
        if event["port"] == original_port:
            event["port"] = "original"
        elif event["port"] == destination_port:
            event["port"] = "destination"
        event["host_header"] = normalize_endpoint(event["host_header"])
    for request_observation in destination_requests:
        request_observation["host"] = normalize_endpoint(request_observation["host"])
    result = {
        "reference": "mitmproxy 12.3.1",
        "original_contacts": original_contacts,
        "destination_requests": destination_requests,
        "clients": clients,
        "hooks": hooks,
    }
    if args.expect:
        expected = json.loads(Path(args.expect).read_text())
        if result != expected:
            raise AssertionError("Reference destination-mutation behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
