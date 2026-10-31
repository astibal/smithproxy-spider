"""Record two pipelined HTTP/1 exchanges from mitmproxy 12.3.1."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_live_http_contract import PIPELINE_SOURCE, parse_http1_stream, selected_headers


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


def receive_messages(connection, count):
    data = bytearray()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            chunk = connection.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(chunk)
        try:
            messages = parse_http1_stream(bytes(data))
        except AssertionError:
            continue
        if len(messages) == count:
            return messages
    raise TimeoutError("Did not receive both pipelined responses")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()
    observed_requests = []

    class Origin(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            observed_requests.append({
                "method": self.command,
                "path": self.path,
                "headers": selected_headers(self.headers.raw_items()),
            })
            sequence = len(observed_requests)
            self.send_response(200, f"Origin {sequence}")
            self.send_header("X-Origin", str(sequence))
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    server = threading.Thread(target=origin.serve_forever, daemon=True)
    server.start()
    proxy_port = reserve_port()

    with tempfile.TemporaryDirectory(prefix="addon-live-pipeline-") as directory:
        addon = Path(directory) / "addon.py"
        addon.write_text(PIPELINE_SOURCE)
        process = subprocess.Popen([
            arguments.reference,
            "--mode", f"reverse:http://127.0.0.1:{origin.server_port}",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(proxy_port),
            "--set", "termlog_verbosity=error",
            "-s", str(addon),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        responses = None
        try:
            wait_for_proxy(proxy_port, process)
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=1) as client:
                client.settimeout(.2)
                client.sendall(
                    b"GET /first HTTP/1.1\r\nHost: input.example\r\n"
                    b"Content-Length: 0\r\n\r\n"
                    b"GET /second HTTP/1.1\r\nHost: input.example\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                responses = receive_messages(client, 2)
        finally:
            origin.shutdown()
            origin.server_close()
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
        "requests": observed_requests,
        "responses": responses,
    }
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference HTTP pipeline behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
