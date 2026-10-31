"""Record end-to-end HTTP addon mutations from mitmproxy 12.3.1."""

import argparse
import gzip
from http.client import HTTPConnection
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

from addon_live_http_contract import ADDON_SOURCE, decoded_body, selected_headers


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()

    observed_requests = []

    class Origin(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_PUT(self):
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length)
            observed_requests.append({
                "method": self.command,
                "path": self.path,
                "headers": selected_headers(self.headers.raw_items()),
                "body": decoded_body(self.headers.raw_items(), body).decode("latin-1"),
            })
            sequence = len(observed_requests)
            response = f"origin-{sequence}".encode()
            encoded_response = gzip.compress(response, mtime=0) if sequence == 3 else response
            self.send_response(201, "Created")
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Origin", str(sequence))
            if sequence == 3:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(encoded_response)))
            self.end_headers()
            self.wfile.write(encoded_response)

        def log_message(self, format, *args):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    server = threading.Thread(target=origin.serve_forever, daemon=True)
    server.start()

    proxy_port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="addon-live-http-") as directory:
        addon = Path(directory) / "addon.py"
        addon.write_text(ADDON_SOURCE)
        process = subprocess.Popen([
            arguments.reference,
            "--mode", f"reverse:http://127.0.0.1:{origin.server_port}",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(proxy_port),
            "--set", "termlog_verbosity=error",
            "-s", str(addon),
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        responses = []
        try:
            wait_for_proxy(proxy_port, process)
            for sequence, (method, path, body) in enumerate((
                ("POST", "/original-one", b"old-one"),
                ("GET", "/original-two", None),
                ("POST", "/original-three", gzip.compress(b"old-three", mtime=0)),
            ), 1):
                headers = {
                    "Host": "input.example",
                    "X-Client": str(sequence),
                    "Content-Type": "application/octet-stream",
                }
                if sequence == 3:
                    headers["Content-Encoding"] = "gzip"
                connection = HTTPConnection("127.0.0.1", proxy_port, timeout=5)
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                response_headers = response.getheaders()
                responses.append({
                    "status": response.status,
                    "reason": response.reason,
                    "headers": selected_headers(response_headers),
                    "body": decoded_body(response_headers, response.read()).decode("latin-1"),
                })
                connection.close()
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
            raise AssertionError("Reference live HTTP behavior changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
