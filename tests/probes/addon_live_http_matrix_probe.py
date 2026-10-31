"""Record a deterministic HTTP/1 mutation matrix from mitmproxy 12.3.1."""

import argparse
import gzip
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))

from addon_live_http_contract import (
    MATRIX_SOURCE, canonical_headers, decoded_body, matrix_cases,
)
from probes.addon_live_http_probe import reserve_port, wait_for_proxy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", required=True, help="Path to reference mitmdump")
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()

    requests = []

    class Origin(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def handle_request(self):
            length = int(self.headers.get("content-length", "0"))
            wire_body = self.rfile.read(length)
            body = decoded_body(self.headers.raw_items(), wire_body)
            case = int(self.headers["x-case"])
            requests.append({
                "case": case,
                "method": self.command,
                "path": self.path,
                "headers": canonical_headers(self.headers.raw_items()),
                "body": body.decode("latin-1"),
            })
            response = f"origin-{case}-".encode() + b"y" * ((case * 13) % 193)
            encoded = gzip.compress(response, mtime=0) if case % 5 == 4 else response
            self.send_response(201, "Created")
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Origin", str(case))
            self.send_header("X-Remove", "response")
            self.send_header("X-Multi", "old")
            if case % 5 == 4:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        do_GET = handle_request
        do_POST = handle_request
        do_DELETE = handle_request
        do_OPTIONS = handle_request
        do_PATCH = handle_request
        do_PUT = handle_request

        def log_message(self, format, *args):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    server = threading.Thread(target=origin.serve_forever, daemon=True)
    server.start()

    proxy_port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="addon-live-http-matrix-") as directory:
        addon = Path(directory) / "addon.py"
        addon.write_text(MATRIX_SOURCE)
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
            for scenario in matrix_cases():
                body = scenario["body"]
                headers = {
                    "Host": "input.example",
                    "X-Case": str(scenario["case"]),
                    "X-Remove": "request",
                    "X-Multi": "old",
                    "Content-Type": "application/octet-stream",
                }
                if scenario["gzip_request"]:
                    body = gzip.compress(body, mtime=0)
                    headers["Content-Encoding"] = "gzip"
                connection = HTTPConnection("127.0.0.1", proxy_port, timeout=5)
                connection.request(
                    scenario["method"], scenario["path"], body=body, headers=headers
                )
                response = connection.getresponse()
                response_headers = response.getheaders()
                responses.append({
                    "case": scenario["case"],
                    "status": response.status,
                    "reason": response.reason,
                    "headers": canonical_headers(response_headers),
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
        "requests": sorted(requests, key=lambda item: item["case"]),
        "responses": responses,
    }
    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference live HTTP matrix changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
