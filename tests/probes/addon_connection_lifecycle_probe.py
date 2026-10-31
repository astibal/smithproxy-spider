#!/usr/bin/env python3
"""Observe public mitmproxy connection-hook ordering through a real proxy.

The same file is loaded as an addon by mitmdump and executed as the independent
probe controller.  It records public values only; no implementation source is
read or imported by the Spider compatibility layer.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


_connection_labels = {}


def _connection(value):
    identity = value.id
    if identity not in _connection_labels:
        prefix = "client" if type(value).__name__ == "Client" else "server"
        count = sum(label.startswith(prefix) for label in _connection_labels.values())
        _connection_labels[identity] = prefix + "-" + str(count + 1)
    return {
        "type": type(value).__name__,
        "identity": _connection_labels[identity],
        "peername_present": value.peername is not None,
        "sockname_present": value.sockname is not None,
        "address_present": getattr(value, "address", None) is not None,
        "state": int(value.state.value),
        "transport_protocol": value.transport_protocol,
        "timestamp_start_present": value.timestamp_start is not None,
        "timestamp_end_present": value.timestamp_end is not None,
    }


def _record(hook, *values):
    output = os.environ.get("SPIDER_CONNECTION_PROBE_OUTPUT")
    if output is None:
        return
    entry = {
        "hook": hook,
        "connections": [_connection(value) for value in values],
    }
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")


def client_connected(client):
    _record("client_connected", client)


def client_disconnected(client):
    _record("client_disconnected", client)


def server_connect(data):
    _record("server_connect", data.client, data.server)


def server_connected(data):
    _record("server_connected", data.client, data.server)


def server_disconnected(data):
    _record("server_disconnected", data.client, data.server)


def server_connect_error(data):
    _record("server_connect_error", data.client, data.server)


class _Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"probe-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_arguments):
        pass


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _wait_for_port(port, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Reference proxy exited during startup")
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                return
            raise
        finally:
            probe.close()
        time.sleep(0.05)
    raise TimeoutError("Reference proxy did not start")


def main():
    mitmdump = os.environ.get("MITMDUMP", "mitmdump")
    origin_port = _port()
    proxy_port = _port()
    origin = ThreadingHTTPServer(("127.0.0.1", origin_port), _Origin)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()

    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "events.jsonl"
        environment = dict(os.environ)
        environment["SPIDER_CONNECTION_PROBE_OUTPUT"] = str(output)
        process = subprocess.Popen(
            [
                mitmdump,
                "--set",
                "termlog_verbosity=error",
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(proxy_port),
                "-s",
                str(Path(__file__).resolve()),
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _wait_for_port(proxy_port, process)
            client = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
            client.request("GET", f"http://127.0.0.1:{origin_port}/probe")
            response = client.getresponse()
            body = response.read()
            client.close()
            if response.status != 200 or body != b"probe-ok":
                raise RuntimeError("Reference proxy did not deliver the probe response")
            time.sleep(0.2)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            origin.shutdown()
            origin.server_close()
            origin_thread.join(timeout=5)

        if not output.exists():
            stdout, stderr = process.communicate()
            raise RuntimeError(
                "Reference addon produced no events\nstdout:\n" + stdout +
                "\nstderr:\n" + stderr)
        events = [json.loads(line) for line in output.read_text().splitlines()]
        print(json.dumps({
            "reference": "mitmproxy 12.3.1",
            "events": events,
        }, indent=2, sort_keys=True))


if (__name__ == "__main__" and
        "SPIDER_CONNECTION_PROBE_OUTPUT" not in os.environ):
    main()
