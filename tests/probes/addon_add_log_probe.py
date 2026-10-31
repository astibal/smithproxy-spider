#!/usr/bin/env python3
"""Observe mitmproxy 12 legacy add_log delivery through public APIs only."""

import json
import logging
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import errno
import socket
import subprocess
import sys
import tempfile
import threading
import time

from mitmproxy import ctx, log


PREFIX = "spider-add-log-probe:"


def _append(value):
    output = os.environ.get("SPIDER_ADD_LOG_PROBE_OUTPUT")
    if output is None:
        return
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def add_log(entry):
    if not entry.msg.startswith(PREFIX):
        return
    _append({
        "hook": "add_log",
        "message": entry.msg,
        "level": entry.level,
        "type": type(entry).__name__,
        "repr": repr(entry),
    })


def request(_flow):
    ctx.log.debug(PREFIX + "legacy-debug")
    ctx.log.info(PREFIX + "legacy-info")
    ctx.log.warn(PREFIX + "legacy-warn")
    ctx.log.error(PREFIX + "legacy-error")
    ctx.log.alert(PREFIX + "legacy-alert")
    logging.info(PREFIX + "standard-info")
    logging.warning(PREFIX + "standard-warning")
    logging.log(log.ALERT, PREFIX + "standard-alert")
    ctx.master.addons.trigger(log.AddLogHook(
        log.LogEntry(PREFIX + "manual-trigger", "warn")
    ))


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
        environment["SPIDER_ADD_LOG_PROBE_OUTPUT"] = str(output)
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
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if output.exists() and len(output.read_text().splitlines()) >= 1:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.05)
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
                "\nstderr:\n" + stderr
            )
        events = [json.loads(line) for line in output.read_text().splitlines()]
        print(json.dumps({
            "reference": "mitmproxy 12.3.1",
            "events": events,
        }, indent=2, sort_keys=True))


if (__name__ == "__main__" and
        "SPIDER_ADD_LOG_PROBE_OUTPUT" not in os.environ):
    main()
