#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

from fake_smithproxy import Handler

def get_json(url):
    with urllib.request.urlopen(url, timeout=1) as response:
        return json.load(response)

def main():
    binary = os.path.abspath(sys.argv[1])
    api = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    api_port = api.server_address[1]
    threading.Thread(target=api.serve_forever, daemon=True).start()

    # Let the kernel select a free callback port, then release it immediately.
    probe = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    spider_port = probe.server_address[1]
    probe.server_close()
    env = os.environ.copy()
    env["SPIDER_SMITHPROXY_KEY"] = "integration-key"
    process = subprocess.Popen([
        binary, "--port", str(spider_port),
        "--smithproxy-url", f"http://127.0.0.1:{api_port}",
        "--callback-url", f"http://127.0.0.1:{spider_port}/webhook",
    ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                events = get_json(f"http://127.0.0.1:{spider_port}/api/events")["events"]
                actions = [entry["event"].get("action") for entry in events]
                states = [entry["event"].get("state") for entry in events]
                if "ping" in actions and "connected" in states:
                    status = get_json(f"http://127.0.0.1:{spider_port}/api/status")
                    ready = get_json(f"http://127.0.0.1:{spider_port}/api/ready")
                    assert status["callbacks_received"] >= 1
                    assert status["active_sessions"] == 0
                    assert ready["ready"] is True
                    return 0
            except OSError:
                pass
            time.sleep(0.1)
        output = process.stdout.read() if process.poll() is not None else ""
        raise RuntimeError(f"chain did not reach callback ping; spider output: {output}")
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
        api.shutdown()
        api.server_close()

if __name__ == "__main__":
    raise SystemExit(main())
