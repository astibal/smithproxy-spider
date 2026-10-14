#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

from fake_smithproxy import Handler

def get_json(url, token=None):
    headers = {"X-Spider-Token": token} if token else {}
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=1) as response:
        return json.load(response)

def post_json(url, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Spider-Token"] = token
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)

def post_bytes(url, body):
    request = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)

def delete_json(url, token=None):
    headers = {"X-Spider-Token": token} if token else {}
    request = urllib.request.Request(url, headers=headers, method="DELETE")
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)

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
    env["SPIDER_TOKEN"] = "frontend-key"
    process = subprocess.Popen([
        binary, "--port", str(spider_port),
        "--smithproxy-url", f"http://127.0.0.1:{api_port}",
        "--callback-url", f"http://127.0.0.1:{spider_port}/webhook",
    ], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                get_json(f"http://127.0.0.1:{spider_port}/api/health")
                break
            except OSError:
                time.sleep(0.05)
        status_code, configured = post_json(
            f"http://127.0.0.1:{spider_port}/api/config/smithproxy",
            {"url": f"http://127.0.0.1:{api_port}", "api_key": "integration-key",
             "verify_tls": False}, "frontend-key")
        assert status_code == 202
        assert configured["status"] == "connecting"

        while time.monotonic() < deadline:
            try:
                events_url = f"http://127.0.0.1:{spider_port}/api/events"
                events = get_json(events_url, "frontend-key")["events"]
                actions = [entry["event"].get("action") for entry in events]
                states = [entry["event"].get("state") for entry in events]
                if "ping" in actions and "connected" in states:
                    status = get_json(f"http://127.0.0.1:{spider_port}/api/status", "frontend-key")
                    ready = get_json(f"http://127.0.0.1:{spider_port}/api/ready", "frontend-key")
                    assert status["callbacks_received"] >= 1
                    assert status["active_sessions"] == 0
                    assert status["smithproxy"]["webhook_api"] == "v2-owned"
                    assert status["smithproxy"]["lease_expires_at"] > 0
                    assert status["last_callback"]["action"] == "ping"
                    assert status["last_callback"]["received_at_ms"] > 0
                    assert ready["ready"] is True
                    diagnostics = get_json(
                        f"http://127.0.0.1:{spider_port}/api/diagnostics", "frontend-key")
                    assert diagnostics["service"] == "smithproxy-spider"
                    assert diagnostics["store"]["callbacks"]["received"] >= 1
                    assert diagnostics["websocket"]["stream"]["events_published"] >= 1
                    assert diagnostics["callback_transport"]["requests"] >= 1
                    history = get_json(
                        f"http://127.0.0.1:{spider_port}/api/session-history", "frontend-key")
                    assert history["sessions"] == []
                    delete_status, deleted = delete_json(
                        f"http://127.0.0.1:{spider_port}/api/session-history", "frontend-key")
                    assert delete_status == 200
                    assert deleted["removed"] == 0
                    try:
                        get_json(events_url)
                        raise AssertionError("browser API accepted a missing token")
                    except urllib.error.HTTPError as error:
                        assert error.code == 401
                    callback = Handler.callback
                    assert callback
                    info_status, info = post_json(callback, {"action": "info"})
                    assert info_status == 200
                    assert info["action"] == "info-response"
                    assert "sxbn-001" in info["protocols"]["connection-content"]
                    payload = b"\x00binary\xffpayload"
                    metadata = json.dumps({
                        "action": "connection-content", "id": "binary-integration",
                        "details": {"info": {
                            "session": "tcp_10.0.0.1:1+tcp_10.0.0.2:2", "side": "L",
                            "payload_length": len(payload), "payload_layer": "tcp",
                        }},
                    }, separators=(",", ":")).encode()
                    envelope = (b"SXBN001:" + f"{len(metadata):08X}:{len(payload):08X}".encode()
                                + metadata + payload)
                    binary_status, binary_reply = post_bytes(callback, envelope)
                    assert binary_status == 200
                    assert binary_reply["action"] == "unchanged"
                    binary_events = get_json(events_url, "frontend-key")["events"]
                    binary_event = next(entry["event"] for entry in binary_events
                                        if entry["event"].get("id") == "binary-integration")
                    assert binary_event["details"]["info"]["payload_encoding"] == "sxbn-001"
                    assert binary_event["details"]["info"]["payload_length"] == len(payload)
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
