#!/usr/bin/env python3
import json
import os
import base64
import gzip
import socket
import struct
import subprocess
import sys
import threading
import time
import tempfile
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer

from fake_smithproxy import Handler

def websocket_connect(port):
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        "GET /api/events/ws HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: spider, frontend-key\r\n\r\n"
    )
    client.sendall(request.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        response += client.recv(4096)
    assert response.startswith(b"HTTP/1.1 101")
    return client

def websocket_send_json(client, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    assert len(payload) < 126
    mask = os.urandom(4)
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    client.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)

def receive_exact(client, length):
    result = b""
    while len(result) < length:
        block = client.recv(length - len(result))
        if not block:
            raise RuntimeError("WebSocket closed while receiving a frame")
        result += block
    return result

def websocket_receive(client):
    first, second = receive_exact(client, 2)
    length = second & 0x7f
    if length == 126:
        length = struct.unpack("!H", receive_exact(client, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", receive_exact(client, 8))[0]
    assert not second & 0x80
    return first & 0x0f, receive_exact(client, length)

def decode_sxbn_chain(wire):
    envelopes = []
    offset = 0
    while offset < len(wire):
        assert wire[offset:offset + 8] == b"SXBN001:"
        json_length = int(wire[offset + 8:offset + 16], 16)
        assert wire[offset + 16:offset + 17] == b":"
        payload_length = int(wire[offset + 17:offset + 25], 16)
        json_start = offset + 25
        payload_start = json_start + json_length
        end = payload_start + payload_length
        assert end <= len(wire)
        envelopes.append((json.loads(wire[json_start:payload_start]),
                          wire[payload_start:end]))
        offset = end
    return envelopes

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
    collection_directory = tempfile.TemporaryDirectory(prefix="spider-chain-collections-")
    env["SPIDER_COLLECTION_DIR"] = collection_directory.name
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

                    live_socket = websocket_connect(spider_port)
                    websocket_send_json(live_socket, {"type": "subscribe", "tail": True})
                    opcode, subscribed = websocket_receive(live_socket)
                    assert opcode == 1
                    assert json.loads(subscribed)["type"] == "subscribed"
                    websocket_send_json(live_socket, {"type": "traffic-rules", "rules": [{
                        "address": "10.0.0.1", "mode": "focus",
                    }]})

                    text_status, _ = post_json(callback, {
                        "action": "connection-start", "id": "text-live",
                        "details": {"info": {"session":
                            "tcp_10.0.0.1:10+tcp_10.0.0.2:20"}},
                    })
                    assert text_status == 200
                    while True:
                        opcode, frame = websocket_receive(live_socket)
                        if opcode != 1:
                            continue
                        text_event = json.loads(frame)
                        if text_event.get("type") == "event" and \
                                text_event.get("event", {}).get("id") == "text-live":
                            assert text_event["event"]["action"] == "connection-start"
                            break

                    payload = (b"GET /watch?v=1 HTTP/1.1\r\nHost: example.test\r\n"
                               b"Accept: */*\r\n\r\n\x00binary\xffpayload")
                    header_end = payload.index(b"\r\n\r\n") + 4
                    first_line_end = payload.index(b"\r\n") + 2
                    metadata = json.dumps({
                        "action": "connection-content", "id": "binary-integration",
                        "details": {"info": {
                            "session": "tcp_10.0.0.1:1+tcp_10.0.0.2:2", "side": "L",
                            "payload_length": len(payload), "payload_layer": "tcp",
                            "content_annotations": [
                                [0, first_line_end, "http1.start_line"],
                                [first_line_end, header_end, "http1.headers"],
                                [header_end, len(payload), "http1.body"],
                            ],
                        }},
                    }, separators=(",", ":")).encode()
                    envelope = (b"SXBN001:" + f"{len(metadata):08X}:{len(payload):08X}".encode()
                                + metadata + payload)
                    binary_status, binary_reply = post_bytes(callback, envelope)
                    assert binary_status == 200
                    assert binary_reply["action"] == "unchanged"
                    while True:
                        opcode, frame = websocket_receive(live_socket)
                        if opcode != 2:
                            continue
                        live_chain = decode_sxbn_chain(frame)
                        if live_chain[0][0]["event"].get("id") == "binary-integration":
                            assert len(live_chain) == 2
                            assert live_chain[0][1] == payload
                            assert live_chain[1][0]["type"] == "enrichment"
                            assert live_chain[1][0]["source"]["envelope"] == \
                                live_chain[0][0]["key"]
                            assert live_chain[1][0]["source"]["annotations"] == [0, 1]
                            assert live_chain[1][0]["operation"] == "http1.parse-head"
                            assert live_chain[1][0]["message"]["method"] == "GET"
                            assert live_chain[1][0]["message"]["headers"][0] == {
                                "name": "Host", "value": "example.test",
                            }
                            assert live_chain[1][1] == b""
                            break

                    # A minimal HPACK block with indexed :method GET and
                    # :path / verifies H2 enrichment through the complete
                    # callback -> cache -> WebSocket SXBN chain.
                    h2_payload = bytes.fromhex("0000020104000000018284")
                    h2_metadata = json.dumps({
                        "action": "connection-content", "id": "h2-integration",
                        "details": {"info": {
                            "session": "tcp_10.0.0.1:3+tcp_10.0.0.2:443", "side": "L",
                            "payload_length": len(h2_payload), "payload_layer": "tcp",
                            "content_annotations": [
                                [0, 9, "h2.frame.header",
                                 {"frame_type": "HEADERS", "stream_id": 1}],
                                [9, len(h2_payload), "h2.headers",
                                 {"frame_type": "HEADERS", "stream_id": 1}],
                            ],
                        }},
                    }, separators=(",", ":")).encode()
                    h2_envelope = (b"SXBN001:" +
                                   f"{len(h2_metadata):08X}:{len(h2_payload):08X}".encode() +
                                   h2_metadata + h2_payload)
                    h2_status, h2_reply = post_bytes(callback, h2_envelope)
                    assert h2_status == 200
                    assert h2_reply["action"] == "unchanged"
                    while True:
                        opcode, frame = websocket_receive(live_socket)
                        if opcode != 2:
                            continue
                        h2_chain = decode_sxbn_chain(frame)
                        if h2_chain[0][0]["event"].get("id") == "h2-integration":
                            assert len(h2_chain) == 2
                            assert h2_chain[1][0]["operation"] == "hpack.decode"
                            assert h2_chain[1][0]["source"]["stream_id"] == 1
                            assert h2_chain[1][0]["headers"] == [
                                {"name": ":method", "value": "GET"},
                                {"name": ":path", "value": "/"},
                            ]
                            break

                    inflated_plain = b"compressed Spider integration payload\n"
                    compressed_body = gzip.compress(inflated_plain)
                    compressed_head = (
                        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n" +
                        f"Content-Length: {len(compressed_body)}\r\n\r\n".encode())
                    compressed_payload = compressed_head + compressed_body
                    compressed_line_end = compressed_payload.index(b"\r\n") + 2
                    compressed_body_start = len(compressed_head)
                    compressed_metadata = json.dumps({
                        "action": "connection-content", "id": "gzip-integration",
                        "details": {"info": {
                            "session": "tcp_10.0.0.1:4+tcp_10.0.0.2:443", "side": "R",
                            "payload_length": len(compressed_payload),
                            "payload_layer": "tcp",
                            "L7_payload_start": [compressed_body_start],
                            "L7_payload_end": [len(compressed_payload)],
                            "L7_encoding": ["gzip"],
                            "content_annotations": [
                                [0, compressed_line_end, "http1.start_line"],
                                [compressed_line_end, compressed_body_start, "http1.headers"],
                                [compressed_body_start, len(compressed_payload), "http1.body"],
                            ],
                        }},
                    }, separators=(",", ":")).encode()
                    compressed_envelope = (b"SXBN001:" +
                        f"{len(compressed_metadata):08X}:{len(compressed_payload):08X}".encode() +
                        compressed_metadata + compressed_payload)
                    compressed_status, compressed_reply = post_bytes(callback,
                                                                      compressed_envelope)
                    assert compressed_status == 200
                    assert compressed_reply["action"] == "unchanged"
                    while True:
                        opcode, frame = websocket_receive(live_socket)
                        if opcode != 2:
                            continue
                        compressed_chain = decode_sxbn_chain(frame)
                        if compressed_chain[0][0]["event"].get("id") == "gzip-integration":
                            assert len(compressed_chain) == 3
                            operations = {item[0]["operation"]: item
                                          for item in compressed_chain[1:]}
                            assert operations["gzip.inflate"][1] == inflated_plain
                            assert operations["gzip.inflate"][0]["finished"] is True
                            assert operations["http1.parse-head"][0]["message"]["status"] == 200
                            break
                    enriched_diagnostics = get_json(
                        f"http://127.0.0.1:{spider_port}/api/diagnostics", "frontend-key")
                    assert enriched_diagnostics["enrichment"]["content_seen"] >= 1
                    assert enriched_diagnostics["enrichment"]["selected"] >= 1
                    assert enriched_diagnostics["enrichment"]["outputs"] >= 1
                    assert enriched_diagnostics["enrichment"]["by_operation"][
                        "http1.parse-head"] >= 1
                    assert enriched_diagnostics["enrichment"]["by_operation"][
                        "hpack.decode"] >= 1
                    assert enriched_diagnostics["enrichment"]["by_operation"][
                        "gzip.inflate"] >= 1
                    live_socket.close()

                    empty_metadata = json.dumps({
                        "action": "connection-content", "id": "binary-empty",
                        "details": {"info": {
                            "session": "tcp_10.0.0.1:1+tcp_10.0.0.2:2", "side": "R",
                            "payload_length": 0, "payload_layer": "tcp",
                        }},
                    }, separators=(",", ":")).encode()
                    empty_envelope = (b"SXBN001:" +
                                      f"{len(empty_metadata):08X}:00000000".encode() +
                                      empty_metadata)
                    empty_status, empty_reply = post_bytes(callback, empty_envelope)
                    assert empty_status == 200
                    assert empty_reply["action"] == "unchanged"
                    try:
                        post_bytes(callback, envelope[:-1])
                        raise AssertionError("truncated SXBN callback was accepted")
                    except urllib.error.HTTPError as error:
                        assert error.code == 400

                    binary_events = get_json(events_url, "frontend-key")["events"]
                    binary_event = next(entry["event"] for entry in binary_events
                                        if entry["event"].get("id") == "binary-integration")
                    assert binary_event["details"]["info"]["payload_encoding"] == "sxbn-001"
                    assert binary_event["details"]["info"]["payload_length"] == len(payload)
                    binary_revision = next(entry["revision"] for entry in binary_events
                                           if entry["event"].get("id") == "binary-integration")
                    websocket = websocket_connect(spider_port)
                    try:
                        websocket_send_json(websocket, {"type": "subscribe",
                                                        "after": binary_revision - 1})
                        opcode, frame = websocket_receive(websocket)
                        assert opcode == 2
                        chain = decode_sxbn_chain(frame)
                        assert len(chain) == 2
                        assert chain[0][0]["type"] == "event"
                        assert chain[0][0]["key"] == f"event:{binary_revision}"
                        assert chain[0][0]["revision"] == binary_revision
                        assert chain[0][0]["event"]["id"] == "binary-integration"
                        assert "content" not in chain[0][0]["event"]["details"]["info"]
                        assert chain[0][1] == payload
                        assert chain[1][0]["key"] == \
                            f"event:{binary_revision}:enrichment:0"
                        assert chain[1][0]["operation"] == "http1.parse-head"
                    finally:
                        websocket.close()
                    inspection_url = f"http://127.0.0.1:{spider_port}/api/inspection"
                    assert not get_json(inspection_url, 'frontend-key')['heavy_traffic']['enabled']
                    _, heavy = post_json(inspection_url + '/heavy-traffic', {'enabled': True, 'grace_seconds': 10}, 'frontend-key')
                    assert heavy['enabled'] and heavy['grace_seconds'] == 10
                    try:
                        post_json(inspection_url + '/heavy-traffic', {'grace_seconds': 4}, 'frontend-key')
                        raise AssertionError('unsafe grace accepted')
                    except urllib.error.HTTPError as error:
                        assert error.code == 400
                    post_json(inspection_url + '/heavy-traffic', {'enabled': False}, 'frontend-key')
                    schema = get_json(inspection_url + '/schema', 'frontend-key')
                    assert schema['version'] == '0.6'
                    assert 'Http2' in schema['types']
                    assert [f['name'] for f in schema['types']['InspectionViews']['fields']] == ['message', 'metadata', 'http1', 'http2', 'state', 'storage', 'instance']
                    assert schema['types']['Message']['fields'][0]['type'] == 'bytes'
                    language_request = {'script': 'h2 = api.http2\nh2.',
                                        'language_action': 'complete', 'line': 2, 'column': 3}
                    try:
                        post_json(inspection_url + '/language', language_request)
                        raise AssertionError('unauthenticated language service allowed')
                    except urllib.error.HTTPError as error:
                        assert error.code == 401
                    before_analysis = get_json(inspection_url, 'frontend-key')['runs']
                    _, analysis = post_json(inspection_url + '/language', language_request, 'frontend-key')
                    if analysis['ok']:
                        assert 'frames' in [item['label'] for item in analysis['items']]
                    else:
                        assert 'requires Jedi' in analysis['error']
                    assert get_json(inspection_url, 'frontend-key')['runs'] == before_analysis
                    try:
                        post_json(inspection_url + '/run', {'script': 'return None'})
                        raise AssertionError('unauthenticated script execution allowed')
                    except urllib.error.HTTPError as error:
                        assert error.code == 401
                    sample = {'action': 'connection-content', 'id': 'headless-api',
                              'details': {'info': {'content': 'YWJj', 'side': 'L',
                              'session': 'tcp_10.0.0.1:10+tcp_10.0.0.2:20'}}}
                    _, result = post_json(inspection_url + '/run',
                        {'script': 'api.print(len(api.bytes))\nreturn api.bytes.upper()',
                         'event': sample}, 'frontend-key')
                    assert result['replacement'] == 'QUJD' and result['logs'] == ['3']
                    assert get_json(inspection_url, 'frontend-key')['sandbox']['required'] is True
                    # Exercise containment through the real authenticated HTTP API.
                    # A request must not be able to opt out of the kernel policy.
                    _, blocked = post_json(inspection_url + '/run', {
                        'script': 'import socket\nsocket.socket()', 'event': sample,
                        'sandbox': False, 'storage_directory': '/'}, 'frontend-key')
                    assert blocked['ok'] is False and blocked['replacement'] is None
                    assert 'PermissionError' in blocked['error']
                    # A denied invocation must not damage the next worker.
                    _, recovered = post_json(inspection_url + '/run', {
                        'script': 'return api.bytes', 'event': sample}, 'frontend-key')
                    assert recovered['ok'] is True and recovered['replacement'] == 'YWJj'
                    before_live = get_json(inspection_url, 'frontend-key')['runs']
                    assert before_live == before_analysis + 3
                    post_json(inspection_url + '/rules', {'rules': [
                        {'address': '10.0.0.1', 'mode': 'inspect'}]}, 'frontend-key')
                    post_json(inspection_url, {'script': 'return api.bytes.upper()',
                        'enabled': True, 'scope': 'rules'}, 'frontend-key')
                    _, result = post_json(callback, sample)
                    assert result['action'] == 'replace' and result['content'] == 'QUJD'
                    state = get_json(inspection_url, 'frontend-key')
                    assert state['enabled'] and state['runs'] == before_live + 1
                    post_json(inspection_url, {'script': 'return api.bytes.upper()',
                        'enabled': False, 'scope': 'rules'}, 'frontend-key')
                    assert post_json(callback, sample)[1]['action'] == 'unchanged'
                    write_wire = b'POST /old HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc'
                    write_event = {'action': 'connection-content', 'id': 'write-api', 'details': {'info': {
                        'content': base64.b64encode(write_wire).decode(), 'side': 'L'}}}
                    write_script = 'draft = api.message.snapshot()\ndraft.http1.body = b"longer"\nreturn draft.commit()'
                    _, written = post_json(inspection_url + '/run', {'script': write_script, 'event': write_event}, 'frontend-key')
                    assert written['ok'] and base64.b64decode(written['replacement']) == write_wire.replace(b'Length: 3', b'Length: 6')[:-3] + b'longer'
                    catch_script = 'draft = api.message.snapshot()\ndraft.http1.target = "bad target"\ntry:\n    return draft.commit()\nexcept CommitException:\n    return None'
                    _, caught = post_json(inspection_url + '/run', {'script': catch_script, 'event': write_event}, 'frontend-key')
                    assert caught['ok'] and caught['replacement'] is None
                    # Real webhook -> input HPACK enrichment -> sandboxed worker
                    # -> replacement, independently decoded by libnghttp2.
                    from inspection_h2_test import frame, unpack, Oracle
                    h2_wire = frame(bytes.fromhex('828684418cf1e3c2e5f23a6ba0ab90f4ff'), 1, 5)
                    h2_event = json.loads(json.dumps(sample))
                    h2_event['id'] = 'h2-live-rewrite'
                    h2_event['details']['info'].update({
                        'content': base64.b64encode(h2_wire).decode(),
                        'content_annotations': [[0, 9, 'h2.frame.header'], [9, len(h2_wire), 'h2.headers']]})
                    h2_script = ('for part in api.message.parts:\n'
                        '    if part.headers is not None:\n'
                        '        part.headers.set_header(b":authority", b"rewrite.example")\n'
                        'return api.message.commit()')
                    post_json(inspection_url, {'script': h2_script, 'enabled': True, 'scope': 'rules'}, 'frontend-key')
                    _, rewritten = post_json(callback, h2_event)
                    assert rewritten['action'] == 'replace', rewritten
                    h2_fields = Oracle().decode(unpack(base64.b64decode(rewritten['content']))[0][3])
                    assert (b':authority', b'rewrite.example') in h2_fields
                    post_json(inspection_url, {'script': h2_script, 'enabled': False, 'scope': 'rules'}, 'frontend-key')
                    assert post_json(callback, h2_event)[1]['action'] == 'unchanged'

                    _, completion = post_json(inspection_url + '/language', {
                        'script': 'part = api.message.parts[0]\npart.',
                        'language_action': 'complete', 'line': 2, 'column': 5}, 'frontend-key')
                    if completion['ok']:
                        assert {'headers', 'commit', 'get_bytes'} <= {item['label'] for item in completion['items']}
                    replay_url = f"http://127.0.0.1:{spider_port}/api/enrichment/replay"
                    raw_head = b"GET /replay HTTP/1.1\r\nHost: example.test\r\n\r\n"
                    replay_event = {"action": "connection-content", "id": "offline-replay",
                        "details": {"info": {"side": "L", "content_annotations": [
                            [0, 22, "http1.start_line"], [22, len(raw_head), "http1.headers"]]}}}
                    meta = json.dumps({"event": replay_event, "context_complete": True}).encode()
                    wire = f"SXBN001:{len(meta):08x}:{len(raw_head):08x}".encode() + meta + raw_head
                    for auth in (False, True):
                        request = urllib.request.Request(replay_url, data=wire, headers={
                            "Content-Type": "application/octet-stream",
                            **({"X-Spider-Token": "frontend-key"} if auth else {})})
                        try:
                            with urllib.request.urlopen(request) as response:
                                assert auth
                                replay = decode_sxbn_chain(response.read())
                                assert replay[-1][0]["type"] == "replay-summary"
                                assert replay[0][0]["operation"] == "http1.parse-head"
                        except urllib.error.HTTPError as error:
                            assert not auth and error.code == 401
                    saved_url = f"http://127.0.0.1:{spider_port}/api/inspection/saved-flows"
                    snapshot = {"name": "Persistent investigation", "scope": {"type": "connection"},
                        "records": [{"revision": 1, "event": sample, "enrichments": []}]}
                    try:
                        post_json(saved_url, snapshot)
                        raise AssertionError("saving sessions accepted a missing token")
                    except urllib.error.HTTPError as error:
                        assert error.code == 401
                    code, saved = post_json(saved_url, snapshot, "frontend-key")
                    assert code == 200 and saved["name"] == snapshot["name"]
                    listing = get_json(saved_url, "frontend-key")
                    assert listing["items"][0]["id"] == saved["id"]
                    loaded = get_json(f"http://127.0.0.1:{spider_port}/api/inspection/saved-flow?id={saved['id']}", "frontend-key")
                    assert loaded["records"] == snapshot["records"]
                    assert loaded["name"] == snapshot["name"]
                    catalog_url = inspection_url + '/library'
                    catalog = get_json(catalog_url, 'frontend-key')
                    key = 'flow:' + saved['id']
                    assert any(item['key'] == key for item in catalog['items'])
                    _, folder = post_json(catalog_url, {'revision': catalog['revision'], 'operation': 'folder', 'name': 'Integration'}, 'frontend-key')
                    _, edited = post_json(catalog_url, {'revision': folder['revision'], 'operation': 'item', 'key': key,
                        'name': 'Renamed capture', 'notes': 'catalog needle', 'folder': folder['folders'][0]['id']}, 'frontend-key')
                    found = get_json(catalog_url + '?q=needle', 'frontend-key')
                    assert found['total'] == 1 and found['items'][0]['name'] == 'Renamed capture'
                    assert get_json(inspection_url + '/saved-flow?id=' + saved['id'], 'frontend-key')['name'] == 'Renamed capture'
                    try:
                        post_json(catalog_url, {'revision': catalog['revision'], 'operation': 'folder', 'name': 'Stale'}, 'frontend-key')
                        raise AssertionError('stale catalog edit accepted')
                    except urllib.error.HTTPError as error:
                        assert error.code == 400
                    # HTTP transport proof: no held byte is included in need-more;
                    # the final response contains one reassembled, resized message.
                    hold_source = ('for part in api.message.parts:\n'
                        '    if part.type == PartType.Http1.Body:\n'
                        '        if not part.content.complete:\n'
                        '            api.message.parts.hold_from(api.message.parts[0])\n'
                        '            return api.message.commit()\n'
                        '        part.set_bytes(b"rewritten body")\n'
                        'return api.message.commit()')
                    state = get_json(inspection_url, 'frontend-key')
                    _, deployed = post_json(inspection_url, {'revision': state['revision'],
                        'operation': 'deploy', 'name': 'hold HTTP proof', 'script': hold_source,
                        'scope': 'all', 'instancing': 'flow'}, 'frontend-key')
                    post_json(inspection_url, {'revision': deployed['revision'], 'operation': 'enable',
                        'id': deployed['chain'][-1]['id'], 'enabled': True}, 'frontend-key')
                    hold_head = b'POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 6\r\n\r\n'
                    for index, fragment in enumerate((hold_head + b'a', b'bc', b'def')):
                        hold_event = {'action': 'connection-content', 'id': 'hold-http',
                            'details': {'info': {'side': 'L', 'content': base64.b64encode(fragment).decode()}}}
                        if index == 0:
                            hold_event['details']['info']['content_annotations'] = [
                                [0, 17, 'http1.start_line'], [17, len(hold_head), 'http1.headers']]
                        _, held_reply = post_json(callback, hold_event)
                        if index < 2:
                            assert held_reply == {'action': 'need-more'}, held_reply
                        else:
                            assert held_reply['action'] == 'replace', held_reply
                            assert base64.b64decode(held_reply['content']) == hold_head.replace(
                                b'Length: 6', b'Length: 14') + b'rewritten body'
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
        collection_directory.cleanup()

if __name__ == "__main__":
    raise SystemExit(main())
