"""Reference-only addon for WebSocket message decision behavior."""

import base64
import json


def encoded(content):
    return base64.b64encode(content).decode("ascii")


def report(name, flow, message=None, before=None):
    item = {
        "hook": name,
        "message_count": len(flow.websocket.messages) if flow.websocket else 0,
        "from_client": None if message is None else message.from_client,
        "type": None if message is None else int(message.type),
        "before": None if before is None else encoded(before),
        "after": None if message is None else encoded(message.content),
        "dropped": None if message is None else message.dropped,
        "live": flow.live,
        "error": None if flow.error is None else str(flow.error),
    }
    print("PROBE " + json.dumps(item, sort_keys=True), flush=True)


def websocket_start(flow):
    report("websocket_start", flow)


def websocket_message(flow):
    message = flow.websocket.messages[-1]
    before = message.content

    if before == b"fragment":
        message.content = b"FRAGMENT"
    elif before == b"\x00\xff":
        message.content = b"\x01\xfe"
    elif before == b"drop-client":
        message.drop()
    elif before == b"":
        suffix = b"client" if message.from_client else b"server"
        message.content = b"filled-" + suffix
    elif before == b"server":
        message.content = b"client:server"
    elif before == b"\x10\xef":
        message.content = b"\x11\xee"
    elif before == b"drop-server":
        message.drop()

    report("websocket_message", flow, message, before)


def websocket_end(flow):
    report("websocket_end", flow)
