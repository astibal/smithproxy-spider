"""Reference-only addon for the live WebSocket lifecycle probe."""

import json


def report(name, flow, message=None, before=None):
    print("PROBE " + json.dumps({
        "hook": name,
        "message_count": len(flow.websocket.messages) if flow.websocket else 0,
        "from_client": None if message is None else message.from_client,
        "before": None if before is None else before.decode("latin-1"),
        "after": None if message is None else message.content.decode("latin-1"),
        "dropped": None if message is None else message.dropped,
        "injected": None if message is None else message.injected,
    }), flush=True)


def websocket_start(flow):
    report("websocket_start", flow)


def websocket_message(flow):
    message = flow.websocket.messages[-1]
    before = message.content
    if message.from_client:
        message.content = message.content.upper()
    else:
        message.content = b"client:" + message.content
    report("websocket_message", flow, message, before)


def websocket_end(flow):
    report("websocket_end", flow)

