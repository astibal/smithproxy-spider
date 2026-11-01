"""Reference-only addon proving shared state across live WebSocket flows."""

import base64
import json


active = 0
ordinal = 0


def report(hook, flow, message=None, before=None):
    print("PROBE " + json.dumps({
        "hook": hook,
        "active": active,
        "ordinal": ordinal,
        "message_count": len(flow.websocket.messages),
        "from_client": None if message is None else message.from_client,
        "before": (
            None if before is None
            else base64.b64encode(before).decode("ascii")),
        "after": (
            None if message is None
            else base64.b64encode(message.content).decode("ascii")),
    }, sort_keys=True), flush=True)


def websocket_start(flow):
    global active
    active += 1
    report("websocket_start", flow)


def websocket_message(flow):
    global ordinal
    message = flow.websocket.messages[-1]
    before = message.content
    ordinal += 1
    message.content = str(ordinal).encode("ascii") + b":" + before
    report("websocket_message", flow, message, before)


def websocket_end(flow):
    global active
    report("websocket_end", flow)
    active -= 1
