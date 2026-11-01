"""Reference-only addon for destructive WebSocket lifecycle scenarios."""

import base64
import json
import os


SCENARIO = os.environ["WEBSOCKET_PROBE_SCENARIO"]


def encoded(value):
    if value is None:
        return None
    return base64.b64encode(value).decode("ascii")


def report(hook, flow, message=None):
    websocket = flow.websocket
    item = {
        "hook": hook,
        "live": flow.live,
        "error": None if flow.error is None else str(flow.error),
        "message_count": len(websocket.messages) if websocket else 0,
        "from_client": None if message is None else message.from_client,
        "content": None if message is None else encoded(message.content),
        "close_code": None if websocket is None else websocket.close_code,
        "close_reason": None if websocket is None else websocket.close_reason,
        "closed_by_client": (
            None if websocket is None else websocket.closed_by_client),
    }
    print("PROBE " + json.dumps(item, sort_keys=True), flush=True)


def websocket_start(flow):
    if SCENARIO == "kill-start":
        flow.kill()
    report("websocket_start", flow)


def websocket_message(flow):
    message = flow.websocket.messages[-1]
    if SCENARIO == "kill-client-message" and message.from_client:
        flow.kill()
    if SCENARIO == "kill-server-message" and not message.from_client:
        flow.kill()
    report("websocket_message", flow, message)


def websocket_end(flow):
    report("websocket_end", flow)
