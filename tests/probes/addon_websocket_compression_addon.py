"""Reference-only addon for negotiated WebSocket compression behavior."""

import base64
import json


def websocket_message(flow):
    message = flow.websocket.messages[-1]
    before = message.content
    prefix = b"client-mutated:" if message.from_client else b"server-mutated:"
    message.content = prefix + before
    print("PROBE " + json.dumps({
        "hook": "websocket_message",
        "from_client": message.from_client,
        "message_count": len(flow.websocket.messages),
        "before": base64.b64encode(before).decode("ascii"),
        "after": base64.b64encode(message.content).decode("ascii"),
    }, sort_keys=True), flush=True)
