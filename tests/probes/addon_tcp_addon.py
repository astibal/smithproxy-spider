"""Reference-only addon for the raw TCP lifecycle probe."""

import json


def report(name, flow, message=None, before=None):
    print("PROBE " + json.dumps({
        "flow_id": flow.id,
        "hook": name,
        "message_count": len(flow.messages),
        "from_client": None if message is None else message.from_client,
        "before": None if before is None else before.decode("latin-1"),
        "after": None if message is None else message.content.decode("latin-1"),
        "error": None if flow.error is None else flow.error.msg,
    }), flush=True)


def tcp_start(flow):
    report("tcp_start", flow)


def tcp_message(flow):
    message = flow.messages[-1]
    before = message.content
    if message.from_client:
        message.content = message.content.upper()
    else:
        message.content = b"client:" + message.content
    report("tcp_message", flow, message, before)


def tcp_end(flow):
    report("tcp_end", flow)


def tcp_error(flow):
    report("tcp_error", flow)
