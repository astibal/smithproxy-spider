"""Reference-only addon for the UDP lifecycle probe."""

import json


def report(name, flow, message=None, before=None):
    print("PROBE " + json.dumps({
        "hook": name,
        "message_count": len(flow.messages),
        "from_client": None if message is None else message.from_client,
        "before": None if before is None else before.decode("latin-1"),
        "after": None if message is None else message.content.decode("latin-1"),
        "error": None if flow.error is None else flow.error.msg,
    }), flush=True)


def udp_start(flow):
    report("udp_start", flow)


def udp_message(flow):
    message = flow.messages[-1]
    before = message.content
    if message.from_client:
        message.content = message.content.upper()
    else:
        message.content = b"client:" + message.content
    report("udp_message", flow, message, before)


def udp_end(flow):
    report("udp_end", flow)


def udp_error(flow):
    report("udp_error", flow)

