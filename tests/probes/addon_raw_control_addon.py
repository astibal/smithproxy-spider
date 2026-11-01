"""Reference-only addon for raw TCP and UDP control observations."""

import json
import os

from mitmproxy.flow import Error


SCENARIO = os.environ["RAW_CONTROL_SCENARIO"]


def report(hook, flow, message=None, before=None):
    print("PROBE " + json.dumps({
        "hook": hook,
        "flow_id": flow.id,
        "live": flow.live,
        "message_count": len(flow.messages),
        "from_client": None if message is None else message.from_client,
        "before": None if before is None else before.decode("latin-1"),
        "after": None if message is None else message.content.decode("latin-1"),
        "error": None if flow.error is None else flow.error.msg,
    }), flush=True)


def apply_start_control(flow):
    if SCENARIO == "kill-start":
        flow.kill()


def apply_message_control(flow):
    message = flow.messages[-1]
    before = message.content

    if SCENARIO == "kill-client-message" and message.from_client:
        flow.kill()
    elif SCENARIO == "kill-server-message" and not message.from_client:
        flow.kill()
    elif SCENARIO == "empty-client-message" and message.from_client:
        message.content = b""
    elif SCENARIO == "empty-server-message" and not message.from_client:
        message.content = b""
    elif SCENARIO == "set-live-false" and message.from_client:
        flow.live = False
    elif SCENARIO == "set-custom-error" and message.from_client:
        flow.error = Error("custom transport error")
    elif SCENARIO == "tag-messages":
        prefix = b"C:" if message.from_client else b"S:"
        message.content = prefix + message.content

    return message, before


def tcp_start(flow):
    apply_start_control(flow)
    report("tcp_start", flow)


def tcp_message(flow):
    message, before = apply_message_control(flow)
    report("tcp_message", flow, message, before)


def tcp_end(flow):
    report("tcp_end", flow)


def tcp_error(flow):
    report("tcp_error", flow)


def udp_start(flow):
    apply_start_control(flow)
    report("udp_start", flow)


def udp_message(flow):
    message, before = apply_message_control(flow)
    report("udp_message", flow, message, before)


def udp_end(flow):
    report("udp_end", flow)


def udp_error(flow):
    report("udp_error", flow)
