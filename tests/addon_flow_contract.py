"""Own black-box lifecycle probes; no reference implementation is included."""


def collect_transport(message_type, flow_type, make_connections):
    observations = []
    for direction in (True, False):
        for content in (b'', b'hello', b'\x00\xff'):
            message = message_type(direction, content, 123.5)
            duplicate = message.copy()
            restored = message_type.from_state(message.get_state())
            observations.append([repr(message), repr(message.get_state()),
                                 duplicate is not message,
                                 duplicate.get_state() == message.get_state(),
                                 restored.get_state() == message.get_state()])
    message = message_type(True, b'x', 1)
    message.set_state((False, b'changed', 0))
    observations.append(['set-zero', message.timestamp == 0,
                         message.copy().timestamp != 0,
                         message_type.from_state((False, b'', 0)).timestamp != 0])
    mutable = message_type(True, bytearray(b'a'), 1)
    duplicate = mutable.copy()
    observations.append(['mutable-content', duplicate.content is mutable.content])
    client, server = make_connections()
    flow = flow_type(client, server, live=True)
    flow.messages.append(message_type(True, b'first', 99))
    flow.messages.append(message_type(False, b'second', 100))
    duplicate = flow.copy()
    observations.append(['flow', flow.type, flow.timestamp_start == client.timestamp_start,
                         duplicate.id != flow.id, duplicate.live,
                         duplicate.messages is not flow.messages,
                         duplicate.messages[0] is not flow.messages[0]])
    flow.intercept()
    flow.resume()
    flow.kill()
    observations.append(['killed', flow.live, flow.intercepted, flow.error.msg, flow.killable])
    return observations


def collect(http, errors, make_connections):
    client, server = make_connections()
    flow = http.HTTPFlow(client, server, live=True)
    flow.request = http.Request.make("GET", "https://example.org/")
    observations = []

    def record(label):
        observations.append({
            "label": label,
            "live": flow.live,
            "intercepted": flow.intercepted,
            "killable": flow.killable,
            "error": None if flow.error is None else flow.error.msg,
            "type": flow.type,
            "response": flow.response is None,
            "websocket": flow.websocket is None,
            "timestamp_matches": flow.timestamp_start == flow.request.timestamp_start,
        })

    record("initial")
    flow.intercept()
    record("intercepted")
    flow.intercept()
    record("intercepted again")
    copied = flow.copy()
    copy_state = {"new_id": copied.id != flow.id, "live": copied.live,
                  "intercepted": copied.intercepted,
                  "new_request": copied.request is not flow.request}
    flow.resume()
    record("resumed")
    flow.error = errors.Error("upstream failed", 123)
    record("error")
    flow.intercept()
    flow.kill()
    record("killed")
    try:
        flow.kill()
    except Exception as error:
        failure = [type(error).__name__, str(error)]
    return {"events": observations, "copy": copy_state, "repeated_kill": failure}
