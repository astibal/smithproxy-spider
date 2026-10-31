"""Record tagged-netstring edge behavior through the public API."""

from io import BytesIO
import json
import re

from mitmproxy.io import tnetstring


def outcome(callback):
    try:
        value = callback()
        if isinstance(value, memoryview):
            value = bytes(value)
        if isinstance(value, bytes):
            value = {"bytes": value.hex()}
        return {"ok": True, "type": type(value).__name__, "value": value}
    except Exception as error:
        message = re.sub(r"<memory at 0x[0-9a-fA-F]+>", "<memory>", str(error))
        message = re.sub(r"<object object at 0x[0-9a-fA-F]+>", "<object>", message)
        cause = error.__cause__
        return {
            "ok": False,
            "type": type(error).__name__,
            "message": message,
            "cause": None if cause is None else type(cause).__name__,
        }


def load(payload):
    return tnetstring.load(BytesIO(payload))


def dump(value):
    destination = BytesIO()
    result = tnetstring.dump(value, destination)
    return {"result": result, "wire": destination.getvalue().hex()}


cases = {
    "dump": outcome(lambda: dump({"a": 1})),
    "dump-unsupported": outcome(lambda: tnetstring.dumps(object())),
    "split-invalid-prefix": outcome(
        lambda: tnetstring.split(memoryview(b"abc:data"), b":")
    ),
    "loads-invalid-prefix": outcome(lambda: tnetstring.loads(b"x:a,")),
    "parse-invalid-float": outcome(
        lambda: tnetstring.parse(ord("^"), memoryview(b"x"))
    ),
    "parse-invalid-boolean": outcome(
        lambda: tnetstring.parse(ord("!"), memoryview(b"x"))
    ),
    "parse-invalid-null": outcome(
        lambda: tnetstring.parse(ord("~"), memoryview(b"x"))
    ),
    "load-valid": outcome(lambda: load(b"3:abc,")),
    "load-empty": outcome(lambda: load(b"")),
    "load-missing-colon": outcome(lambda: load(b"3")),
    "load-invalid-prefix": outcome(lambda: load(b"x:a,")),
    "load-negative": outcome(lambda: load(b"-1:,")),
    "load-truncated": outcome(lambda: load(b"3:ab,")),
}

print(json.dumps({"reference": "12.3.1", "cases": cases}, sort_keys=True))
