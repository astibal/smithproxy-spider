"""Record selected public mitmproxy 12.3.1 data and exception contracts.

The probe runs only against an independently installed reference package. Its
JSON output is test data; Spider never imports or executes that package.
"""

import argparse
import json
from pathlib import Path

from mitmproxy import exceptions
from mitmproxy import http
from mitmproxy import options


def normalized(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, tuple):
        return {"tuple": [normalized(item) for item in value]}
    if isinstance(value, list):
        return [normalized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalized(item) for key, item in value.items()}
    return value


def data_values():
    headers = http.Headers([(b"X-A", b"one"), (b"X-A", b"two")])
    return [
        http.MessageData(b"HTTP/2.0", headers, b"body", None, 1.5, None),
        http.RequestData(
            b"HTTP/2.0", headers, b"body", None, 1.5, 2.5,
            "example.test", 443, b"GET", b"https", b"example.test", b"/x",
        ),
        http.ResponseData(
            b"HTTP/2.0", headers, b"body", None, 1.5, 2.5, 201, b"Created",
        ),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    parser.add_argument("--expect")
    arguments = parser.parse_args()

    values = data_values()
    data = {}
    for value in values:
        copied = value.copy()
        partial = value.copy()
        partial.set_state({"headers": ((b"Y", b"changed"),), "unknown": 1})
        data[type(value).__name__] = {
            "state": normalized(value.get_state()),
            "roundtrip": normalized(type(value).from_state(value.get_state()).get_state()),
            "copy_state": normalized(copied.get_state()),
            "copy_has_independent_headers": copied.headers is not value.headers,
            "partial_state": normalized(partial.get_state()),
        }

    exception_names = (
        "MitmproxyException", "FlowReadException", "ControlException",
        "OptionsError", "CommandError", "AddonManagerError", "AddonHalt",
    )
    result = {
        "reference": "mitmproxy 12.3.1",
        "http_exports": {
            name: getattr(http, name).__module__
            for name in ("MessageData", "RequestData", "ResponseData")
        },
        "options_export": options.Options.__module__,
        "data": data,
        "exceptions": {
            name: {
                "mro": [item.__name__ for item in getattr(exceptions, name).__mro__],
                "message": str(getattr(exceptions, name)("example")),
            }
            for name in exception_names
        },
    }

    if arguments.expect:
        expected = json.loads(Path(arguments.expect).read_text())
        if result != expected:
            raise AssertionError("Reference public surface changed")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
