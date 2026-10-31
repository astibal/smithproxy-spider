"""Black-box contract for uncommon public Headers operations."""

from __future__ import annotations

import copy


def _normalize(value):
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    return value


def _outcome(callback):
    try:
        value = callback()
    except Exception as error:
        return {
            "status": "error",
            "type": type(error).__name__,
            "message": str(error),
        }
    return {
        "status": "ok",
        "value": _normalize(value),
    }


def _snapshot(headers):
    return {
        "fields": [
            [name.hex(), value.hex()]
            for name, value in headers.fields
        ],
        "items": [list(item) for item in headers.items()],
        "multi": [list(item) for item in headers.items(multi=True)],
        "keys": list(headers),
        "length": len(headers),
    }


def _mutation(http, operation, initial=((b"X-A", b"one"), (b"x-a", b"two"))):
    headers = http.Headers(initial)
    result = _outcome(lambda: operation(headers))
    return {
        "result": result,
        "after": _normalize(headers.fields),
    }


def collect(http):
    cases = {}

    constructors = {
        "none fields": lambda: http.Headers(None),
        "text raw field": lambda: http.Headers((("X", b"one"),)),
        "text raw value": lambda: http.Headers(((b"X", "one"),)),
        "short raw field": lambda: http.Headers(((b"X",),)),
        "long raw field": lambda: http.Headers(((b"X", b"one", b"extra"),)),
        "invalid keyword value": lambda: http.Headers(x_test=object()),
    }
    cases["constructors"] = {
        name: _outcome(callback)
        for name, callback in constructors.items()
    }

    headers = http.Headers(((b"X-A", b"one"), (b"x-a", b"two")))
    cases["mapping reads"] = {
        "contains upper": "X-A" in headers,
        "contains bytes": b"x-a" in headers,
        "contains invalid": _outcome(lambda: object() in headers),
        "get missing": headers.get("missing"),
        "get default": headers.get("missing", "fallback"),
        "getitem missing": _outcome(lambda: headers["missing"]),
    }

    cases["pop existing"] = _mutation(http, lambda value: value.pop("x-a"))
    cases["pop missing"] = _mutation(http, lambda value: value.pop("missing"))
    cases["pop default"] = _mutation(
        http,
        lambda value: value.pop("missing", "fallback"),
    )
    cases["setdefault existing"] = _mutation(
        http,
        lambda value: value.setdefault("X-A", "replacement"),
    )
    cases["setdefault missing"] = _mutation(
        http,
        lambda value: value.setdefault("X-B", "three"),
    )
    cases["popitem"] = _mutation(http, lambda value: value.popitem())
    cases["clear"] = _mutation(http, lambda value: value.clear())
    cases["update mapping"] = _mutation(
        http,
        lambda value: value.update({"X-A": "changed", "X-B": "three"}),
    )
    cases["update pairs"] = _mutation(
        http,
        lambda value: value.update((("X-A", "changed"), ("X-B", "three"))),
    )
    cases["delete missing"] = _mutation(http, lambda value: value.__delitem__("missing"))

    def set_all_generator(value):
        value.set_all("X-A", (item for item in ("first", "second", "third")))

    cases["set_all generator"] = _mutation(http, set_all_generator)
    cases["set_all invalid atomic"] = _mutation(
        http,
        lambda value: value.set_all("X-A", ("valid", object())),
    )
    cases["insert negative"] = _mutation(
        http,
        lambda value: value.insert(-1, "X-B", "middle"),
    )
    cases["insert beyond end"] = _mutation(
        http,
        lambda value: value.insert(99, b"X-B", b"last"),
    )

    def assign_fields(value):
        value.fields = [(b"Y", b"three")]
        return type(value.fields).__name__

    cases["assign fields"] = _mutation(http, assign_fields)
    cases["assign invalid fields"] = _mutation(
        http,
        lambda value: setattr(value, "fields", [("Y", b"three")]),
    )

    original = http.Headers(((b"X", b"\xff"),))
    shallow = copy.copy(original)
    deep = copy.deepcopy(original)
    shallow["X"] = shallow["X"]
    deep.add("Y", "other")
    cases["copy semantics"] = {
        "original": _normalize(original.fields),
        "shallow": _normalize(shallow.fields),
        "deep": _normalize(deep.fields),
        "identity": [shallow is original, deep is original],
    }

    return cases
