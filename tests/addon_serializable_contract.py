"""Black-box contract cases for the public serialization helpers.

The collector receives either the isolated reference module or Spider's
clean-room facade.  It only uses public classes and ordinary dataclasses.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal


def _normalized(value):
    if isinstance(value, bytes):
        return {"bytes": value.hex()}
    if isinstance(value, Enum):
        return {"enum": type(value).__name__, "value": value.value}
    if isinstance(value, tuple):
        return {"tuple": [_normalized(item) for item in value]}
    if isinstance(value, list):
        return [_normalized(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalized(item) for key, item in value.items()}
    if hasattr(value, "get_state"):
        return {"object": type(value).__name__, "state": _normalized(value.get_state())}
    return value


def _observed(operation):
    try:
        return {"result": _normalized(operation())}
    except Exception as error:
        return {"error": type(error).__name__, "message": str(error)}


def collect(serializable):
    @dataclass
    class Child(serializable.SerializableDataclass):
        value: int

    class Choice(Enum):
        FIRST = "first"
        SECOND = "second"

    @dataclass
    class Sample(serializable.SerializableDataclass):
        integer: int
        floating: float
        flag: bool
        text: str
        payload: bytes
        optional: int | None
        numbers: list[int]
        pair: tuple[str, int]
        mapping: dict[str, int]
        sequence: Sequence[int]
        choice: Choice
        label: Literal["short", "long"]
        child: Child
        children: list[Child]

    @dataclass
    class AnyValue(serializable.SerializableDataclass):
        value: Any

    @dataclass
    class BroadUnion(serializable.SerializableDataclass):
        value: int | str

    @dataclass
    class VariadicTuple(serializable.SerializableDataclass):
        value: tuple[int, ...]

    def sample():
        return Sample(
            1, 2.5, True, "text", b"payload", None, [3, 4], ("pair", 5),
            {"key": 6}, (7, 8), Choice.SECOND, "short", Child(9), [Child(10)],
        )

    cases = {}
    value = sample()
    cases["get_state"] = _observed(value.get_state)
    cases["copy"] = _observed(value.copy)

    state = value.get_state()
    cases["from_state"] = _observed(lambda: Sample.from_state(state))
    cases["from_state_input_after"] = _normalized(state)

    state = value.get_state()
    target = sample()
    cases["set_state"] = _observed(lambda: target.set_state(state))
    cases["set_state_input_after"] = _normalized(state)
    cases["set_state_target_after"] = _normalized(target)

    mutations = {
        "integer_as_bool": {"integer": True},
        "integer_as_float": {"integer": 1.0},
        "integer_as_string": {"integer": "1"},
        "float_as_integer": {"floating": 2},
        "float_as_string": {"floating": "2.5"},
        "flag_as_integer": {"flag": 1},
        "flag_as_string": {"flag": "yes"},
        "text_as_bytes": {"text": b"text"},
        "bytes_as_text": {"payload": "payload"},
        "list_as_tuple": {"numbers": (3, 4)},
        "list_as_string": {"numbers": "34"},
        "tuple_as_list": {"pair": ["pair", 5]},
        "mapping_as_pairs": {"mapping": [("key", 6)]},
        "sequence_as_tuple": {"sequence": (7, 8)},
        "sequence_as_list": {"sequence": [7, 8]},
        "sequence_as_string": {"sequence": "78"},
        "bad_literal": {"label": "other"},
        "bad_enum": {"choice": "other"},
        "nested_object_as_state": {"child": Child(11)},
        "nested_state": {"child": {"value": 11}},
    }
    baseline = value.get_state()
    for name, changes in mutations.items():
        changed = dict(baseline)
        changed.update(changes)
        cases["from/" + name] = _observed(lambda changed=changed: Sample.from_state(changed))

    for name, field, field_value in (
        ("integer_as_bool", "integer", True),
        ("integer_as_float", "integer", 1.0),
        ("integer_as_string", "integer", "1"),
        ("float_as_integer", "floating", 2),
        ("float_as_string", "floating", "2.5"),
        ("flag_as_integer", "flag", 1),
        ("flag_as_string", "flag", "yes"),
        ("text_as_bytes", "text", b"text"),
        ("bytes_as_text", "payload", "payload"),
        ("list_as_tuple", "numbers", (3, 4)),
        ("list_as_string", "numbers", "34"),
        ("tuple_as_list", "pair", ["pair", 5]),
        ("mapping_as_pairs", "mapping", [("key", 6)]),
        ("sequence_as_tuple", "sequence", (7, 8)),
        ("sequence_as_list", "sequence", [7, 8]),
        ("sequence_as_string", "sequence", "78"),
        ("bad_literal", "label", "other"),
        ("bad_enum", "choice", "other"),
    ):
        candidate = sample()
        setattr(candidate, field, field_value)
        cases["get/" + name] = _observed(candidate.get_state)

    missing = value.get_state()
    del missing["text"]
    cases["from/missing"] = _observed(lambda: Sample.from_state(missing))
    extra = value.get_state()
    extra["extra"] = 1
    cases["from/extra"] = _observed(lambda: Sample.from_state(extra))
    cases["get/any"] = _observed(lambda: AnyValue("opaque").get_state())
    cases["get/broad_union"] = _observed(lambda: BroadUnion(1).get_state())
    cases["get/variadic_tuple"] = _observed(lambda: VariadicTuple((1, 2)).get_state())

    return cases
