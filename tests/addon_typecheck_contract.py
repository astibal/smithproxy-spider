"""Public type-check observations shared with the reference probe."""

from collections.abc import Sequence as ABCSequence
from typing import Optional, Sequence


TYPE_SPECS = {
    "str": str,
    "int": int,
    "bool": bool,
    "float": float,
    "optional_str": Optional[str],
    "optional_int": Optional[int],
    "optional_bool": Optional[bool],
    "sequence_str": Sequence[str],
    "abc_sequence_str": ABCSequence[str],
    "sequence_int": Sequence[int],
    "str_or_int": str | int,
    "list_str": list[str],
}


VALUES = {
    "none": None,
    "true": True,
    "zero": 0,
    "float": 1.5,
    "text": "value",
    "bytes": b"value",
    "empty_list": [],
    "text_list": ["one", "two"],
    "int_list": [1, 2],
    "text_tuple": ("one", "two"),
    "text_set": {"one", "two"},
    "range": range(2),
}


def outcome(operation):
    try:
        value = operation()
    except Exception as error:
        return {
            "error": type(error).__name__,
            "message": str(error),
        }
    return {"value": value}


def collect(typecheck):
    labels = {
        name: outcome(lambda typespec=typespec: typecheck.typespec_to_str(typespec))
        for name, typespec in TYPE_SPECS.items()
    }
    accepted = {}
    representative_errors = {}
    for spec_name, typespec in TYPE_SPECS.items():
        results = {
            value_name: outcome(
                lambda value=value, typespec=typespec:
                    typecheck.check_option_type("probe", value, typespec)
            )
            for value_name, value in VALUES.items()
        }
        accepted[spec_name] = [
            name for name, result in results.items() if "value" in result
        ]
        rejected = [result for result in results.values() if "error" in result]
        representative_errors[spec_name] = rejected[0] if rejected else None
    return {
        "labels": labels,
        "accepted": accepted,
        "representative_errors": representative_errors,
        "nested_sequence_error": outcome(
            lambda: typecheck.check_option_type(
                "probe", ["valid", 1], Sequence[str]
            )
        ),
    }
