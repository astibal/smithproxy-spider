"""Type validation shared by addon options and the public compatibility API.

The supported shapes intentionally follow the option system's narrow contract.
This is not a general-purpose runtime implementation of Python's typing module.
"""

from collections.abc import Sequence
from types import UnionType
from typing import Union, get_args, get_origin


def check_option_type(name, value, typeinfo):
    """Validate one option value and raise ``TypeError`` on a mismatch."""
    origin = get_origin(typeinfo)
    arguments = get_args(typeinfo)

    if origin in (Union, UnionType):
        for candidate in arguments:
            try:
                check_option_type(name, value, candidate)
                return
            except TypeError:
                continue
    elif origin is Sequence:
        # Option sequences are concrete JSON-like values. Arbitrary sequence
        # views such as ``range`` are deliberately not accepted here.
        if isinstance(value, (list, tuple)):
            for item in value:
                check_option_type(name, item, arguments[0])
            return
    elif typeinfo is bool:
        # ``bool`` is an ``int`` subclass, but an integer must not turn a
        # switch on merely because it is numerically truthy.
        if type(value) is bool:
            return
    elif typeinfo is float:
        # Numeric option values accept integral input without requiring the
        # caller to perform a lossless conversion first.
        if isinstance(value, (int, float)):
            return
    elif isinstance(value, typeinfo):
        return

    raise TypeError(
        f"Expected {typeinfo} for {name}, but got {type(value)}."
    )


def typespec_to_str(typespec):
    """Return the reference option UI label for a supported type shape."""
    if typespec in (str, int, bool, float):
        return typespec.__name__

    origin = get_origin(typespec)
    arguments = get_args(typespec)
    if origin is Sequence and arguments == (str,):
        return "sequence of str"

    if origin in (Union, UnionType):
        candidates = set(arguments)
        if candidates == {str, type(None)}:
            return "optional str"
        if candidates == {int, type(None)}:
            return "optional int"

    raise NotImplementedError
