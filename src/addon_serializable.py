"""Clean-room state contracts shared by public addon data objects.

The compatibility model keeps serialization independent of proxy transport.
Concrete Spider objects provide their own schemas; the dataclass helper is also
useful for small addon-defined values composed from supported Python types.
"""

from abc import ABCMeta, abstractmethod
from collections.abc import Sequence
from dataclasses import fields
from enum import Enum
import types
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints


State = Any


def _invalid(name, expected, value):
    raise ValueError(
        f"Invalid value for {name}. Expected {expected}, "
        f"got {value} ({type(value)})."
    )


def _union_members(annotation):
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        return get_args(annotation)
    return ()


def _convert(value, annotation, name, *, to_state):
    """Validate and recursively convert one supported annotated value."""
    if annotation is Any:
        raise TypeError(f"Unexpected type for {name}: {annotation!r}")

    members = _union_members(annotation)
    if members:
        if len(members) != 2 or type(None) not in members:
            raise AssertionError(
                f"{name}: only `x | None` union types are supported`"
            )
        if value is None and type(None) in members:
            return None
        for member in members:
            if member is type(None):
                continue
            return _convert(value, member, name, to_state=to_state)

    origin = get_origin(annotation)
    arguments = get_args(annotation)
    if origin is list:
        item_type = arguments[0]
        return [_convert(item, item_type, name, to_state=to_state) for item in value]
    if origin is tuple:
        if not isinstance(value, (tuple, list)):
            _invalid(name, annotation, value)
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            raise TypeError(f"Unexpected type for {name}: {Ellipsis!r}")
        if len(value) != len(arguments):
            _invalid(name, annotation, value)
        return tuple(_convert(item, item_type, name, to_state=to_state)
                     for item, item_type in zip(value, arguments))
    if origin is dict:
        key_type, value_type = arguments
        return {
            _convert(key, key_type, name, to_state=to_state):
            _convert(item, value_type, name, to_state=to_state)
            for key, item in value.items()
        }
    if origin is Sequence:
        return [_convert(item, arguments[0], name, to_state=to_state)
                for item in value]
    if origin is Literal:
        if value not in arguments:
            raise ValueError(
                f"Invalid value for {name}: {value!r} "
                "does not match any literal value."
            )
        return value

    if annotation is type(None):
        raise ValueError(f"Attribute {name} must not be None.")
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        if to_state:
            return value.value
        return annotation(value)

    if isinstance(annotation, type) and issubclass(annotation, Serializable):
        if to_state:
            if not isinstance(value, annotation):
                _invalid(name, annotation, value)
            return value.get_state()
        return annotation.from_state(value)

    if annotation is int and isinstance(value, (int, float)):
        return int(value)
    if annotation is float and isinstance(value, (int, float)):
        return float(value)
    if isinstance(annotation, type) and isinstance(value, annotation):
        return value
    _invalid(name, annotation, value)


class Serializable(metaclass=ABCMeta):
    """Abstract public state contract used by mitmproxy addon objects."""

    @classmethod
    @abstractmethod
    def from_state(cls, state):
        raise NotImplementedError

    @abstractmethod
    def get_state(self):
        raise NotImplementedError

    @abstractmethod
    def set_state(self, state):
        raise NotImplementedError

    def copy(self):
        return type(self).from_state(self.get_state())


class SerializableDataclass(Serializable):
    """State conversion for dataclasses with explicit supported annotations."""

    @classmethod
    def from_state(cls, state):
        converted = state
        annotations = get_type_hints(cls)
        for member in fields(cls):
            converted[member.name] = _convert(
                converted[member.name], annotations[member.name], member.name,
                to_state=False,
            )
        try:
            return cls(**converted)
        except TypeError as error:
            raise ValueError(
                f"Invalid state for {cls}: {error} (state={converted})"
            ) from error

    def get_state(self):
        annotations = get_type_hints(type(self))
        return {
            member.name: _convert(
                getattr(self, member.name), annotations[member.name], member.name,
                to_state=True,
            )
            for member in fields(self)
        }

    def set_state(self, state):
        annotations = get_type_hints(type(self))
        for member in fields(self):
            value = state.pop(member.name)
            setattr(self, member.name, _convert(
                value, annotations[member.name], member.name, to_state=False,
            ))
        if state:
            raise ValueError(
                f"Unexpected fields in {type(self).__name__}.set_state: {state}"
            )


__all__ = ["Serializable", "SerializableDataclass", "State"]
