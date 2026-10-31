"""Clean-room HTTP objects exposed to addon scripts by Spider.

These are editable application objects, never an alternative wire parser.
The Parts adapter owns conversion and publication through the native API.
"""

from collections.abc import MutableMapping
from addon_serializable import Serializable


def _header_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "surrogateescape")
    raise TypeError(f"Expected str or bytes, but got {type(value).__name__}.")


def _header_text(value):
    return value.decode("utf-8", "surrogateescape")


class Headers(MutableMapping, Serializable):
    """Ordered byte fields with a case-insensitive, joined text mapping view."""

    def __init__(self, fields=(), **headers):
        values = []
        for name, value in fields:
            if not isinstance(name, bytes) or not isinstance(value, bytes):
                raise TypeError("Header fields must be bytes.")
            values.append((name, value))
        self.fields = tuple(values)
        for name, value in headers.items():
            self[name.replace("_", "-")] = value

    def get_all(self, key):
        needle = _header_bytes(key).lower()
        return [_header_text(value) for name, value in self.fields
                if name.lower() == needle]

    def set_all(self, key, values):
        name = _header_bytes(key)
        needle = name.lower()
        replacements = tuple(_header_bytes(value) for value in values)
        updated = []
        position = 0
        for original, value in self.fields:
            if original.lower() != needle:
                updated.append((original, value))
            elif position < len(replacements):
                # Existing occurrences keep their position and original casing.
                updated.append((original, replacements[position]))
                position += 1
        for value in replacements[position:]:
            updated.append((name, value))
        self.fields = tuple(updated)

    def add(self, key, value):
        self.fields += ((_header_bytes(key), _header_bytes(value)),)

    def insert(self, index, key, value):
        fields = list(self.fields)
        fields.insert(index, (_header_bytes(key), _header_bytes(value)))
        self.fields = tuple(fields)

    def __getitem__(self, key):
        values = self.get_all(key)
        if not values:
            raise KeyError(key)
        return ", ".join(values)

    def __setitem__(self, key, value):
        self.set_all(key, [value])

    def __delitem__(self, key):
        if not self.get_all(key):
            raise KeyError(_header_bytes(key))
        self.set_all(key, ())

    def __iter__(self):
        seen = set()
        for name, value in self.fields:
            normalized = name.lower()
            if normalized not in seen:
                seen.add(normalized)
                yield _header_text(name)

    def __len__(self):
        return len({name.lower() for name, value in self.fields})

    def items(self, multi=False):
        if multi:
            return [(_header_text(name), _header_text(value)) for name, value in self.fields]
        return [(name, self[name]) for name in self]

    def keys(self, multi=False):
        if multi:
            return [_header_text(name) for name, value in self.fields]
        return list(self)

    def values(self, multi=False):
        return [value for name, value in self.items(multi)]

    def __bytes__(self):
        return b"".join(name + b": " + value + b"\r\n" for name, value in self.fields)

    def __repr__(self):
        return f"Headers{list(self.fields)!r}"

    def __eq__(self, other):
        if not isinstance(other, Headers):
            return NotImplemented
        return self.fields == other.fields

    def get_state(self):
        return self.fields

    def set_state(self, state):
        self.fields = Headers(state).fields

    @classmethod
    def from_state(cls, state):
        return cls(state)

    def copy(self):
        return type(self)(self.fields)
