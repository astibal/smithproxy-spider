"""Ordered, duplicate-preserving mappings used by addon message views."""

from collections.abc import MutableMapping
from addon_serializable import Serializable


class _FieldMapping(MutableMapping):
    """Mapping operations shared by owned values and live message views."""
    def __getitem__(self, key):
        values = self.get_all(key)
        if not values:
            raise KeyError(key)
        return values[0]

    def __setitem__(self, key, value):
        self.set_all(key, [value])

    def __delitem__(self, key):
        if key not in self:
            raise KeyError(key)
        self.set_all(key, [])

    def __iter__(self):
        return iter(dict.fromkeys(key for key, value in self.fields))

    def __len__(self):
        return len(dict.fromkeys(key for key, value in self.fields))

    def get_all(self, key):
        return [value for name, value in self.fields if name == key]

    def set_all(self, key, values):
        # Replace existing occurrences in place; extra values follow all fields.
        # Build the complete replacement before publishing a live view update.
        remaining = iter(values)
        fields = []
        for name, value in self.fields:
            if name != key:
                fields.append((name, value))
                continue
            try:
                fields.append((key, next(remaining)))
            except StopIteration:
                pass
        fields.extend((key, value) for value in remaining)
        self.fields = tuple(fields)

    def add(self, key, value):
        self.insert(len(self.fields), key, value)

    def insert(self, index, key, value):
        fields = self.fields
        before = fields[:index]
        after = fields[index:]
        # Preserve the owner's sequence contract. In API v12, a list-backed
        # multipart view rejects insertion instead of coercing it to a tuple.
        self.fields = before + ((key, value),) + after

    def items(self, multi=False):
        if multi:
            return iter(self.fields)
        return super().items()

    def keys(self, multi=False):
        if multi:
            return (key for key, value in self.fields)
        return super().keys()

    def values(self, multi=False):
        if multi:
            return (value for key, value in self.fields)
        return super().values()

    def clear(self):
        self.fields = ()

    def copy(self):
        return MultiDict(self.fields)

    def __repr__(self):
        return f"{type(self).__name__}{list(self.fields)!r}"

    def __eq__(self, other):
        return isinstance(other, _FieldMapping) and self.fields == other.fields


class MultiDict(_FieldMapping, Serializable):
    """Owned fields can be serialized; a live view has no independent state."""

    def __init__(self, fields=()):
        self.fields = tuple(fields)

    def get_state(self):
        return self.fields

    def set_state(self, state):
        self.fields = tuple(state)

    @classmethod
    def from_state(cls, state):
        return cls(state)

    def __repr__(self):
        return f"MultiDict{list(self.fields)!r}"

    def __eq__(self, other):
        if not isinstance(other, MultiDict):
            return False
        return self.fields == other.fields


class MultiDictView(_FieldMapping):
    """Read the owner on every access, including after external mutations."""

    def __init__(self, getter, setter):
        self._getter = getter
        self._setter = setter

    @property
    def fields(self):
        return self._getter()

    @fields.setter
    def fields(self, value):
        self._setter(value)


class CookieAttrs(MultiDict):
    """Case-insensitive cookie attributes; the last occurrence wins."""

    def get_all(self, key):
        return [value for name, value in self.fields if name.lower() == key.lower()]

    def __getitem__(self, key):
        values = self.get_all(key)
        if not values:
            raise KeyError(key)
        return values[-1]

    def set_all(self, key, values):
        remaining = iter(values)
        fields = []
        for name, value in self.fields:
            if name.lower() != key.lower():
                fields.append((name, value))
                continue
            try:
                fields.append((name, next(remaining)))
            except StopIteration:
                pass
        fields.extend((key, value) for value in remaining)
        self.fields = tuple(fields)

    def __iter__(self):
        seen = set()
        for name, value in self.fields:
            folded = name.lower()
            if folded not in seen:
                seen.add(folded)
                yield name

    def __len__(self):
        return len({name.lower() for name, value in self.fields})

    def copy(self):
        return CookieAttrs(self.fields)

    def __repr__(self):
        return f"CookieAttrs{list(self.fields)!r}"
