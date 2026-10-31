"""Public event values for the Spider-owned addon compatibility facade."""

from dataclasses import dataclass, fields
import re
from typing import ClassVar


class Hook:
    name: ClassVar[str | None] = None

    def __new__(cls, *args, **kwargs):
        if cls is Hook:
            raise TypeError('Hook may not be instantiated directly.')
        return super().__new__(cls)

    def __init_subclass__(cls):
        super().__init_subclass__()
        if cls.name is None:
            label = cls.__name__.removesuffix('Hook')
            cls.name = (label[:1] + re.sub(r'([A-Z]+)', r'_\1', label[1:])).lower()

    def args(self):
        return [getattr(self, field.name) for field in fields(self)]


@dataclass
class ConfigureHook(Hook):
    updated: set[str]


@dataclass
class RunningHook(Hook):
    pass


@dataclass
class DoneHook(Hook):
    pass


@dataclass
class UpdateHook(Hook):
    flows: object


@dataclass
class LoadHook(Hook):
    loader: object
