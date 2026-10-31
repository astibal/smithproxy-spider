"""Detached WebSocket values for addons; no framing or transport ownership."""

from dataclasses import dataclass, field
import time
import warnings

from wsproto.frame_protocol import Opcode
from addon_serializable import Serializable, SerializableDataclass


WebSocketMessageState = tuple[int, bool, bytes, float, bool, bool]


class WebSocketMessage(Serializable):
    def __init__(self, type, from_client, content, timestamp=None,
                 dropped=False, injected=False):
        self.type = Opcode(type)
        self.from_client = from_client
        self.content = content
        self.timestamp = timestamp or time.time()
        self.dropped = dropped
        self.injected = injected

    @property
    def is_text(self):
        return self.type == Opcode.TEXT

    def _require_text(self):
        if not self.is_text:
            label = self.type.name.capitalize()
            raise AttributeError(f"{label} WebSocket frames do not have a 'text' attribute.")

    @property
    def text(self):
        self._require_text()
        return self.content.decode('utf-8')

    @text.setter
    def text(self, value):
        self._require_text()
        self.content = value.encode('utf-8')

    def __repr__(self):
        if self.is_text:
            return repr(self.content.decode('utf-8', errors='replace'))
        return repr(self.content)

    def drop(self):
        self.dropped = True

    def kill(self):
        warnings.warn('WebSocketMessage.kill() is deprecated, use .drop() instead.',
                      DeprecationWarning, stacklevel=2)
        self.drop()

    def get_state(self):
        return (int(self.type), self.from_client, self.content, self.timestamp,
                self.dropped, self.injected)

    def set_state(self, state):
        opcode, self.from_client, self.content, self.timestamp, self.dropped, self.injected = state
        self.type = Opcode(opcode)

    @classmethod
    def from_state(cls, state):
        return cls(*state)

    def copy(self):
        return type(self).from_state(self.get_state())


@dataclass
class WebSocketData(SerializableDataclass):
    messages: list[WebSocketMessage] = field(default_factory=list)
    closed_by_client: bool | None = None
    close_code: int | None = None
    close_reason: str | None = None
    timestamp_end: float | None = None

    def get_state(self):
        return {
            'messages': [message.get_state() for message in self.messages],
            'closed_by_client': self.closed_by_client,
            'close_code': self.close_code,
            'close_reason': self.close_reason,
            'timestamp_end': self.timestamp_end,
        }

    def set_state(self, state):
        # Updating an existing object consumes fields in order. It can leave
        # partial updates when a later field is missing, unlike construction.
        for name in ('messages', 'closed_by_client', 'close_code', 'close_reason', 'timestamp_end'):
            value = state.pop(name)
            if name == 'messages':
                value = [WebSocketMessage.from_state(item) for item in value]
            setattr(self, name, value)
        if state:
            raise ValueError(f'Unexpected fields in WebSocketData.set_state: {state}')

    @classmethod
    def from_state(cls, state):
        # Construction keeps keys but replaces serialized message values in
        # the caller's dictionary, matching the public state contract.
        state['messages'] = [WebSocketMessage.from_state(item) for item in state['messages']]
        for name in ('closed_by_client', 'close_code', 'close_reason', 'timestamp_end'):
            if name not in state:
                raise KeyError(name)
        try:
            return cls(**state)
        except TypeError as error:
            raise ValueError(f'Invalid state for {cls.__name__}: {error}') from error

    def copy(self):
        return type(self).from_state(self.get_state())
