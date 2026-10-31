"""Addon flow identity and lifecycle, without transport ownership.

The adapter supplies connection objects and observes control decisions after
dispatch. Nothing in this module opens sockets or implements proxy protocols.
"""

import asyncio
from copy import deepcopy
from dataclasses import dataclass, field
import time
import uuid
import warnings

from addon_exceptions import MitmproxyException
from addon_serializable import Serializable, SerializableDataclass


class ControlException(MitmproxyException):
    """A requested flow-control operation is not valid in the current state."""


@dataclass
class Error(SerializableDataclass):
    msg: str
    timestamp: float = field(default_factory=time.time)

    KILLED_MESSAGE = "Connection killed."

    def __post_init__(self):
        self.timestamp = float(self.timestamp)

    def __str__(self):
        return self.msg

    def __repr__(self):
        return self.msg

    def get_state(self):
        return {"msg": self.msg, "timestamp": self.timestamp}

    def set_state(self, state):
        self.msg = state["msg"]
        self.timestamp = float(state["timestamp"])

    @classmethod
    def from_state(cls, state):
        return cls(**state)

    def copy(self):
        return deepcopy(self)


class Flow(Serializable):
    """Shared addon identity and controls; the adapter owns all transport I/O."""

    error = None
    marked = ""

    def __init__(self, client_conn, server_conn, live=False):
        self.id = str(uuid.uuid4())
        self.client_conn = client_conn
        self.server_conn = server_conn
        self.live = live
        self.timestamp_created = time.time()
        self.intercepted = False
        self.is_replay = None
        self.marked = ""
        self.metadata = {}
        self.comment = ""
        self._resume_event = None
        self._backup = None

    def get_state(self):
        # This is a saved observation, not a transport checkpoint. Live socket
        # state and asynchronous resume events deliberately stay out of it.
        return {
            "version": 21,
            "type": self.type,
            "id": self.id,
            "error": None if self.error is None else self.error.get_state(),
            "client_conn": self.client_conn.get_state(),
            "server_conn": self.server_conn.get_state(),
            "intercepted": self.intercepted,
            "is_replay": self.is_replay,
            "marked": self.marked,
            "metadata": deepcopy(self.metadata),
            "comment": self.comment,
            "timestamp_created": self.timestamp_created,
            "backup": deepcopy(self._backup),
        }

    @classmethod
    def from_state(cls, state):
        from addon_connection import Client, Server

        kinds = {"http": HTTPFlow, "tcp": TCPFlow, "udp": UDPFlow}
        if state["type"] == "dns":
            # Import lazily: addon_dns builds DNSFlow on top of this base class.
            from addon_dns import DNSFlow
            kinds["dns"] = DNSFlow
        kind = state["type"]
        if kind not in kinds:
            raise ValueError(f"Unknown flow type: {kind}")
        # Empty descriptors are private construction placeholders. set_state
        # replaces their fields before the detached flow is returned.
        result = kinds[kind](Client(peername=None, sockname=None), Server(address=None))
        result.set_state(state)
        return result

    def set_state(self, state):
        if state.pop("version") != 21:
            raise AssertionError("Unsupported flow state version")
        if state.pop("type") != self.type:
            raise AssertionError("Flow state type does not match the destination")
        self.id = state.pop("id")
        error = state.pop("error")
        self.error = None if error is None else Error.from_state(error)
        # Keep descriptor identity: addons may retain references to them.
        # Their own setters enforce restrictions on an open destination.
        self.client_conn.set_state(state.pop("client_conn"))
        self.server_conn.set_state(state.pop("server_conn"))
        for name in ("intercepted", "is_replay", "marked", "metadata", "comment",
                     "timestamp_created"):
            setattr(self, name, state.pop(name))
        self._backup = state.pop("backup")
        if state:
            raise AssertionError("Unexpected flow state fields")

    def backup(self, force=False):
        # The v12 reference retains the first snapshot even with force=True.
        # Preserve that observable contract rather than redefining the flag.
        if self._backup is None:
            self._backup = self.get_state()

    def modified(self):
        if self._backup is None:
            return False
        # The reference compares the complete state, including its backup
        # field. Consequently a newly backed-up flow already reports modified.
        return self.get_state() != self._backup

    def revert(self):
        if self._backup is not None:
            self.set_state(deepcopy(self._backup))
            self._backup = None

    @property
    def timestamp_start(self):
        return self.client_conn.timestamp_start

    @property
    def killable(self):
        return bool(self.live and
                    (self.error is None or self.error.msg != Error.KILLED_MESSAGE))

    def kill(self):
        if not self.killable:
            raise ControlException("Flow is not killable.")
        self.error = Error(Error.KILLED_MESSAGE)
        self.live = False
        self.resume()

    def intercept(self):
        self.intercepted = True
        if self._resume_event is not None:
            self._resume_event.clear()

    def resume(self):
        self.intercepted = False
        if self._resume_event is not None:
            self._resume_event.set()

    async def wait_for_resume(self):
        if not self.intercepted:
            return
        if self._resume_event is None:
            self._resume_event = asyncio.Event()
        await self._resume_event.wait()

    def copy(self):
        # A detached copy must not share the live flow's wake-up event, nor its
        # transport identity. Connection descriptors and metadata are copied.
        result = object.__new__(type(self))
        for name, value in self.__dict__.items():
            if name != "_resume_event":
                setattr(result, name, deepcopy(value))
        result.id = str(uuid.uuid4())
        result.live = False
        result._resume_event = None
        return result


class HTTPFlow(Flow):
    """One exchange, retained across its request and response callbacks."""

    type = "http"
    response = None
    websocket = None

    @property
    def mode(self):
        warnings.warn('HTTPFlow.mode is deprecated.', DeprecationWarning,
                      stacklevel=2)
        return getattr(self, '_mode', 'regular')

    @mode.setter
    def mode(self, value):
        warnings.warn('HTTPFlow.mode is deprecated.', DeprecationWarning,
                      stacklevel=2)
        self._mode = value

    def get_state(self):
        state = super().get_state()
        state["request"] = self.request.get_state()
        state["response"] = None if self.response is None else self.response.get_state()
        state["websocket"] = None if self.websocket is None else self.websocket.get_state()
        return state

    def set_state(self, state):
        from addon_http_message import Request, Response

        self.request = Request.from_state(state.pop("request"))
        response = state.pop("response")
        self.response = None if response is None else Response.from_state(response)
        websocket = state.pop("websocket")
        self.websocket = None
        if websocket is not None:
            from addon_websocket import WebSocketData
            self.websocket = WebSocketData.from_state(websocket)
        super().set_state(state)

    @property
    def timestamp_start(self):
        return self.request.timestamp_start


class _TransportMessage(Serializable):
    def __init__(self, from_client, content, timestamp=None):
        self.from_client = from_client
        self.content = content
        self.timestamp = timestamp or time.time()

    def __repr__(self):
        direction = '->' if self.from_client else '<-'
        return f'{direction} {self.content!r}'

    def get_state(self):
        return self.from_client, self.content, self.timestamp

    def set_state(self, state):
        self.from_client, self.content, self.timestamp = state

    @classmethod
    def from_state(cls, state):
        return cls(*state)

    def copy(self):
        return type(self).from_state(self.get_state())


class TCPMessage(_TransportMessage):
    """One observed stream chunk, not an application-protocol message."""


class UDPMessage(_TransportMessage):
    """One complete datagram; the adapter must preserve this boundary."""


class TCPFlow(Flow):
    type = 'tcp'

    def __init__(self, client_conn, server_conn, live=False):
        super().__init__(client_conn, server_conn, live)
        self.messages = []

    def get_state(self):
        state = super().get_state()
        state["messages"] = [message.get_state() for message in self.messages]
        return state

    def set_state(self, state):
        self.messages = [TCPMessage.from_state(item) for item in state.pop("messages")]
        super().set_state(state)


class UDPFlow(Flow):
    type = 'udp'

    def __init__(self, client_conn, server_conn, live=False):
        super().__init__(client_conn, server_conn, live)
        self.messages = []

    def get_state(self):
        state = super().get_state()
        state["messages"] = [message.get_state() for message in self.messages]
        return state

    def set_state(self, state):
        self.messages = [UDPMessage.from_state(item) for item in state.pop("messages")]
        super().set_state(state)
