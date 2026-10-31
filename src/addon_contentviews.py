"""Generation-local custom content views for the addon compatibility facade.

The public types mirror the documented mitmproxy 12 addon contract.  The
registry deliberately contains only views registered by the loaded addon;
Spider keeps ownership of its built-in payload renderers.
"""

from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from addon_signals import SyncSignal


SyntaxHighlight = Literal["css", "javascript", "xml", "yaml", "none", "error"]
SYNTAX_HIGHLIGHTS = frozenset(("css", "javascript", "xml", "yaml", "none", "error"))


@dataclass
class Metadata:
    """Metadata available while a registered view handles one payload."""

    flow: object | None = None
    content_type: str | None = None
    http_message: object | None = None
    tcp_message: object | None = None
    udp_message: object | None = None
    websocket_message: object | None = None
    dns_message: object | None = None
    protobuf_definitions: Path | None = None
    original_data: bytes | None = None


@dataclass
class ContentviewResult:
    """Rendered text and presentation metadata returned by a content view."""

    text: str
    syntax_highlight: SyntaxHighlight
    view_name: str | None
    description: str


@runtime_checkable
class Contentview(Protocol):
    """A custom formatter for one binary payload."""

    @property
    def name(self) -> str:
        return type(self).__name__.removesuffix("Contentview")

    @property
    def syntax_highlight(self) -> SyntaxHighlight:
        return "none"

    @abstractmethod
    def prettify(self, data: bytes, metadata: Metadata) -> str:
        """Return a human-readable representation of *data*."""

    def render_priority(self, data: bytes, metadata: Metadata) -> float:
        return 0

    def __lt__(self, other):
        return self.name < other.name


@runtime_checkable
class InteractiveContentview(Contentview, Protocol):
    """A content view that can turn an edited representation back into bytes."""

    @abstractmethod
    def reencode(self, prettified: str, metadata: Metadata) -> bytes:
        """Encode edited text using the view's original binary format."""


class ContentviewRegistry:
    """Small generation-owned mapping used by both the facade and Spider UI."""

    def __init__(self):
        self._views = {}
        self.on_change = SyncSignal(lambda contentview: None)

    def register(self, contentview):
        instance = contentview() if isinstance(contentview, type) else contentview
        # Accessing name before publication intentionally preserves the public
        # failure boundary for objects that do not implement the protocol.
        key = instance.name.lower()
        self._views[key] = instance
        self.on_change.send(instance)

    def get(self, key, default=None):
        if not isinstance(key, str):
            return default
        return self._views.get(key.lower(), default)

    def __getitem__(self, key):
        return self._views[key.lower()]

    def keys(self):
        return self._views.keys()

    def values(self):
        return self._views.values()

    def items(self):
        return self._views.items()

    def available_views(self):
        return sorted(self._views)

    def get_view(self, data, metadata, view_name="auto"):
        if view_name != "auto":
            requested = self.get(view_name)
            if requested is not None:
                return requested

        selected = None
        selected_priority = float("-inf")
        for view in self._views.values():
            try:
                priority = view.render_priority(data, metadata)
                if not isinstance(priority, (int, float)):
                    continue
            except Exception:
                continue
            if priority > selected_priority:
                selected = view
                selected_priority = priority
        return selected


def create_contentviews():
    """Return one isolated registry and its public registration function."""
    registry = ContentviewRegistry()

    def add(contentview):
        registry.register(contentview)

    return registry, add


def get_data(message):
    """Return the bytes rendered by a content view and their wire annotation."""
    from addon_dns import DNSMessage
    from addon_http_message import Message

    if isinstance(message, DNSMessage):
        return message.packed, ""
    if isinstance(message, Message):
        encoding = message.headers.get("content-encoding", "")
        try:
            content = message.content
        except ValueError:
            return message.raw_content, "[cannot decode]"
        annotation = "[decoded " + encoding + "]" if encoding else ""
        return content, annotation
    return message.content, ""


def make_metadata(message, flow, protobuf_definitions=None):
    """Build content-view metadata without retaining a global proxy context."""
    from addon_dns import DNSMessage
    from addon_flow import TCPMessage, UDPMessage
    from addon_http_message import Message
    from addon_websocket import WebSocketMessage

    metadata = Metadata(
        flow=flow,
        protobuf_definitions=(
            None if protobuf_definitions is None
            else Path(protobuf_definitions)
        ),
    )
    if isinstance(message, Message):
        metadata.content_type = message.headers.get("content-type")
        metadata.http_message = message
    elif isinstance(message, TCPMessage):
        metadata.tcp_message = message
    elif isinstance(message, UDPMessage):
        metadata.udp_message = message
    elif isinstance(message, WebSocketMessage):
        metadata.websocket_message = message
    elif isinstance(message, DNSMessage):
        metadata.dns_message = message
    else:
        raise AssertionError(
            "Expected code to be unreachable, but got: " + repr(message))
    return metadata


def prettify_message(message, flow, view_name="auto", *, registry,
                      protobuf_definitions=None):
    """Render one public message with a generation-owned registry."""
    data, description = get_data(message)
    if data is None:
        return ContentviewResult(
            "Content is missing.", "error", None, description)

    metadata = make_metadata(message, flow, protobuf_definitions)
    view = registry.get_view(data, metadata, view_name)
    if view is None:
        return ContentviewResult(
            "No content view is available.", "error", None, description)
    return ContentviewResult(
        view.prettify(data, metadata),
        view.syntax_highlight,
        view.name,
        description,
    )


def reencode_message(prettified, message, flow, view_name, *, registry,
                     protobuf_definitions=None):
    """Reencode edited content through one explicitly selected view."""
    view = registry[view_name]
    if not isinstance(view, InteractiveContentview):
        raise ValueError("Contentview " + view.name + " is not interactive.")
    metadata = make_metadata(message, flow, protobuf_definitions)
    return view.reencode(prettified, metadata)


def describe_registered(registry):
    """Describe custom views without exposing worker-owned Python objects."""
    descriptions = []
    for key, view in sorted(registry.items()):
        name = view.name
        syntax = view.syntax_highlight
        if not isinstance(name, str) or not name or len(name) > 256:
            raise ValueError("Content view names must be 1 to 256 characters")
        if syntax not in SYNTAX_HIGHLIGHTS:
            raise ValueError("Unsupported content view syntax highlight: " + str(syntax))
        descriptions.append({
            "key": key,
            "name": name,
            "syntax_highlight": syntax,
            "interactive": isinstance(view, InteractiveContentview),
        })
    return descriptions


def render_registered(registry, data, content_type=None, view_name="auto"):
    """Render one payload through the generation-local custom-view registry."""
    metadata = Metadata(content_type=content_type, original_data=data)
    view = registry.get_view(data, metadata, view_name)
    if view is None:
        raise ValueError("No registered content view can render this payload")
    text = view.prettify(data, metadata)
    if not isinstance(text, str):
        raise TypeError("Content view prettify() must return str")
    syntax = view.syntax_highlight
    if syntax not in SYNTAX_HIGHLIGHTS:
        raise ValueError("Unsupported content view syntax highlight: " + str(syntax))
    return {
        "text": text,
        "syntax_highlight": syntax,
        "view_name": view.name,
        "interactive": isinstance(view, InteractiveContentview),
    }


def reencode_registered(registry, text, original_data, content_type, view_name):
    """Reencode edited text through one explicitly selected interactive view."""
    view = registry.get(view_name)
    if view is None:
        raise ValueError("Unknown content view: " + view_name)
    if not isinstance(view, InteractiveContentview):
        raise ValueError("Content view is not interactive: " + view.name)
    metadata = Metadata(content_type=content_type, original_data=original_data)
    encoded = view.reencode(text, metadata)
    if not isinstance(encoded, bytes):
        raise TypeError("Content view reencode() must return bytes")
    return encoded


__all__ = (
    "Contentview",
    "InteractiveContentview",
    "SyntaxHighlight",
    "add",
    "Metadata",
)
