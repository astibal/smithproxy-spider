"""Addon connection descriptors, deliberately independent of socket ownership.

These are data objects. Assigning an address never opens a socket or redirects
Spider traffic. The native adapter must separately authorize transport changes.
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError, dataclass, field, fields
from enum import Flag
from functools import lru_cache
import ipaddress
import re
import time
from typing import Literal
import uuid
import warnings

from addon_serializable import Serializable, SerializableDataclass


Address = tuple[str, int]
TransportProtocol = Literal['tcp', 'udp']
TlsVersion = Literal[
    'SSLv3', 'TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3',
    'DTLSv0.9', 'DTLSv1', 'DTLSv1.2', 'QUICv1',
]
ServerSpec = tuple[Literal[
    "http", "https", "http3", "tls", "dtls", "tcp", "udp", "dns", "quic"
], tuple[str, int]]

_SERVER_SCHEMES = frozenset({"http", "https", "http3", "tls", "dtls", "tcp", "udp", "dns", "quic"})
_SERVER_DEFAULT_PORTS = {"http": 80, "https": 443, "http3": 443, "dns": 53, "quic": 443}
_SERVER_SPEC = re.compile(
    r"^(?:(?P<scheme>\w+)://)?"
    r"(?P<host>\[[^\]]+\]|[^:/]+)"
    r"(?::(?P<port>[0-9]+))?/?$"
)
_HOST_LABEL = re.compile(rb"[A-Za-z0-9_-]{1,63}$")


def _valid_hostname(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    try:
        encoded = host.encode("idna")
    except UnicodeError:
        return False
    return bool(encoded) and len(encoded) <= 255 and all(
        _HOST_LABEL.fullmatch(label) for label in encoded.rstrip(b".").split(b".")
    )


@lru_cache(maxsize=1024)
def parse_server_spec(server_spec: str, default_scheme: str) -> ServerSpec:
    if not isinstance(server_spec, str) or not isinstance(default_scheme, str):
        raise TypeError("Server specification and default scheme must be text")
    # The public parser accepts the conventional single trailing slash. Its
    # historical regular-expression boundary also accepts one final newline;
    # preserve that observable behavior for existing configuration files.
    match = _SERVER_SPEC.match(server_spec)
    if match is None:
        raise ValueError("Invalid server specification: " + server_spec)
    scheme = match.group("scheme") or default_scheme
    if scheme not in _SERVER_SCHEMES:
        raise ValueError("Invalid server scheme: " + scheme)
    host = match.group("host")
    if host.startswith("["):
        host = host[1:-1]
    if not _valid_hostname(host):
        raise ValueError("Invalid hostname: " + host)
    port_text = match.group("port")
    if port_text is None:
        port = _SERVER_DEFAULT_PORTS.get(scheme)
        if port is None:
            raise ValueError("Port specification missing.")
    else:
        port = int(port_text)
        if port > 65535:
            raise ValueError("Invalid port: " + port_text)
    return scheme, (host, port)


class ConnectionState(Flag):
    CLOSED = 0
    CAN_READ = 1
    CAN_WRITE = 2
    OPEN = CAN_READ | CAN_WRITE


@dataclass(frozen=True, repr=False)
class ProxyMode(Serializable):
    """Immutable proxy-mode descriptor without executable transport behavior."""

    full_spec: str
    data: str
    custom_listen_host: str | None
    custom_listen_port: int | None

    type_name = None
    description = None
    transport_protocol = None
    default_port = None

    @classmethod
    @lru_cache(maxsize=128)
    def parse(cls, spec):
        if not isinstance(spec, str):
            raise TypeError("Proxy mode specification must be text")
        mode_spec, separator, listen_spec = spec.rpartition("@")
        if not separator:
            mode_spec = spec
            listen_spec = ""
        mode_name, data_separator, data = mode_spec.partition(":")
        if not data_separator:
            data = ""
        mode_class = _PROXY_MODES.get(mode_name)
        if mode_class is None:
            raise ValueError("unknown mode")
        host, port = _parse_listen_spec(listen_spec)
        return mode_class(spec, data, host, port)

    @classmethod
    def from_state(cls, state):
        return cls.parse(state)

    def listen_host(self, default=None):
        if self.custom_listen_host is not None:
            return self.custom_listen_host
        return default if default is not None else ""

    def listen_port(self, default=None):
        if self.custom_listen_port is not None:
            return self.custom_listen_port
        if self.default_port is None:
            return None
        return self.default_port if default is None else default

    def get_state(self):
        return self.full_spec

    def set_state(self, state):
        if state == self.full_spec:
            return None
        raise FrozenInstanceError("Proxy modes are immutable.")

    def copy(self):
        return self

    def __repr__(self):
        return f"ProxyMode.parse({self.full_spec!r})"


class _NoArgumentsMode(ProxyMode):
    def __post_init__(self):
        if self.data:
            raise ValueError("mode takes no arguments")


@dataclass(frozen=True, repr=False)
class RegularMode(_NoArgumentsMode):
    type_name = "regular"
    description = "HTTP(S) proxy"
    transport_protocol = "tcp"
    default_port = 8080


@dataclass(frozen=True, repr=False)
class TransparentMode(_NoArgumentsMode):
    type_name = "transparent"
    description = "Transparent Proxy"
    transport_protocol = "tcp"
    default_port = 8080


@dataclass(frozen=True, repr=False)
class Socks5Mode(_NoArgumentsMode):
    type_name = "socks5"
    description = "SOCKS v5 proxy"
    transport_protocol = "tcp"
    default_port = 1080


@dataclass(frozen=True, repr=False)
class DnsMode(_NoArgumentsMode):
    type_name = "dns"
    description = "DNS server"
    transport_protocol = "both"
    default_port = 53


@dataclass(frozen=True, repr=False)
class ReverseMode(ProxyMode):
    type_name = "reverse"
    transport_protocol = "both"
    default_port = 8080

    def __post_init__(self):
        _validate_server_spec(self.data, {"http", "https", "tcp", "tls", "udp", "dns", "quic", "http3"})
        scheme = self.data.partition("://")[0]
        object.__setattr__(self, "transport_protocol",
                           "tcp" if scheme in ("tcp", "tls", "http") else
                           "udp" if scheme in ("udp", "quic", "http3") else "both")
        if scheme == "dns":
            object.__setattr__(self, "default_port", 53)

    @property
    def description(self):
        return "reverse proxy to " + self.data


@dataclass(frozen=True, repr=False)
class UpstreamMode(ProxyMode):
    type_name = "upstream"
    description = "HTTP(S) proxy (upstream mode)"
    transport_protocol = "tcp"
    default_port = 8080

    def __post_init__(self):
        _validate_server_spec(self.data, {"http", "https"})


@dataclass(frozen=True, repr=False)
class WireGuardMode(ProxyMode):
    type_name = "wireguard"
    description = "WireGuard server"
    transport_protocol = "udp"
    default_port = 51820


@dataclass(frozen=True, repr=False)
class LocalMode(ProxyMode):
    type_name = "local"
    description = "Local redirector"
    transport_protocol = "both"
    default_port = None


@dataclass(frozen=True, repr=False)
class TunMode(ProxyMode):
    type_name = "tun"
    description = "TUN interface"
    transport_protocol = "both"
    default_port = None


class OsProxyMode(ProxyMode):
    def __new__(cls, *args, **kwargs):
        raise ValueError("osproxy mode has been renamed to local mode. "
                         "Thanks for trying our experimental features!")


def _parse_listen_spec(value):
    if not value:
        return None, None
    if value.isdecimal():
        return None, int(value)
    host, separator, port_text = value.rpartition(":")
    if not separator:
        return value, None
    try:
        port = int(port_text)
    except ValueError as error:
        raise ValueError("invalid port: " + port_text) from error
    return host, port


def _validate_server_spec(value, schemes):
    if "://" not in value:
        raise ValueError("Invalid server specification: " + value)
    try:
        scheme, _ = parse_server_spec(value, "tcp")
    except ValueError as error:
        raise ValueError("Invalid server specification: " + value) from error
    if scheme not in schemes:
        raise ValueError("Invalid server specification: " + value)


_PROXY_MODES = {
    "regular": RegularMode,
    "transparent": TransparentMode,
    "socks5": Socks5Mode,
    "reverse": ReverseMode,
    "upstream": UpstreamMode,
    "wireguard": WireGuardMode,
    "local": LocalMode,
    "tun": TunMode,
    "dns": DnsMode,
    "osproxy": OsProxyMode,
}


@lru_cache(maxsize=1)
def _default_regular_mode():
    # Parsed immutable mode values are shared; connection objects are not.
    return ProxyMode.parse("regular")


def _state_value(name, value, expected, *, optional=False):
    if value is None and optional:
        return None
    valid = isinstance(value, expected)
    if expected is float:
        valid = isinstance(value, (int, float))
    if not valid:
        raise ValueError(f"Invalid value for {name}. Expected {expected}, "
                         f"got {value} ({type(value)}).")
    return float(value) if expected is float else value


def _state_address(name, address):
    if address is None:
        return None
    # The public state schema treats an address as a variable-length tuple:
    # the first item is text and every remaining item is an integer. This is
    # observable for Unix-domain and extended address values, even though the
    # usual TCP form remains ``(host, port)``.
    validated = []
    for index, item in enumerate(address):
        expected = str if index == 0 else int
        validated.append(_state_value(name, item, expected))
    return tuple(validated)


def _serialize_field(name, value):
    """The small connection schema is independent of live transport state."""
    if name in ("peername", "sockname", "address"):
        return _state_address(name, value)
    if name.startswith("timestamp_"):
        return _state_value(name, value, float, optional=True)
    if name == "id":
        return _state_value(name, value, str)
    if name == "transport_protocol":
        if value not in ("tcp", "udp"):
            raise ValueError(
                f"Invalid value for transport_protocol: {value!r} "
                "does not match any literal value."
            )
        return value
    if name == "tls":
        return _state_value(name, value, bool)
    if name in ("error", "cipher", "tls_version", "sni"):
        return _state_value(name, value, str, optional=True)
    if name == "alpn":
        return _state_value(name, value, bytes, optional=True)
    if name in ("alpn_offers", "cipher_list"):
        expected = bytes if name == "alpn_offers" else str
        return [_state_value(name, item, expected) for item in value]
    if name == "certificate_list":
        return [item.get_state() for item in value]
    if name in ("mitmcert", "proxy_mode"):
        return None if value is None else value.get_state()
    if name == "via":
        if value is None:
            return None
        protocol, address = value
        return _state_value(name, protocol, str), _state_address(name, address)
    raise ValueError(f"Unknown connection field: {name}")


def _deserialize_field(name, value):
    if name in ("alpn_offers", "cipher_list"):
        validated = _serialize_field(name, value)
        if isinstance(value, list):
            value[:] = validated
            return value
        return validated
    if name in ("certificate_list", "mitmcert"):
        # Certificate parsing is needed only when loading certificate state.
        from addon_certs import Cert

        if name == "certificate_list":
            return [Cert.from_state(item) for item in value]
        return None if value is None else Cert.from_state(value)
    if name == "proxy_mode":
        return ProxyMode.parse(value)
    return _serialize_field(name, value)


@dataclass(eq=False, kw_only=True)
class Connection(SerializableDataclass):
    peername: tuple | None
    sockname: tuple | None
    state: ConnectionState = ConnectionState.CLOSED
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    transport_protocol: str = "tcp"
    error: str | None = None
    tls: bool = False
    certificate_list: tuple = ()
    alpn: bytes | None = None
    alpn_offers: tuple = ()
    cipher: str | None = None
    cipher_list: tuple = ()
    tls_version: str | None = None
    sni: str | None = None
    timestamp_start: float | None = None
    timestamp_end: float | None = None
    timestamp_tls_setup: float | None = None

    @property
    def connected(self):
        return self.state == ConnectionState.OPEN

    @property
    def tls_established(self):
        return self.timestamp_tls_setup is not None

    @property
    def alpn_proto_negotiated(self):
        warnings.warn("Connection.alpn_proto_negotiated is deprecated, "
                      "use Connection.alpn instead.", DeprecationWarning, stacklevel=2)
        return self.alpn

    def __eq__(self, other):
        if not isinstance(other, Connection):
            return NotImplemented
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)

    def get_state(self):
        # Socket readiness is intentionally not serialized. A saved descriptor
        # describes an observation, not a socket that can be reopened by loading.
        result = {}
        for member in fields(self):
            if member.name != "state":
                result[member.name] = _serialize_field(member.name, getattr(self, member.name))
        return result

    @classmethod
    def from_state(cls, state):
        for member in fields(cls):
            if member.name != "state":
                state[member.name] = _deserialize_field(member.name, state[member.name])
        extra = set(state) - {member.name for member in fields(cls)}
        if extra:
            raise ValueError(f"Unexpected connection fields: {sorted(extra)}")
        return cls(**state)

    def set_state(self, state):
        # Loading observations must not reopen a socket or bypass the live
        # server destination guard in __setattr__.
        for member in fields(self):
            if member.name != "state":
                value = state.pop(member.name)
                setattr(self, member.name, _deserialize_field(member.name, value))
        if state:
            raise ValueError(f"Unexpected fields in {type(self).__name__}.set_state: {state}")

    def copy(self):
        result = deepcopy(self)
        result.id = str(uuid.uuid4())
        result.state = ConnectionState.CLOSED
        return result


@dataclass(eq=False, kw_only=True)
class Client(Connection):
    timestamp_start: float = field(default_factory=time.time)
    mitmcert: object | None = None
    # Proxy modes are immutable and cached. Sharing this default matches the
    # public class attribute without sharing any live connection state.
    proxy_mode: ProxyMode = _default_regular_mode()

    def get_state(self):
        for name in ("peername", "sockname"):
            if getattr(self, name) is None:
                raise ValueError(f"Attribute {name} must not be None.")
        _state_value("timestamp_start", self.timestamp_start, float)
        if self.proxy_mode is None:
            raise ValueError("Attribute proxy_mode must not be None.")
        return super().get_state()

    @property
    def address(self):
        warnings.warn("Client.address is deprecated, use Client.peername instead.",
                      DeprecationWarning, stacklevel=2)
        return self.peername

    @address.setter
    def address(self, value):
        warnings.warn("Client.address is deprecated, use Client.peername instead.",
                      DeprecationWarning, stacklevel=2)
        self.peername = value

    @property
    def cipher_name(self):
        warnings.warn("Client.cipher_name is deprecated, use Client.cipher instead.",
                      DeprecationWarning, stacklevel=2)
        return self.cipher

    @property
    def clientcert(self):
        warnings.warn("Client.clientcert is deprecated, use Client.certificate_list instead.",
                      DeprecationWarning, stacklevel=2)
        return self.certificate_list[0] if self.certificate_list else None

    @clientcert.setter
    def clientcert(self, value):
        warnings.warn("Client.clientcert is deprecated, use Client.certificate_list instead.",
                      DeprecationWarning, stacklevel=2)
        self.certificate_list = [] if value is None else [value]


@dataclass(eq=False, kw_only=True)
class Server(Connection):
    peername: tuple | None = None
    sockname: tuple | None = None
    address: tuple | None
    timestamp_tcp_setup: float | None = None
    via: tuple | None = None

    @property
    def ip_address(self):
        warnings.warn("Server.ip_address is deprecated, use Server.peername instead.",
                      DeprecationWarning, stacklevel=2)
        return self.peername

    @property
    def cert(self):
        warnings.warn("Server.cert is deprecated, use Server.certificate_list instead.",
                      DeprecationWarning, stacklevel=2)
        return self.certificate_list[0] if self.certificate_list else None

    @cert.setter
    def cert(self, value):
        warnings.warn("Server.cert is deprecated, use Server.certificate_list instead.",
                      DeprecationWarning, stacklevel=2)
        self.certificate_list = [] if value is None else [value]

    def __setattr__(self, name, value):
        if name in ("address", "via"):
            if self.connected and getattr(self, name, None) != value:
                raise RuntimeError(f"Cannot change server.{name} on open connection.")
        super().__setattr__(name, value)
