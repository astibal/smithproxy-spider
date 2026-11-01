"""Public QUIC TLS hook values without a QUIC transport implementation."""

from dataclasses import dataclass, field

from addon_hooks import Hook
from addon_tls import TlsData


@dataclass
class QuicTlsSettings:
    alpn_protocols: list[str] | None = None
    certificate: object | None = None
    certificate_chain: list[object] = field(default_factory=list)
    certificate_private_key: object | None = None
    cipher_suites: list[object] | None = None
    ca_path: str | None = None
    ca_file: str | None = None
    verify_mode: object | None = None


@dataclass
class QuicTlsData(TlsData):
    settings: QuicTlsSettings | None = None


@dataclass(eq=False)
class QuicStartClientHook(Hook):
    data: QuicTlsData
    blocking = True


@dataclass(eq=False)
class QuicStartServerHook(Hook):
    data: QuicTlsData
    blocking = True


QuicTlsSettings.__module__ = "mitmproxy.proxy.layers.quic._hooks"
QuicTlsData.__module__ = "mitmproxy.proxy.layers.quic._hooks"
QuicStartClientHook.__module__ = "mitmproxy.proxy.layers.quic._hooks"
QuicStartServerHook.__module__ = "mitmproxy.proxy.layers.quic._hooks"
