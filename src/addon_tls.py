"""Clean-room public TLS values for the addon compatibility facade."""

from __future__ import annotations

from dataclasses import dataclass

import addon_connection as connection
from addon_hooks import Hook
from addon_proxy_context import Context


from inspection_tls_hello import EndOfStreamError, ParsedClientHello


class ClientHello(ParsedClientHello):
    """Compatibility name for the shared protocol value."""


@dataclass
class ClientHelloData:
    """Event data for a TLS ClientHello callback."""

    context: Context
    client_hello: ClientHello
    ignore_connection: bool = False
    establish_server_tls_first: bool = False


@dataclass
class TlsData:
    """Event data for TLS start and handshake callbacks."""

    conn: connection.Connection
    context: Context
    ssl_conn: object | None = None
    is_dtls: bool = False


@dataclass(eq=False)
class TlsClienthelloHook(Hook):
    data: ClientHelloData
    name = "tls_clienthello"
    blocking = True


@dataclass(eq=False)
class TlsStartClientHook(Hook):
    data: TlsData
    name = "tls_start_client"
    blocking = True


@dataclass(eq=False)
class TlsStartServerHook(Hook):
    data: TlsData
    name = "tls_start_server"
    blocking = True


@dataclass(eq=False)
class TlsEstablishedClientHook(Hook):
    data: TlsData
    name = "tls_established_client"
    blocking = True


@dataclass(eq=False)
class TlsEstablishedServerHook(Hook):
    data: TlsData
    name = "tls_established_server"
    blocking = True


@dataclass(eq=False)
class TlsFailedClientHook(Hook):
    data: TlsData
    name = "tls_failed_client"
    blocking = True


@dataclass(eq=False)
class TlsFailedServerHook(Hook):
    data: TlsData
    name = "tls_failed_server"
    blocking = True


ClientHello.__module__ = "mitmproxy.tls"
ClientHelloData.__module__ = "mitmproxy.tls"
TlsData.__module__ = "mitmproxy.tls"

for _hook in (
    TlsClienthelloHook,
    TlsStartClientHook,
    TlsStartServerHook,
    TlsEstablishedClientHook,
    TlsEstablishedServerHook,
    TlsFailedClientHook,
    TlsFailedServerHook,
):
    _hook.__module__ = "mitmproxy.proxy.layers.tls"
