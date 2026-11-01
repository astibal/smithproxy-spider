"""Public SOCKS5 authentication values without transport ownership."""

from __future__ import annotations

from dataclasses import dataclass

import addon_connection as connection
from addon_hooks import Hook


@dataclass
class Socks5AuthData:
    """Credentials presented by a SOCKS5 client and the addon decision."""

    client_conn: connection.Client
    username: str
    password: str
    valid: bool = False


@dataclass(eq=False)
class Socks5AuthHook(Hook):
    """Deliver one authentication decision to an addon hook."""

    data: Socks5AuthData


Socks5AuthData.__module__ = "mitmproxy.proxy.layers.modes"
Socks5AuthHook.__module__ = "mitmproxy.proxy.layers.modes"
