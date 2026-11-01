"""Public connection lifecycle hook values without socket ownership."""

from dataclasses import dataclass

from addon_connection import Client, Server
from addon_hooks import Hook


@dataclass
class ServerConnectionHookData:
    server: Server
    client: Client


@dataclass(eq=False)
class ClientConnectedHook(Hook):
    client: Client
    blocking = True


@dataclass(eq=False)
class ClientDisconnectedHook(Hook):
    client: Client
    blocking = True


@dataclass(eq=False)
class ServerConnectHook(Hook):
    data: ServerConnectionHookData
    blocking = True


@dataclass(eq=False)
class ServerConnectedHook(Hook):
    data: ServerConnectionHookData
    blocking = True


@dataclass(eq=False)
class ServerConnectErrorHook(Hook):
    data: ServerConnectionHookData
    blocking = True


@dataclass(eq=False)
class ServerDisconnectedHook(Hook):
    data: ServerConnectionHookData
    blocking = True


for _value in (
    ServerConnectionHookData,
    ClientConnectedHook,
    ClientDisconnectedHook,
    ServerConnectHook,
    ServerConnectedHook,
    ServerConnectErrorHook,
    ServerDisconnectedHook,
):
    _value.__module__ = "mitmproxy.proxy.server_hooks"
