"""Public protocol hook values without adding transport implementations."""

from dataclasses import dataclass

from addon_dns import DNSFlow
from addon_flow import HTTPFlow, TCPFlow, UDPFlow
from addon_hooks import Hook


@dataclass(eq=False)
class WebsocketStartHook(Hook):
    flow: HTTPFlow
    name = "websocket_start"
    blocking = True


@dataclass(eq=False)
class WebsocketMessageHook(Hook):
    flow: HTTPFlow
    name = "websocket_message"
    blocking = True


@dataclass(eq=False)
class WebsocketEndHook(Hook):
    flow: HTTPFlow
    name = "websocket_end"
    blocking = True


@dataclass(eq=False)
class DnsRequestHook(Hook):
    flow: DNSFlow
    name = "dns_request"
    blocking = True


@dataclass(eq=False)
class DnsResponseHook(Hook):
    flow: DNSFlow
    name = "dns_response"
    blocking = True


@dataclass(eq=False)
class DnsErrorHook(Hook):
    flow: DNSFlow
    name = "dns_error"
    blocking = True


@dataclass(eq=False)
class TcpStartHook(Hook):
    flow: TCPFlow
    name = "tcp_start"
    blocking = True


@dataclass(eq=False)
class TcpMessageHook(Hook):
    flow: TCPFlow
    name = "tcp_message"
    blocking = True


@dataclass(eq=False)
class TcpEndHook(Hook):
    flow: TCPFlow
    name = "tcp_end"
    blocking = True


@dataclass(eq=False)
class TcpErrorHook(Hook):
    flow: TCPFlow
    name = "tcp_error"
    blocking = True


@dataclass(eq=False)
class UdpStartHook(Hook):
    flow: UDPFlow
    name = "udp_start"
    blocking = True


@dataclass(eq=False)
class UdpMessageHook(Hook):
    flow: UDPFlow
    name = "udp_message"
    blocking = True


@dataclass(eq=False)
class UdpEndHook(Hook):
    flow: UDPFlow
    name = "udp_end"
    blocking = True


@dataclass(eq=False)
class UdpErrorHook(Hook):
    flow: UDPFlow
    name = "udp_error"
    blocking = True


_MODULE_CLASSES = {
    "mitmproxy.proxy.layers.websocket": (
        WebsocketStartHook,
        WebsocketMessageHook,
        WebsocketEndHook,
    ),
    "mitmproxy.proxy.layers.dns": (
        DnsRequestHook,
        DnsResponseHook,
        DnsErrorHook,
    ),
    "mitmproxy.proxy.layers.tcp": (
        TcpStartHook,
        TcpMessageHook,
        TcpEndHook,
        TcpErrorHook,
    ),
    "mitmproxy.proxy.layers.udp": (
        UdpStartHook,
        UdpMessageHook,
        UdpEndHook,
        UdpErrorHook,
    ),
}

for _module_name, _classes in _MODULE_CLASSES.items():
    for _hook in _classes:
        _hook.__module__ = _module_name
