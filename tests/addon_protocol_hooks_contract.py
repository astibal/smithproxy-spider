"""Shared black-box observations for non-HTTP protocol hook values."""

import dataclasses


def _inspect_hook(hook_type, flow):
    hook = hook_type(flow)
    return {
        "name": hook.name,
        "blocking": hook.blocking,
        "argument_identity": hook.args()[0] is flow,
        "equal_other": hook == hook_type(flow),
        "fields": [field.name for field in dataclasses.fields(hook)],
        "module": hook_type.__module__,
    }


def collect(websocket_hooks, dns_hooks, tcp_hooks, udp_hooks,
            http, dns, tcp, udp, connection):
    client = connection.Client(
        peername=("192.0.2.10", 41000),
        sockname=("192.0.2.1", 443),
        id="client-1",
    )
    server = connection.Server(
        address=("example.test", 443),
        id="server-1",
    )

    flows = {
        "websocket": http.HTTPFlow(client, server, live=True),
        "dns": dns.DNSFlow(client, server, live=True),
        "tcp": tcp.TCPFlow(client, server, live=True),
        "udp": udp.UDPFlow(client, server, live=True),
    }
    hook_types = {
        "websocket": (
            websocket_hooks.WebsocketStartHook,
            websocket_hooks.WebsocketMessageHook,
            websocket_hooks.WebsocketEndHook,
        ),
        "dns": (
            dns_hooks.DnsRequestHook,
            dns_hooks.DnsResponseHook,
            dns_hooks.DnsErrorHook,
        ),
        "tcp": (
            tcp_hooks.TcpStartHook,
            tcp_hooks.TcpMessageHook,
            tcp_hooks.TcpEndHook,
            tcp_hooks.TcpErrorHook,
        ),
        "udp": (
            udp_hooks.UdpStartHook,
            udp_hooks.UdpMessageHook,
            udp_hooks.UdpEndHook,
            udp_hooks.UdpErrorHook,
        ),
    }

    result = {}
    for protocol, types in hook_types.items():
        result[protocol] = {
            hook_type.__name__: _inspect_hook(hook_type, flows[protocol])
            for hook_type in types
        }
    return result
