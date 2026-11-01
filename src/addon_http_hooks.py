"""Public HTTP hook values without protocol-layer ownership."""

from dataclasses import dataclass

from addon_flow import HTTPFlow
from addon_hooks import Hook


@dataclass(eq=False)
class HttpConnectHook(Hook):
    flow: HTTPFlow
    name = "http_connect"
    blocking = True


@dataclass(eq=False)
class HttpConnectErrorHook(Hook):
    flow: HTTPFlow
    name = "http_connect_error"
    blocking = True


@dataclass(eq=False)
class HttpConnectUpstreamHook(Hook):
    flow: HTTPFlow
    name = "http_connect_upstream"
    blocking = True


@dataclass(eq=False)
class HttpConnectedHook(Hook):
    flow: HTTPFlow
    name = "http_connected"
    blocking = True


@dataclass(eq=False)
class HttpRequestHeadersHook(Hook):
    flow: HTTPFlow
    name = "requestheaders"
    blocking = True


@dataclass(eq=False)
class HttpRequestHook(Hook):
    flow: HTTPFlow
    name = "request"
    blocking = True


@dataclass(eq=False)
class HttpResponseHeadersHook(Hook):
    flow: HTTPFlow
    name = "responseheaders"
    blocking = True


@dataclass(eq=False)
class HttpResponseHook(Hook):
    flow: HTTPFlow
    name = "response"
    blocking = True


@dataclass(eq=False)
class HttpErrorHook(Hook):
    flow: HTTPFlow
    name = "error"
    blocking = True


for _hook in (
    HttpConnectHook,
    HttpConnectErrorHook,
    HttpConnectUpstreamHook,
    HttpConnectedHook,
    HttpRequestHeadersHook,
    HttpRequestHook,
    HttpResponseHeadersHook,
    HttpResponseHook,
    HttpErrorHook,
):
    _hook.__module__ = "mitmproxy.proxy.layers.http._hooks"
