"""Detached public proxy context used by addon event data."""

from addon_connection import Client, Server


class Context:
    """Keep connection descriptors and options for one protocol-layer chain."""

    def __init__(self, client: Client, options):
        self.client = client
        self.options = options
        self.server = Server(address=None)
        self.layers = []

    def fork(self):
        """Return a branch with shared endpoints and an independent layer list."""
        forked = object.__new__(type(self))
        forked.client = self.client
        forked.options = self.options
        forked.server = self.server
        forked.layers = self.layers.copy()
        return forked


Context.__module__ = "mitmproxy.proxy.context"
