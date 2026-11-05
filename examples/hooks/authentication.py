#!mitmproxy
"""Separate authentication/all/message deployment, not a content addon."""


def socks5_auth(data):
    # Only narrow the authoritative AAA result; never log credentials.
    data.valid = data.valid and data.username != "blocked"
