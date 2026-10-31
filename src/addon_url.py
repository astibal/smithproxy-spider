"""Public URL helpers for addon scripts, without transport side effects."""

import ipaddress
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from addon_strutils import always_str


_DEFAULT_PORTS = {
    'http': 80,
    'https': 443,
    b'http': 80,
    b'https': 443,
}


def default_port(scheme):
    return _DEFAULT_PORTS.get(scheme)


def hostport(scheme, host, port):
    if port == default_port(scheme):
        return host
    separator = b':' if isinstance(host, bytes) else ':'
    suffix = str(port).encode() if isinstance(host, bytes) else str(port)
    return host + separator + suffix


def is_valid_port(port):
    return 0 <= port <= 65535


def is_valid_host(host):
    # The public helper accepts Unicode presentation names, but bytes are an
    # already encoded DNS name. Calling decode on other input types also
    # preserves the reference contract's useful type error.
    if isinstance(host, str):
        try:
            host = host.encode('idna').decode('ascii')
        except UnicodeError:
            return False
    else:
        try:
            host = host.decode('idna')
        except UnicodeError:
            return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    if len(host) > 255 or host.endswith('..'):
        return False
    labels = host[:-1].split('.') if host.endswith('.') else host.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not re.fullmatch(r'[A-Za-z0-9_-]+', label):
            return False
    return True


def parse_authority(authority, check):
    authority = always_str(authority)
    host = authority
    port = None

    bracketed = re.fullmatch(r'\[([^]]+)](?::([0-9]+))?', authority)
    ordinary = re.fullmatch(r'([^:@]+)(?::([0-9]+))?', authority)
    match = bracketed or ordinary
    accepted = False
    if match is not None:
        candidate_host = match.group(1)
        candidate_port = None
        if match.group(2) is not None:
            candidate_port = int(match.group(2))

        valid = is_valid_host(candidate_host)
        if candidate_port is not None:
            valid = valid and is_valid_port(candidate_port)
        if valid:
            host = candidate_host
            port = candidate_port
            accepted = True

    if check and not accepted:
        raise ValueError()
    return host, port


def parse(url):
    wire_url = url.encode() if isinstance(url, str) else url
    parsed = urlsplit(wire_url)
    if parsed.hostname is None:
        raise ValueError('No hostname given')

    try:
        port = parsed.port
    except ValueError:
        raise
    if port is None:
        port = default_port(parsed.scheme) or 80

    path = urlunsplit(
        (b'', b'', parsed.path or b'/', parsed.query, parsed.fragment)
    )
    return (
        parsed.scheme,
        parsed.hostname,
        port,
        path,
    )


def unparse(scheme, host, port, path):
    separator = b'://' if isinstance(scheme, bytes) else '://'
    return scheme + separator + hostport(scheme, host, port) + path


def decode(value):
    return parse_qsl(value, keep_blank_values=True)


def encode(fields, similar_to=None):
    del similar_to
    return urlencode(fields)


__all__ = (
    'always_str', 'decode', 'default_port', 'encode', 'hostport',
    'is_valid_host', 'is_valid_port', 'parse', 'parse_authority',
    'quote', 'unparse', 'unquote',
)
