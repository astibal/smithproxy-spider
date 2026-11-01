"""Shared strict validators for producer-owned transport envelopes."""


def exact_object(error_type, name, value, fields):
    """Require an object with exactly the documented field set."""

    if not isinstance(value, dict):
        raise error_type(name + ' must be an object')
    if set(value) != set(fields):
        raise error_type(name + ' has missing or unknown fields')
    return value


def bounded_text(error_type, name, value, maximum, *, nullable=False):
    """Validate metadata text before it reaches logs or public models."""

    if nullable and value is None:
        return None
    if not isinstance(value, str):
        suffix = ' or null' if nullable else ''
        raise error_type(name + ' must be bounded text' + suffix)
    encoded = value.encode('utf-8')
    if len(encoded) > maximum or any(
            character in value for character in ('\r', '\n', '\x00')):
        raise error_type(name + ' must be bounded text')
    return value


def network_address(error_type, name, value):
    """Return one validated optional ``(host, port)`` observation."""

    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise error_type(name + ' must be null or [host, port]')
    host, port = value
    host = bounded_text(error_type, name + ' host', host, 1024)
    if not host:
        raise error_type(name + ' host must be bounded text')
    if type(port) is not int or not 0 <= port <= 65535:
        raise error_type(name + ' port must be an integer in 0..65535')
    return host, port
