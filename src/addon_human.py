"""Small human-readable formatting helpers exposed to addon scripts."""

from datetime import datetime


SIZE_UNITS = {
    'b': 1,
    'k': 1024,
    'm': 1024 ** 2,
    'g': 1024 ** 3,
    't': 1024 ** 4,
}


def pretty_duration(seconds):
    if seconds is None:
        return ''
    if seconds < 1:
        return f'{round(seconds * 1000)}ms'
    if seconds < 10:
        return f'{seconds:.2f}s'
    if seconds < 100:
        return f'{seconds:.1f}s'
    return f'{seconds:.0f}s'


def pretty_size(size):
    if size < 1024:
        return f'{size}b'

    value = size / 1024
    unit = 'k'
    for candidate in ('m', 'g', 't'):
        if value < 1024:
            break
        value /= 1024
        unit = candidate

    if value < 100:
        return f'{value:.1f}{unit}'
    return f'{value:.0f}{unit}'


def parse_size(size):
    """Parse an integer byte count with an optional binary unit suffix."""
    if size is None:
        return None
    if isinstance(size, (int, float)):
        return int(size)

    factor = 1
    for suffix, candidate in SIZE_UNITS.items():
        if suffix != 'b' and size.endswith(suffix):
            factor = candidate
            size = size[:-1]
            break
    else:
        if size.endswith('b'):
            size = size[:-1]

    try:
        return int(size) * factor
    except ValueError as error:
        raise ValueError('Invalid size specification.') from error


def format_address(address):
    """Format a host/port pair without confusing IPv6 colons for a port."""
    if address is None:
        return '<no address>'
    host, port = address[:2]
    if ':' in host:
        host = '[' + host + ']'
    return f'{host}:{port}'


def format_timestamp(seconds=None):
    timestamp = datetime.now() if seconds is None else datetime.fromtimestamp(seconds)
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')


def format_timestamp_with_milli(seconds):
    timestamp = datetime.fromtimestamp(seconds)
    return timestamp.strftime('%Y-%m-%d %H:%M:%S.') + f'{timestamp.microsecond // 1000:03d}'
