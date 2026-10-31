"""Public message-header validation helpers for addon scripts."""

import re
from typing import Literal


TransferEncoding = Literal[
    'chunked',
    'compress,chunked',
    'deflate,chunked',
    'gzip,chunked',
    'compress',
    'deflate',
    'gzip',
    'identity',
]


_CONTENT_LENGTH = re.compile(rb'(?:0|[1-9][0-9]*)\Z')
_TRANSFER_ENCODINGS = frozenset({
    'chunked',
    'compress,chunked',
    'deflate,chunked',
    'gzip,chunked',
    'compress',
    'deflate',
    'gzip',
    'identity',
})


def parse_content_length(value):
    original = value
    if isinstance(value, str):
        value = value.encode('ascii')
    if _CONTENT_LENGTH.fullmatch(value) is None:
        raise ValueError(f'invalid content-length header: {original!r}')
    return int(value)


def parse_transfer_encoding(value):
    original = value
    if not value.isascii():
        raise ValueError(f'invalid transfer-encoding header: {original!r}')
    if value != value.strip():
        raise ValueError(f'unknown transfer-encoding header: {original!r}')

    if isinstance(value, bytes):
        text = value.decode('ascii')
    else:
        text = value
    normalized = ','.join(item.strip().lower() for item in text.split(','))
    if normalized not in _TRANSFER_ENCODINGS:
        raise ValueError(f'unknown transfer-encoding header: {original!r}')
    return normalized


def _raw_values(message, name):
    needle = name.lower()
    return [value for field, value in message.headers.fields if field.lower() == needle]


def validate_headers(message):
    content_lengths = _raw_values(message, b'content-length')
    transfer_encodings = _raw_values(message, b'transfer-encoding')

    if content_lengths and transfer_encodings:
        raise ValueError('message with both transfer-encoding and content-length headers')
    if len(content_lengths) > 1:
        raise ValueError(f'multiple content-length headers: {content_lengths!r}')
    if content_lengths:
        parse_content_length(content_lengths[0])

    if not transfer_encodings:
        return None
    if len(transfer_encodings) > 1:
        raise ValueError(f'multiple transfer-encoding headers: {transfer_encodings!r}')

    transfer_encoding = transfer_encodings[0]
    if message.http_version != 'HTTP/1.1':
        raise ValueError(
            f'unexpected HTTP transfer-encoding {transfer_encoding!r} '
            f'for {message.http_version}'
        )

    parsed = parse_transfer_encoding(transfer_encoding)
    if hasattr(message, 'method'):
        if not parsed.endswith('chunked'):
            raise ValueError(
                f"unexpected HTTP transfer-encoding {parsed!r} for request"
            )
        return None

    status_code = message.status_code
    if 100 <= status_code < 200 or status_code == 204:
        raise ValueError(
            f'unexpected HTTP transfer-encoding {transfer_encoding!r} '
            f'for response with status code {status_code}'
        )
    return None
