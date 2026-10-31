"""Public multipart form helpers shared with the HTTP request view."""

from urllib.parse import quote
import re
import warnings


def boundary(content_type):
    """Return the literal v12 form boundary parameter, if one is present."""
    if not content_type or 'multipart/form-data' not in content_type.lower():
        return None
    selected = None
    for parameter in content_type.split(';')[1:]:
        name, separator, value = parameter.strip().partition('=')
        if separator and name.strip() == 'boundary':
            selected = value.strip().encode('utf-8', 'surrogateescape')
    return selected


def decode_multipart(content_type, content):
    """Decode the public byte-valued multipart form view.

    This deliberately is not a general MIME parser.  It preserves the observed
    v12 view semantics, including loss of physical line separators in values.
    """
    marker = boundary(content_type)
    if marker is None or not content:
        return []

    fields = []
    for section in content.split(b'--' + marker)[1:]:
        lines = section.lstrip(b'\r\n').splitlines()
        try:
            separator = lines.index(b'')
        except ValueError:
            continue

        physical_lines = section.splitlines()
        name = None
        if separator and len(physical_lines) > 1:
            name = re.search(br'\bname="([^"]+)"', physical_lines[1])
        if name is not None:
            fields.append((name.group(1), b''.join(lines[separator + 1:])))
    return fields


def encode_multipart(content_type, parts):
    """Encode ordered byte-valued form fields using the literal boundary."""
    selected = boundary(content_type)
    if selected is None:
        return b''

    marker = b'--' + quote(selected).encode('ascii')
    chunks = []
    for name, value in parts:
        if not name:
            chunks.append(b'')
            continue
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            raise TypeError('Multipart form names and values must be bytes')
        if value == marker:
            raise ValueError('Multipart form value conflicts with boundary')
        chunks.extend((
            marker,
            b'Content-Disposition: form-data; name="' + name + b'"',
            b'Content-Type: text/plain; charset=utf-8',
            b'',
            value,
            b'',
        ))
    chunks.append(marker + b'--')
    return b'\r\n'.join(chunks) + b'\r\n'


def decode(content_type, parts):
    """Retain the legacy v12 name, including its historical encode behavior."""
    warnings.warn(
        'multipart.decode is deprecated, use multipart.decode_multipart instead.',
        DeprecationWarning,
        stacklevel=2,
    )
    return encode_multipart(content_type, parts)


def encode(content_type, parts):
    """Retain the second legacy v12 encoder spelling."""
    warnings.warn(
        'multipart.encode is deprecated, use multipart.encode_multipart instead.',
        DeprecationWarning,
        stacklevel=2,
    )
    return encode_multipart(content_type, parts)
