"""Public content and character encoding helpers for addon scripts.

HTTP message objects use the same functions.  Keeping the codec implementation
here avoids a facade-specific copy that could drift from message behavior.
"""

import codecs
from collections import namedtuple
import gzip
import zlib

import brotli
import zstandard


__all__ = ('decode', 'encode')

CachedDecode = namedtuple(
    'CachedDecode',
    ('encoded', 'encoding', 'errors', 'decoded'),
)


def identity(content):
    return content


def encode_gzip(content):
    wire = gzip.compress(content, compresslevel=1, mtime=0)
    # Python has emitted a platform-specific gzip OS byte in some releases.
    return wire[:9] + b'\xff' + wire[10:]


def decode_gzip(content):
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        return decoder.decompress(content)
    except zlib.error as error:
        raise ValueError(f'Decompression failed: {error}') from error


def encode_deflate(content):
    return zlib.compress(content, level=1)


def decode_deflate(content):
    try:
        return zlib.decompress(content)
    except zlib.error:
        return zlib.decompress(content, -zlib.MAX_WBITS)


def encode_brotli(content):
    return brotli.compress(content, quality=0)


def decode_brotli(content):
    return brotli.decompress(content) if content else b''


def encode_zstd(content):
    return zstandard.ZstdCompressor().compress(content)


def decode_zstd(content):
    # HTTP bodies may contain concatenated frames.  Each frame must finish;
    # accepting a truncated last frame would expose partially decoded content.
    chunks = []
    remaining = content
    while remaining:
        decoder = zstandard.ZstdDecompressor().decompressobj()
        chunks.append(decoder.decompress(remaining))
        if not decoder.eof:
            raise ValueError('Incomplete Zstandard frame')
        remaining = decoder.unused_data
    return b''.join(chunks)


custom_encode = {
    'identity': identity,
    'none': identity,
    'gzip': encode_gzip,
    'deflate': encode_deflate,
    'deflateraw': encode_deflate,
    'br': encode_brotli,
    'zstd': encode_zstd,
}

custom_decode = {
    'identity': identity,
    'none': identity,
    'gzip': decode_gzip,
    'deflate': decode_deflate,
    'deflateraw': decode_deflate,
    'br': decode_brotli,
    'zstd': decode_zstd,
}


def _failure(operation, content, coding, error):
    label = type(error).__name__
    raise ValueError(
        f"{label} when {operation} {content!r} with {coding!r}: {error!r}"
    ) from error


def encode(decoded, encoding, errors='strict'):
    """Apply an HTTP content coding or a Python character encoding."""
    if decoded is None:
        return None

    coding = encoding.lower()
    try:
        encoder = custom_encode.get(coding)
        if encoder is not None:
            return encoder(decoded)
        return codecs.encode(decoded, coding, errors)
    except (LookupError, UnicodeError, OSError, EOFError, zlib.error,
            brotli.error, zstandard.ZstdError, ValueError) as error:
        _failure('encoding', decoded, coding, error)


def decode(encoded, encoding, errors='strict'):
    """Remove an HTTP content coding or a Python character encoding."""
    if encoded is None:
        return None

    coding = encoding.lower()
    try:
        decoder = custom_decode.get(coding)
        if decoder is not None:
            return decoder(encoded)
        return codecs.decode(encoded, coding, errors)
    except (LookupError, UnicodeError, OSError, EOFError, zlib.error,
            brotli.error, zstandard.ZstdError, ValueError) as error:
        _failure('decoding', encoded, coding, error)
