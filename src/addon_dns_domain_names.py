"""Public RFC 1035 domain-name helpers for addon DNS values."""

import struct


_COMPRESSIBLE_RECORD_TYPES = frozenset({
    2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 21, 24, 26, 30,
    33, 35,
})


def cache():
    """Create the offset cache used while decoding one DNS message."""
    return {}


def pack(name):
    """Encode an uncompressed presentation-format domain name."""
    if name == "":
        return b"\x00"

    labels = name.split(".")
    if any(label == "" for label in labels):
        raise ValueError(f"domain name {name!r} contains empty labels")

    result = bytearray()
    for label in labels:
        encoded = label.encode("idna")
        result.append(len(encoded))
        result.extend(encoded)
    result.append(0)
    return bytes(result)


def _label(buffer, offset, length):
    end = offset + length
    if end > len(buffer):
        raise struct.error(f"unpack requires a label buffer of {length} bytes")
    return buffer[offset:end].decode("idna"), end


def unpack_from(buffer, offset):
    """Decode an uncompressed name and return its absolute end offset."""
    labels = []
    cursor = offset
    while True:
        length = struct.unpack_from("!B", buffer, cursor)[0]
        if length & 0xC0 == 0xC0:
            raise struct.error(
                "unpack encountered a pointer which is not supported in RDATA"
            )
        if length > 63:
            raise struct.error(f"unpack encountered a label of length {length}")
        cursor += 1
        if length == 0:
            return ".".join(labels), cursor
        label, cursor = _label(buffer, cursor, length)
        labels.append(label)


def unpack(buffer):
    """Decode exactly one uncompressed name from a complete buffer."""
    name, end = unpack_from(buffer, 0)
    if end != len(buffer):
        raise struct.error(f"unpack requires a buffer of {end} bytes")
    return name


def unpack_from_with_compression(buffer, offset, cached_names):
    """Decode a possibly compressed name and retain bounded offset results."""
    existing = cached_names.get(offset, False)
    if existing is None:
        raise struct.error("unpack encountered domain name loop")
    if existing is not False:
        name, consumed = existing
        return name, offset + consumed

    cached_names[offset] = None
    labels = []
    cursor = offset
    try:
        while True:
            length = struct.unpack_from("!B", buffer, cursor)[0]
            if length & 0xC0 == 0xC0:
                pointer = struct.unpack_from("!H", buffer, cursor)[0] & 0x3FFF
                suffix, _end = unpack_from_with_compression(
                    buffer, pointer, cached_names
                )
                if suffix:
                    labels.append(suffix)
                cursor += 2
                break
            if length > 63:
                raise struct.error(
                    f"unpack encountered a label of length {length}"
                )
            cursor += 1
            if length == 0:
                break
            label, cursor = _label(buffer, cursor, length)
            labels.append(label)
    except BaseException:
        cached_names.pop(offset, None)
        raise

    name = ".".join(labels)
    consumed = cursor - offset
    cached_names[offset] = (name, consumed)
    return name, cursor


def decompress_from_record_data(buffer, offset, end_data, cached_names):
    """Replace a compressed leading name and preserve the remaining RDATA."""
    name, end_name = unpack_from_with_compression(buffer, offset, cached_names)
    return pack(name) + buffer[end_name:end_data]


def record_data_can_have_compression(record_type):
    return record_type in _COMPRESSIBLE_RECORD_TYPES
