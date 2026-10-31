"""Public HTTPS and SVCB record helpers for addon DNS values."""

import struct
from typing import TypeAlias

from addon_dns import HTTPSRecord, SVCParamKeys
import addon_dns_domain_names as domain_names


HTTPSRecordJSON: TypeAlias = dict[str | int, int | str]


def pack(record):
    """Encode one HTTPS or SVCB record without DNS name compression."""
    result = bytearray(struct.pack("!H", record.priority))
    result.extend(domain_names.pack(record.target_name))
    for key, value in record.params.items():
        result.extend(struct.pack("!HH", key, len(value)))
        result.extend(value)
    return bytes(result)


def unpack(data):
    """Decode one complete HTTPS or SVCB record payload."""
    priority = struct.unpack("!H", data[:2])[0]
    target_name, offset = domain_names.unpack_from(data, 2)
    params = {}

    while offset < len(data):
        key = struct.unpack("!H", data[offset:offset + 2])[0]
        length = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        value_offset = offset + 4
        required = value_offset + length
        if len(data) < required:
            # Match the public helper's complete-record validation rather than
            # leaking an implementation-specific unpack_from offset message.
            struct.unpack(f"!{required}s", data)
        value = data[value_offset:required]
        params[key] = value
        offset = required

    return HTTPSRecord(priority, target_name, params)
