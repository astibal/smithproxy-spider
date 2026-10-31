"""Domain-name codec observations shared by reference and adapter tests."""


def _outcome(callback):
    try:
        value = callback()
    except Exception as error:
        return {
            "ok": False,
            "type": type(error).__name__,
            "message": str(error),
        }
    return {"ok": True, "value": repr(value)}


def _cache_state(values):
    return {
        str(offset): None if value is None else [value[0], value[1]]
        for offset, value in values.items()
    }


def collect(domain_names):
    compressed = b"\x03www\xc0\x06\x07example\x03com\x00"
    names = domain_names.cache()
    compressed_result = domain_names.unpack_from_with_compression(
        compressed, 0, names
    )
    cached_result = domain_names.unpack_from_with_compression(
        compressed, 0, names
    )

    root_pointer_names = domain_names.cache()
    root_pointer_result = domain_names.unpack_from_with_compression(
        b"\xc0\x02\x00", 0, root_pointer_names
    )

    base = domain_names.pack("example.com")
    record = base + b"\xc0\x00TAIL"
    record_names = domain_names.cache()
    decompressed = domain_names.decompress_from_record_data(
        record, len(base), len(record), record_names
    )

    return {
        "pack": {
            "empty": domain_names.pack("").hex(),
            "ascii": domain_names.pack("www.example.com").hex(),
            "unicode": domain_names.pack("bücher.example").hex(),
            "root_error": _outcome(lambda: domain_names.pack(".")),
            "empty_label_error": _outcome(
                lambda: domain_names.pack("www..example")
            ),
        },
        "unpack": {
            "ascii": domain_names.unpack(
                domain_names.pack("www.example.com")
            ),
            "root": domain_names.unpack(b"\x00"),
            "from_suffix": list(domain_names.unpack_from(compressed, 6)),
            "trailing_error": _outcome(
                lambda: domain_names.unpack(b"\x01ax")
            ),
            "trailing_root_error": _outcome(
                lambda: domain_names.unpack(b"\x00x")
            ),
            "pointer_error": _outcome(
                lambda: domain_names.unpack_from(compressed, 0)
            ),
            "truncated_error": _outcome(
                lambda: domain_names.unpack(b"\x03ab")
            ),
            "long_label_error": _outcome(
                lambda: domain_names.unpack(b"\x40" + b"a" * 64 + b"\x00")
            ),
        },
        "compression": {
            "result": list(compressed_result),
            "cached_result": list(cached_result),
            "cache": _cache_state(names),
            "loop_error": _outcome(
                lambda: domain_names.unpack_from_with_compression(
                    b"\xc0\x00", 0, domain_names.cache()
                )
            ),
            "decompressed": decompressed.hex(),
            "record_cache": _cache_state(record_names),
            "root_pointer_result": list(root_pointer_result),
            "root_pointer_cache": _cache_state(root_pointer_names),
            "long_label_error": _outcome(
                lambda: domain_names.unpack_from_with_compression(
                    b"\x40" + b"a" * 64 + b"\x00", 0,
                    domain_names.cache(),
                )
            ),
        },
        "compressible_record_types": [
            value
            for value in range(300)
            if domain_names.record_data_can_have_compression(value)
        ],
    }
