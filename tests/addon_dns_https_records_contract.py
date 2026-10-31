"""HTTPS-record observations shared by reference and adapter tests."""


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


def collect(https_records):
    value = https_records.HTTPSRecord(
        1,
        "svc.example",
        {
            https_records.SVCParamKeys.ALPN.value: b"h2",
            65400: b"\x00",
        },
    )
    wire = https_records.pack(value)
    restored = https_records.unpack(wire)
    short_value = https_records.pack(
        https_records.HTTPSRecord(1, "x", {})
    ) + b"\x00\x01\x00\x02a"

    return {
        "wire": wire.hex(),
        "enum_is_int": isinstance(https_records.SVCParamKeys.ALPN, int),
        "roundtrip_equal": restored == value,
        "roundtrip": {
            "priority": restored.priority,
            "target_name": restored.target_name,
            "params": {
                str(key): item.hex()
                for key, item in restored.params.items()
            },
            "json": {
                str(key): item
                for key, item in restored.to_json().items()
            },
        },
        "errors": {
            "empty": _outcome(lambda: https_records.unpack(b"")),
            "one_byte": _outcome(lambda: https_records.unpack(b"\x00")),
            "trailing_byte": _outcome(
                lambda: https_records.unpack(wire + b"x")
            ),
            "short_value": _outcome(
                lambda: https_records.unpack(short_value)
            ),
        },
        "domain_module": https_records.domain_names.__name__,
        "public_surface": sorted(
            name for name in dir(https_records) if not name.startswith("_")
            and name in {
                "HTTPSRecord", "HTTPSRecordJSON", "SVCParamKeys",
                "domain_names", "pack", "unpack",
            }
        ),
    }
