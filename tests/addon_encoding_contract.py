"""Content-coding observations shared by reference and adapter tests."""


def collect(encoding):
    body = b"abc"
    cached = encoding.CachedDecode(body, "gzip", "strict", b"decoded")
    function_names = (
        "decode_brotli", "decode_deflate", "decode_gzip", "decode_zstd",
        "encode_brotli", "encode_deflate", "encode_gzip", "encode_zstd",
        "identity",
    )
    return {
        "all": list(encoding.__all__),
        "cached": {
            "fields": list(cached._fields),
            "state": [repr(value) for value in cached],
            "repr": repr(cached),
        },
        "custom_encode": {
            key: callback.__name__
            for key, callback in encoding.custom_encode.items()
        },
        "custom_decode": {
            key: callback.__name__
            for key, callback in encoding.custom_decode.items()
        },
        "functions": {
            name: getattr(encoding, name)(body).hex()
            for name in function_names
            if name.startswith("encode_") or name == "identity"
        },
        "roundtrips": {
            name: getattr(encoding, "decode_" + name)(
                getattr(encoding, "encode_" + name)(body)
            ).hex()
            for name in ("brotli", "deflate", "gzip", "zstd")
        },
        "deflateraw": {
            "wire": encoding.encode(body, "deflateraw").hex(),
            "decoded": encoding.decode(
                encoding.encode(body, "deflateraw"), "deflateraw"
            ).hex(),
        },
    }
