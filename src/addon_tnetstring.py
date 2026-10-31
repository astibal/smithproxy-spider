"""Tagged netstring codec used by saved addon flows.

This implementation follows the public tagged-netstring format.  It is kept
small and independent so saved-flow compatibility does not pull a proxy
runtime into the inspection worker.
"""

def _frame(payload, tag):
    return str(len(payload)).encode("ascii") + b":" + payload + tag


def dumps(value):
    if value is None:
        return b"0:~"
    if value is True:
        return b"4:true!"
    if value is False:
        return b"5:false!"
    if isinstance(value, int):
        return _frame(str(value).encode("ascii"), b"#")
    if isinstance(value, float):
        # repr preserves finite values and the spelling used by Python for
        # nan and infinities.  The public format intentionally permits them.
        return _frame(repr(value).encode("ascii"), b"^")
    if isinstance(value, bytes):
        return _frame(value, b",")
    if isinstance(value, str):
        return _frame(value.encode("utf-8"), b";")
    if isinstance(value, (list, tuple)):
        return _frame(b"".join(dumps(item) for item in value), b"]")
    if isinstance(value, dict):
        # The established writer emits mappings in reverse insertion order.
        # Preserve that wire contract so our files are byte-for-byte familiar
        # to existing tooling, even though the reader accepts any key order.
        entries = reversed(tuple(value.items()))
        payload = b"".join(dumps(key) + dumps(item) for key, item in entries)
        return _frame(payload, b"}")
    raise ValueError(f"unserializable object: {value!r} ({type(value)!r})")


def dump(value, file_handle):
    file_handle.write(dumps(value))


def split(data, separator):
    """Split a tagged-netstring length prefix from its remaining data."""
    raw = data.tobytes()
    prefix, found, _remaining = raw.partition(separator)
    if not found:
        raise ValueError(
            "not a tnetstring: missing or invalid length prefix: "
            f"{raw!r}"
        )

    try:
        length = int(prefix)
    except ValueError:
        raise ValueError(
            "not a tnetstring: missing or invalid length prefix: "
            f"{raw!r}"
        ) from None

    offset = len(prefix) + len(separator)
    return length, data[offset:]


def _split(data):
    view = memoryview(data)
    separator = 0
    while separator < len(view) and view[separator] != ord(":"):
        separator += 1
    if separator == len(view):
        raise ValueError(
            "not a tnetstring: missing or invalid length prefix: "
            f"{bytes(view)!r}"
        )
    prefix = bytes(view[:separator])
    try:
        length = int(prefix)
    except ValueError:
        raise ValueError(
            "not a tnetstring: missing or invalid length prefix: "
            f"{bytes(view)!r}"
        ) from None
    end = separator + 1 + length
    if length < 0 or end >= len(view):
        raise ValueError(f"not a tnetstring: invalid length prefix: {length}")
    return view[separator + 1:end], view[end], view[end + 1:]


def _parse(tag, payload):
    if tag == ord(","):
        return bytes(payload)
    if tag == ord(";"):
        return bytes(payload).decode("utf-8")
    if tag == ord("#"):
        view = memoryview(payload)
        try:
            return int(view)
        except ValueError:
            raise ValueError(
                f"not a tnetstring: invalid integer literal: {view!r}"
            ) from None
    if tag == ord("^"):
        view = memoryview(payload)
        try:
            return float(view)
        except ValueError:
            raise ValueError(
                f"not a tnetstring: invalid float literal: {view!r}"
            ) from None
    if tag == ord("!"):
        if payload == b"true":
            return True
        if payload == b"false":
            return False
        raise ValueError(f"not a tnetstring: invalid boolean literal: {payload!r}")
    if tag == ord("~"):
        if payload:
            raise ValueError(f"not a tnetstring: invalid null literal: {payload!r}")
        return None
    if tag == ord("]"):
        result = []
        remaining = memoryview(payload)
        while remaining:
            item, remaining = pop(remaining)
            result.append(item)
        return result
    if tag == ord("}"):
        result = {}
        remaining = memoryview(payload)
        while remaining:
            key, remaining = pop(remaining)
            item, remaining = pop(remaining)
            result[key] = item
        return result
    raise ValueError(f"unknown type tag: {tag}")


def parse(data_type, data):
    """Decode a tagged-netstring payload with an already parsed type tag."""
    # The public helper accepts the memoryview returned by split().  Touch the
    # method here as the reference API does, preserving its input contract.
    data.tobytes()
    return _parse(data_type, data)


def pop(data):
    view = memoryview(data)
    payload, tag, remaining = _split(view)
    return _parse(tag, payload), remaining


def loads(string):
    value, _remaining = pop(memoryview(string))
    return value


def load(file_handle):
    prefix = bytearray()
    while True:
        chunk = file_handle.read(1)
        if not chunk:
            if not prefix:
                raise ValueError("not a tnetstring: empty file")
            raise ValueError("not a tnetstring: missing or invalid length prefix")
        if chunk == b":":
            break
        prefix.extend(chunk)

    try:
        length = int(prefix)
    except ValueError:
        raise ValueError(
            "not a tnetstring: missing or invalid length prefix"
        ) from None
    if length < 0:
        raise ValueError("not a tnetstring: missing or invalid length prefix")

    framed = file_handle.read(length + 1)
    if len(framed) != length + 1:
        raise ValueError(f"not a tnetstring: invalid length prefix: {length}")
    return _parse(framed[-1], framed[:-1])


__all__ = ("dump", "dumps", "load", "loads", "pop")
