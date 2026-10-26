"""H2 REWRITE parts. Embedded after inspection_api; no persistent output HPACK state.

The backend's decoded fields are attached only by an exact callback-local offset.
HPACK instructions remain intact unless edited. New strings use literal bytes,
not Huffman coding: both are valid HPACK and require no new runtime dependency.
"""


class PartType:
    Opaque = 'opaque'

    class Http1:
        Part = 'http1'
        Header = 'http1.header'
        Body = 'http1.body'
        Chunk = 'http1.chunk'

    class Http2:
        Part = 'http2'
        Body = 'http2.body'
        Header = 'http2.header'
        Data = 'http2.data'
        Frame = 'http2.frame'


def _h2_uint(value, bits, label):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise CommitException(f'{label} must be an unsigned {bits}-bit integer')
    return value


def _h2_bytes(value):
    if not isinstance(value, bytes):
        raise CommitException('H2 representation must be bytes')
    if len(value) > 1024 * 1024:
        raise CommitException('H2 representation exceeds 1 MiB')
    return value


def _hpack_integer(value, prefix, marker=0):
    _h2_uint(value, 32, 'HPACK integer')
    maximum = (1 << prefix) - 1
    if value < maximum:
        return bytes([marker | value])
    result = bytearray([marker | maximum])
    value -= maximum
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _hpack_read_integer(data, cursor, prefix):
    if cursor >= len(data):
        raise CommitException('Truncated HPACK integer')
    maximum = (1 << prefix) - 1
    value = data[cursor] & maximum
    cursor += 1
    if value == maximum:
        for shift in range(0, 35, 7):
            if cursor >= len(data):
                raise CommitException('Truncated HPACK integer')
            byte = data[cursor]
            cursor += 1
            value += (byte & 127) << shift
            if byte < 128:
                break
        else:
            raise CommitException('HPACK integer exceeds implementation limit')
    _h2_uint(value, 32, 'HPACK integer')
    return value, cursor


def _hpack_string(value):
    _h2_bytes(value)
    return _hpack_integer(len(value), 7) + value


def _hpack_read_string(data, cursor):
    if cursor >= len(data):
        raise CommitException('Truncated HPACK string')
    huffman = bool(data[cursor] & 128)
    size, cursor = _hpack_read_integer(data, cursor, 7)
    if cursor + size > len(data):
        raise CommitException('Truncated HPACK string')
    return (None if huffman else data[cursor:cursor + size]), cursor + size


@dataclass
class HpackField:
    """One HPACK instruction, including indexed references and table-size updates.

    Logical names/values are bytes, not escaped GUI strings. None means the
    backend did not supply the decode context. Explicit indices are not resolved
    or checked against the peer's table; REWRITE deliberately leaves that to you.
    """
    name: bytes | None = documented('Logical name, None when unresolved.', 'entry.name = b"x-test"', access='mutable rewrite draft')
    value: bytes | None = documented('Logical value, None when unresolved.', 'entry.value = b"changed"', access='mutable rewrite draft')
    indexing: str = documented('without, incremental, never, indexed, or table-size. Changing it may diverge peer HPACK state.', 'entry.indexing = "incremental"', access='mutable rewrite draft')
    index: int = documented('Full-field reference for indexed; capacity for table-size.', 'entry.index = 62', access='mutable rewrite draft')
    name_index: int = documented('Name-only reference for literal fields; zero encodes the name bytes.', 'entry.name_index = 0', access='mutable rewrite draft')

    def _state(self):
        return self.name, self.value, self.indexing, self.index, self.name_index

    def _encode(self):
        initial = getattr(self, '_initial', None)
        if initial == self._state():
            return self._raw

        mode = self.indexing
        logical_edit = initial is not None and self._state()[:2] != initial[:2]
        if mode == 'indexed' and not logical_edit:
            if self.index == 0:
                raise CommitException('HPACK field index zero is invalid')
            return _hpack_integer(self.index, 7, 128)
        if mode == 'table-size':
            return _hpack_integer(self.index, 5, 32)
        if mode == 'indexed':
            mode = 'without'  # Editing an indexed value creates a literal.
        if mode not in ('without', 'incremental', 'never'):
            raise CommitException('Unknown HPACK indexing mode')

        name_index = self.name_index
        if initial is not None and self.name != initial[0] and name_index == initial[4]:
            name_index = 0
        prefix, marker = (6, 64) if mode == 'incremental' else (4, 16 if mode == 'never' else 0)
        result = _hpack_integer(name_index, prefix, marker)
        if not name_index:
            if self.name is None:
                raise CommitException('Unresolved HPACK name: supply name bytes or name_index')
            result += _hpack_string(self.name)
        if self.value is None:
            raise CommitException('Unresolved HPACK value: supply value bytes')
        return result + _hpack_string(self.value)


def _hpack_fields(data, decoded=None):
    entries, cursor, logical = [], 0, 0
    while cursor < len(data):
        start, first = cursor, data[cursor]
        if first & 128:
            index, cursor = _hpack_read_integer(data, cursor, 7)
            if not index:
                raise CommitException('HPACK field index zero is invalid')
            entry = HpackField(None, None, 'indexed', index, 0)
        elif first & 64 or not first & 32:
            mode = 'incremental' if first & 64 else ('never' if first & 16 else 'without')
            index, cursor = _hpack_read_integer(data, cursor, 6 if first & 64 else 4)
            name = None
            if not index:
                name, cursor = _hpack_read_string(data, cursor)
            value, cursor = _hpack_read_string(data, cursor)
            entry = HpackField(name, value, mode, 0, index)
        else:
            index, cursor = _hpack_read_integer(data, cursor, 5)
            entry = HpackField(None, None, 'table-size', index, 0)

        if entry.indexing != 'table-size':
            if decoded is not None:
                if logical >= len(decoded):
                    raise CommitException('HPACK enrichment field count mismatch')
                entry.name = _h2_display_bytes(decoded[logical], 'name')
                entry.value = _h2_display_bytes(decoded[logical], 'value')
            logical += 1
        entry._raw, entry._initial = data[start:cursor], entry._state()
        entries.append(entry)

    if decoded is not None and logical != len(decoded):
        raise CommitException('HPACK enrichment field count mismatch')
    return entries


def _h2_display_bytes(header, key):
    value = header[key]
    if header.get(key + '_encoding') != 'escaped-bytes':
        return value.encode('ascii')
    result, cursor = bytearray(), 0
    while cursor < len(value):
        if value[cursor] == '\\':
            if value[cursor:cursor + 2] != '\\x' or cursor + 4 > len(value):
                raise CommitException('Malformed escaped HPACK enrichment')
            result.append(int(value[cursor + 2:cursor + 4], 16))
            cursor += 4
        else:
            result.extend(value[cursor].encode('ascii'))
            cursor += 1
    return bytes(result)


@dataclass
class H2Headers:
    """Ordered mutable HPACK instructions. Unchanged instructions keep their wire bytes."""
    entries: list[HpackField] = documented('Preserves duplicates, representation choices and table-size instructions. Reorder, append or remove explicitly.',
        'part.headers.entries.append(api.http2.Header(b"x-test", b"yes", "incremental"))', access='mutable rewrite draft')

    @api_method('name: bytes, value: bytes, indexing: str = "without"', 'None',
                'Replace matching fields with one literal; fails if any field name is unresolved. Does not protect future peer state.',
                'part.headers.set_header(b"x-test", b"yes")', availability='Complete decoded H2 header block.', access='mutable rewrite draft')
    def set_header(self, name, value, indexing='without'):
        _h2_bytes(name)
        _h2_bytes(value)
        if indexing not in ('without', 'incremental', 'never'):
            raise CommitException('set_header requires a literal indexing mode')
        if any(e.name is None for e in self.entries if e.indexing != 'table-size'):
            raise CommitException('Unresolved names: edit entries explicitly or supply decode context')
        positions = [i for i, e in enumerate(self.entries) if e.name == name]
        position = positions[0] if positions else len(self.entries)
        self.entries[:] = [e for e in self.entries if e.name != name]
        self.entries.insert(position, HpackField(name, value, indexing, 0, 0))

    def _encode(self):
        original = getattr(self, '_original', None)
        if original is not None and len(original) == len(self.entries):
            if all(entry is old and entry._state() == entry._initial
                   for entry, old in zip(self.entries, original)):
                return self._wire

        output, field_seen = bytearray(), False
        for entry in self.entries:
            if not isinstance(entry, HpackField):
                raise CommitException('Expected HpackField in entries')
            if entry.indexing == 'table-size' and field_seen:
                raise CommitException('HPACK table-size updates must precede fields')
            field_seen |= entry.indexing != 'table-size'
            output.extend(entry._encode())
            if len(output) > 1024 * 1024:
                raise CommitException('HPACK block exceeds 1 MiB')
        return bytes(output)


@dataclass(frozen=True)
class PartContent:
    """Completeness of this callback's known content, not just one frame."""
    complete: bool | None = documented('True only for a complete locally bounded content; False for a known unfinished content; otherwise None.',
        'if part.content.complete is not True:\n    api.print("Whole content is not available")')


@dataclass(init=False)
class RewritePart:
    """Assembler-level H2 or Opaque part. No implicit future-message translation."""
    type: str = documented('opaque, http2.header, http2.data, or http2.frame.', 'if part.type == PartType.Http2.Data:\n    part.set_bytes(b"new body")')
    stream_id: int = documented('H2 stream identifier, or 1 for Opaque. Zero remains zero.', 'part.stream_id = 3', access='mutable rewrite draft')
    frame_type: int | None = documented('Numeric frame type; None for Opaque.', 'api.print(part.frame_type) ', access='mutable rewrite draft')
    flags: int = documented('Frame flags; END_HEADERS is rebuilt when a header block is edited.', 'part.flags |= 1  # END_STREAM on DATA/HEADERS', access='mutable rewrite draft')
    complete: bool = documented('Complete frame or HEADERS/PUSH_PROMISE block including CONTINUATION available. Hold incomplete parts to continue them in a later callback before assembly.', 'if part.complete:\n    api.print(part.get_bytes()[:16].hex())')
    content: PartContent = documented('Separate whole-content completeness, based on original callback parts.', 'api.print(part.complete, part.content.complete)')
    headers: H2Headers | None = documented('HPACK instructions for a complete parseable HEADERS or PUSH_PROMISE block; None otherwise. Active translate resolves logical names and values using the shared directional table.', 'if part.headers is not None:\n    part.headers.set_header(b"x-test", b"yes")', access='mutable rewrite draft')
    max_frame_size: int = documented('Output splitting limit, default 16384. Caller may set a known peer limit up to 16777215.', 'part.max_frame_size = 16384', access='mutable rewrite draft',
        easy='Commit accepts 16384..16777215 and rejects oversized control/unknown frames.',
        expert='Commit accepts 1..16777215 for fragmentation and permits control/unknown frames above this limit. Positive frame capacity, wire representation and output quota remain mandatory.')
    http1: Http1Draft | None = documented('H1 header draft for an annotated Content-Length or chunked message; None on other parts. Edit the body through its Body part.', 'for part in api.message.parts:\n    if part.http1 is not None:\n        part.http1.set_header("X-Test", "held")', access='mutable rewrite draft')
    chunks: tuple[RewritePart, ...] = documented('Physical data-chunk views owned by a chunked H1 Body; empty on other parts. Edit chunk bytes or the whole Body, never both. Do not emit these views separately or reorder them.',
        'for chunk in part.chunks:\n    api.print(chunk.get_bytes().hex())', access='read-only tuple of editable views',
        easy='Rebuild changed chunk sizes. Body edits with trailers are rejected until trailer dependencies can be repaired.',
        expert='Rebuild changed chunk sizes and preserve trailers unchanged; their meaning is the caller responsibility. Framing, completeness and quotas remain enforced.')

    def __init__(self, wire=b'', frame_type=None, flags=0, stream_id=1, data=b'', complete=True):
        self.type = (PartType.Opaque if frame_type is None else PartType.Http2.Header
                     if frame_type in (1, 5) else PartType.Http2.Data if frame_type == 0 else PartType.Http2.Frame)
        self.frame_type, self.flags, self.stream_id = frame_type, flags, stream_id
        self.complete, self.content = complete, PartContent(None)
        self.headers, self.max_frame_size = None, 16384
        self.http1 = None
        self.chunks = ()
        self._wire, self._data = wire, data
        self._pending, self._prefix, self._padding = None, b'', b''
        self._initial = (frame_type, flags, stream_id)
        self._reserved = 0

    @api_method('kind: str', 'bool', 'Test exact type or family.', 'if part.is_a(PartType.Http2.Part):\n    api.print(part.stream_id)', availability='All rewrite parts.', access='read-only')
    def is_a(self, kind):
        return self.type == kind or self.type.startswith(kind + '.')

    @api_method('', 'bytes', 'Materialize representation: unpadded DATA, HPACK block, raw control-frame payload, or Opaque bytes. No gzip inflation.',
                'api.print(part.get_bytes()[:32].hex())', availability='All rewrite parts.', access='read-only')
    def get_bytes(self):
        if self._pending is not None:
            return self._pending

        # DATA and Opaque start as views of immutable callback bytes. Reading
        # explicitly materializes once; it does not mark the part as modified.
        if isinstance(self._data, memoryview):
            self._data = self._data.tobytes()
        return self._data

    @api_method('value: bytes', 'None', 'Replace the representation, not the nine-byte frame header. Rewrite supports unknown frame types; translate permits same-length DATA edits while preserving stream ID, flags and padding.',
                'part.set_bytes(b"changed")', availability='Complete parts only for a changed commit.', access='mutable rewrite draft')
    def set_bytes(self, value):
        self._pending = _h2_bytes(value)

    @api_method('*, safety: str = Safety.Easy', 'bytes', 'Prepare this part without publishing or changing the original. Message commit handles cross-part dependencies.',
                'wire = part.commit()\napi.print(len(wire))', availability='Unchanged or complete parts.', access='assemble private draft',
                easy='Apply H1 semantic guards and H2 configured frame-size bounds. No-op preserves original bytes.',
                expert='Allow H1 semantic inconsistencies and oversized H2 control frames; permit smaller fragmentation sizes when payload capacity is positive. Keep representation checks, quotas and complete-part requirements. Does not set the mode of a later message commit.')
    def commit(self, *, safety=Safety.Easy):
        try:
            _validate_safety(safety)
            result = bytes(self._assemble(safety=safety))
            if len(result) > 1024 * 1024:
                raise CommitException('Replacement exceeds 1 MiB')
            return result
        except CommitException:
            raise
        except (ValueError, TypeError, AttributeError, OverflowError) as error:
            raise CommitException(str(error)) from error

    def _assemble(self, header_override=None, *, safety=Safety.Easy):
        state = self.frame_type, self.flags, self.stream_id
        if self._wire and self._pending is None and self.headers is None and state == self._initial:
            return self._wire

        data = self.get_bytes()
        if self.headers is not None:
            encoded = self.headers._encode() if header_override is None else header_override
            if self._pending is not None and encoded != self._data:
                raise CommitException('Cannot mix raw HPACK replacement and field edits')
            if self._pending is None:
                data = encoded
        _h2_bytes(data)
        if self._wire and data == self._data and state == self._initial:
            return self._wire
        if not self.complete:
            raise CommitException('Incomplete H2 part: hold it and await more content before assembly')
        if self.frame_type is None:
            return data

        _h2_uint(self.frame_type, 8, 'Frame type')
        _h2_uint(self.flags, 8, 'Frame flags')
        _h2_uint(self.stream_id, 31, 'Stream id')
        minimum = 16384 if safety == Safety.Easy else 1
        if type(self.max_frame_size) is not int or not minimum <= self.max_frame_size <= 0xffffff:
            raise CommitException(f'max_frame_size must be {minimum}..16777215')
        if self.frame_type != self._initial[0]:
            raise CommitException('For a different frame type, replace the part with api.http2.Frame()')
        if (self.flags ^ self._initial[1]) & (0x28 if self.frame_type == 1 else 8 if self.frame_type in (0, 5) else 0):
            raise CommitException('Padding/priority flags require a new raw Frame, not an interpreted part')

        prefix, padding = self._prefix, self._padding
        if self.frame_type not in (0, 1, 5):
            if len(data) > self.max_frame_size and safety == Safety.Easy:
                raise CommitException('Control/unknown frame exceeds max_frame_size')
            return self._frame(self.frame_type, self.flags, data)

        # Expert can request very small fragments; bound expansion before
        # allocating a list of potentially hundreds of thousands of frames.
        minimum_frames = max(1, (len(data) + self.max_frame_size - 1) // self.max_frame_size)
        if len(data) + 9 * minimum_frames > 1024 * 1024:
            raise CommitException('Replacement exceeds 1 MiB')

        output, cursor, first = [], 0, True
        while first or cursor < len(data):
            capacity = self.max_frame_size - len(prefix) - len(padding)
            if capacity <= 0:
                raise CommitException('Frame has no positive payload capacity after padding/priority')
            chunk = data[cursor:cursor + capacity]
            cursor += len(chunk)
            last = cursor == len(data)
            if self.frame_type == 0:
                typ = 0
                flags = self.flags if first else self.flags & ~8
                if not last:
                    flags &= ~1
            else:
                typ = self.frame_type if first else 9
                flags = (self.flags & ~4) if first else 0
                if last:
                    flags |= 4
            output.append(self._frame(typ, flags, prefix + chunk + padding))
            prefix, padding, first = b'', b'', False
        return b''.join(output)

    def _frame(self, typ, flags, data):
        return (len(data).to_bytes(3, 'big') + bytes([typ, flags]) +
                (self.stream_id | self._reserved).to_bytes(4, 'big') + data)


def _h2_new_frame(typ, flags, stream_id, payload):
    _h2_uint(typ, 8, 'Frame type')
    _h2_uint(flags, 8, 'Frame flags')
    _h2_uint(stream_id, 31, 'Stream id')
    payload = _h2_bytes(payload)
    wire = len(payload).to_bytes(3, 'big') + bytes([typ, flags]) + stream_id.to_bytes(4, 'big') + payload
    part = _h2_parse_part(wire, 0, len(wire), None)
    # Defer configured frame-size checks to commit, where safety is explicit.
    part._wire = b''
    return part


def _h2_parse_part(wire, start, end, decoded):
    typ, flags = wire[start + 3:start + 5]
    declared = int.from_bytes(wire[start:start + 3], 'big')
    stream = int.from_bytes(wire[start + 5:start + 9], 'big')
    raw = wire[start + 9:min(start + 9 + declared, end)]
    part = RewritePart(wire[start:end], typ, flags, stream & 0x7fffffff, raw,
                       start + 9 + declared <= end)
    part._reserved = stream & 0x80000000
    if typ not in (0, 1, 5) or not part.complete:
        return part
    padding = raw[0] if flags & 8 and raw else 0
    prefix_len = int(bool(flags & 8)) + (5 if typ == 1 and flags & 32 else 4 if typ == 5 else 0)
    if prefix_len + padding > len(raw):
        part.complete = False
        return part
    part._prefix = bytes(raw[:prefix_len])
    part._padding = bytes(raw[len(raw) - padding:]) if padding else b''
    part._data = raw[prefix_len:len(raw) - padding]
    if typ in (1, 5):
        part._data = bytes(part._data)
        cursor, final = start + 9 + declared, bool(flags & 4)
        while not final and cursor + 9 <= end:
            size = int.from_bytes(wire[cursor:cursor + 3], 'big')
            part._data += bytes(wire[cursor + 9:cursor + 9 + size])
            final = bool(wire[cursor + 4] & 4)
            cursor += 9 + size
        part.complete = final and cursor == end
        if part.complete:
            try:
                part.headers = H2Headers(_hpack_fields(part._data, decoded))
                part.headers._original = tuple(part.headers.entries)
                part.headers._wire = part._data
            except (CommitException, ValueError, KeyError, TypeError, UnicodeError):
                # Invalid/unresolved metadata never makes untouched traffic fail.
                part.headers = None
    return part


def make_rewrite_parts(payload, info, enrichments):
    views = make_http2(info, payload, ())
    frames = {f.offset: f for f in views.frames}
    decoded = {}
    for item in enrichments:
        meta = item.get('metadata', {})
        offset = meta.get('source', {}).get('payload_offset')
        if meta.get('operation') == 'hpack.decode' and meta.get('context') == 'complete' and type(offset) is int:
            decoded[offset] = meta.get('headers', [])
    parts, cursor = [], 0
    source = memoryview(payload)
    for start, frame in sorted(frames.items()):
        if start < cursor:
            continue
        if start > cursor:
            parts.append(RewritePart(source[cursor:start], data=source[cursor:start]))
        end = min(len(payload), start + 9 + frame.length)
        final = bool(frame.flags & 4)
        if frame.type in (1, 5) and frame.complete:
            while not final and end in frames:
                following = frames[end]
                if following.type != 9 or following.stream_id != frame.stream_id or not following.complete:
                    break
                end += 9 + following.length
                final = bool(following.flags & 4)
        parts.append(_h2_parse_part(source, start, end, decoded.get(start)))
        cursor = end
    if cursor < len(payload):
        parts.append(RewritePart(source[cursor:], data=source[cursor:]))
    _h2_content_groups(parts)
    return parts


def _h2_content_groups(parts):
    """Only explicit request/response heads establish a local body boundary."""
    active, groups = {}, []
    for part in parts:
        if not part.type.startswith('http1.'):
            part.content = PartContent(None)

    for part in parts:
        # Unknown bytes may hide a boundary or data. Never claim completeness
        # through a gap we cannot interpret. RST_STREAM is not END_STREAM.
        if part.frame_type is None:
            active.clear()
        elif part.frame_type == 3:
            active.pop(part.stream_id, None)

        if part.frame_type == 1:
            if part.headers is None:
                # END_STREAM on HEADERS does not complete content until the
                # entire header block (including CONTINUATION) is available.
                if part.stream_id in active and not part.complete:
                    active[part.stream_id].append(part)
                else:
                    active.pop(part.stream_id, None)
            elif any(e.name in (b':method', b':status') for e in part.headers.entries):
                active[part.stream_id] = [part]
                groups.append(active[part.stream_id])
            elif part.stream_id in active:
                active[part.stream_id].append(part)
        elif part.frame_type == 0 and part.stream_id in active:
            active[part.stream_id].append(part)
        if part.frame_type in (0, 1) and part.flags & 1 and part.stream_id in active:
            group = active.pop(part.stream_id)
            complete = all(p.complete for p in group)
            for member in group:
                member.content = PartContent(complete)
    for group in active.values():
        for part in group:
            part.content = PartContent(False)
    return groups


@dataclass(init=False)
class H2Body:
    """Logical view, not an additional wire part. DATA retain their physical order."""
    type: str = documented('Always PartType.Http2.Body.', 'api.print(body.type)')
    stream_id: int = documented('Stream owning these DATA parts.', 'api.print(body.stream_id)')
    complete: bool = documented('Whole content is known only after complete END_STREAM DATA or trailers; unknown after gaps/reset.', 'api.print(body.complete)')
    content: PartContent = documented('Whole-content completeness; unlike a DATA part, Body itself spans the whole content.', 'api.print(body.content.complete)')
    chunks: tuple[RewritePart, ...] = documented('Existing DATA parts, including incomplete frames. Read or edit these instead of replacing the whole body; do not emit them again.', 'for chunk in body.chunks:\n    api.print(chunk.complete)', access='tuple of mutable drafts')

    def __init__(self, group):
        self.type = PartType.Http2.Body
        self.stream_id = group[0].stream_id
        self.content = group[0].content
        self.complete = self.content.complete is True
        self.chunks = tuple(part for part in group if part.frame_type == 0)

    @api_method('', 'bytes', 'Concatenate unpadded bytes of complete DATA frames. Incomplete frames cannot safely expose logical content; no decompression.',
                'api.print(body.get_bytes().hex())', access='read-only')
    def get_bytes(self):
        if any(not part.complete for part in self.chunks):
            raise CommitException('Incomplete DATA frame: hold and await its remaining bytes')

        return b''.join(part.get_bytes() for part in self.chunks)

    @api_method('value: bytes', 'None', 'Replace complete content through existing DATA drafts. Keep original capacities except the last DATA, which receives the remainder. Keep padding, flags and interleaved frame order; no new stream or implicit flow-control translation.',
                'body.set_bytes(body.get_bytes())', access='mutable draft',
                easy='Require complete content and no prior DATA edits; final message commit repairs known Content-Length. Translate allows only same-length DATA.',
                expert='Same view guards. Rewrite may resize DATA; connection-wide correctness remains the caller responsibility. Translate does not allow resizing.')
    def set_bytes(self, value):
        value = _h2_bytes(value)

        if not self.complete or any(not part.complete for part in self.chunks):
            raise CommitException('Incomplete H2 body: hold from its header and await END_STREAM')

        if any(part._pending is not None for part in self.chunks):
            raise CommitException('Cannot combine whole-body replacement with existing DATA edits')

        if not self.chunks:
            if value:
                raise CommitException('Body has no DATA slots; construct explicit frames to add content')
            return

        # Prepare all slices before touching the drafts. Empty DATA stay in place
        # so END_STREAM and trailer ordering cannot move to another stream.
        replacements, offset = [], 0
        for index, part in enumerate(self.chunks):
            end = len(value) if index == len(self.chunks) - 1 else min(len(value), offset + len(part._data))
            replacements.append(value[offset:end])
            offset = end

        for part, data in zip(self.chunks, replacements):
            part.set_bytes(data)


def _h2_length_overrides(message):
    """Encode derived headers locally; failed commits must not edit the draft."""
    overrides = {}

    for group in _h2_content_groups(message.parts):
        head = group[0]
        bodies = [part for part in group if part.frame_type == 0]
        size = sum(len(p._data if p._pending is None else p._pending) for p in bodies)
        body_changed = any(
            part._pending is not None and part._pending != part._data
            for part in bodies
        )

        if size == message._body_sizes.get(id(head)) and not body_changed:
            continue

        fields = head.headers.entries

        if not any(field.name == b'content-length' for field in fields):
            continue

        if not head.content.complete:
            raise CommitException(
                'Cannot recalculate Content-Length without complete local content; '
                'use commit(False) for explicit research edits'
            )

        encoded_size = str(size).encode('ascii')
        adjusted = [
            HpackField(field.name, encoded_size, 'without', 0, 0)
            if field.name == b'content-length' else field
            for field in fields
        ]
        overrides[id(head)] = H2Headers(adjusted)._encode()

    return overrides


def commit_rewrite_message(message, update_content_length=True, *, safety=Safety.Easy):
    if type(update_content_length) is not bool:
        raise CommitException('update_content_length must be bool')
    if any(not isinstance(p, RewritePart) for p in message.parts):
        raise CommitException('Expected RewritePart in message.parts')
    if len({id(p) for p in message.parts}) != len(message.parts):
        raise CommitException('A part cannot be emitted twice; construct an explicit copy')

    if any(p.type == PartType.Http1.Chunk for p in message.parts):
        raise CommitException('Chunk views belong to their Body; do not append them to message.parts')

    overrides = _h2_length_overrides(message) if update_content_length else {}
    output = bytearray()

    for part in message.parts:
        output.extend(part._assemble(overrides.get(id(part)), safety=safety))

        if len(output) > 1024 * 1024:
            raise CommitException('Replacement exceeds 1 MiB')

    return bytes(output)
