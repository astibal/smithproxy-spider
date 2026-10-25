"""Explicit, bounded HPACK translation. Embedded before entering the sandbox.

Only data is checkpointed. No pickle, Python globals or worker affinity.
Default SETTINGS only. Incomplete wire units require an explicit suffix hold.
"""
try:
    import hpack as _translate_hpack
except ImportError:
    _translate_hpack = None


_H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


def _translate_parts(data, preface=False):
    """Frame an established H2 direction, retaining its unfinished last unit.

    This is not protocol detection. Only translate's admitted H2 stream uses
    these boundaries; ordinary rewrite keeps using the supplied annotations.
    """
    parts, cursor = [], 0

    if preface:
        available = min(len(data), len(_H2_PREFACE))

        if data[:available] != _H2_PREFACE[:available]:
            raise CommitException('Invalid continued H2 preface')

        part = RewritePart(data[:available], data=data[:available], complete=available == len(_H2_PREFACE))
        parts.append(part)
        cursor = available

        if not part.complete:
            part._translate_fragment = 'preface'
            return parts

    while cursor < len(data):
        start = cursor
        stream = None

        while True:
            if len(data) - cursor < 9:
                complete = False
                break

            size = int.from_bytes(data[cursor:cursor + 3], 'big')
            typ, flags = data[cursor + 3:cursor + 5]
            current_stream = int.from_bytes(data[cursor + 5:cursor + 9], 'big') & 0x7fffffff

            if size > 16384:
                raise CommitException('Translate requires frames within the default 16384-byte capacity')

            if stream is not None and (typ != 9 or current_stream != stream):
                raise CommitException('Expected CONTINUATION on the held header stream')

            if stream is None and typ == 9:
                raise CommitException('Orphan CONTINUATION frame')

            end = cursor + 9 + size

            if end > len(data):
                complete = False
                break

            cursor = end

            if typ not in (1, 5, 9) or flags & 4:
                complete = True
                break

            stream = current_stream

        end = cursor if complete else len(data)

        if end - start < 9:
            part = RewritePart(data[start:end], data=data[start:end], complete=False)
        else:
            part = _h2_parse_part(memoryview(data), start, end, None)

            if complete and not part.complete:
                raise CommitException('Invalid complete H2 frame or header block')

        part.complete = complete
        parts.append(part)

        if not complete:
            part._translate_fragment = 'frame'
            break

    return parts


def _resume_translation(message, checkpoint):
    """Keep complete held drafts; only rebuild the unfinished physical tail."""
    held, _ = _restore(checkpoint) if checkpoint else ([], {})
    data = message.bytes
    preface = False

    if held and not held[-1].complete:
        tail = held.pop()

        if (tail._pending is not None or tail.headers is not None or
                (tail.frame_type, tail.flags, tail.stream_id) != tail._initial):
            raise CommitException('Cannot resume an edited incomplete H2 part')

        kind = getattr(tail, '_translate_fragment', None)

        if kind not in ('frame', 'preface'):
            raise CommitException('Missing translate framing checkpoint')

        data = bytes(tail._wire) + data
        preface = kind == 'preface'

    if sum(len(p._wire) for p in held) + len(data) > 1024 * 1024:
        raise CommitException('Resumed translate message exceeds 1 MiB')

    # The first client callback may be only a prefix of the H2 preface.
    if not checkpoint and data and _H2_PREFACE.startswith(data[:len(_H2_PREFACE)]):
        preface = True

    object.__setattr__(message, 'parts', PartList(held + _translate_parts(data, preface)))


def _translate_table_dump(codec):
    import base64

    table = codec.header_table
    return {'size': table.maxsize, 'entries': [
        [base64.b64encode(name).decode(), base64.b64encode(value).decode()]
        for name, value in table.dynamic_entries
    ]}


def _translate_table_load(codec, saved):
    import base64

    size = saved['size']

    if type(size) is not int or not 0 <= size <= 4096:
        raise CommitException('Invalid translate table capacity')

    codec.header_table.maxsize = size
    total = 0

    # Checkpoints list newest entries first; rebuild the table oldest first.
    for name, value in reversed(saved['entries']):
        name = base64.b64decode(name, validate=True)
        value = base64.b64decode(value, validate=True)
        total += 32 + len(name) + len(value)

        if total > size:
            raise CommitException('Translate table exceeds capacity')

        codec.header_table.add(name, value)

    codec.header_table.resized = False


class _Translation:
    def __init__(self, message, checkpoint, active):
        if _translate_hpack is None:
            raise CommitException('H2 translate requires python-hpack')

        self.message = message
        self.decoder = _translate_hpack.Decoder()
        self.encoder = _translate_hpack.Encoder()
        self.result = None
        self.checkpoint = None
        self.decoded = {}
        self.original_fields = {}
        self.originals = tuple(bytes(p._wire) for p in message.parts)
        self.identities = tuple(id(p) for p in message.parts)

        if checkpoint is not None:
            if checkpoint.get('version') != 1:
                raise CommitException('Unsupported translate checkpoint')

            _translate_table_load(self.decoder, checkpoint['input'])
            _translate_table_load(self.encoder, checkpoint['output'])

        self.input_before = _translate_table_dump(self.decoder)

        for part in message.parts:
            if not part.complete:
                continue  # Only an explicit hold may publish this unfinished unit.

            if part.type == PartType.Opaque:
                if part.get_bytes() != _H2_PREFACE:
                    raise CommitException('Translate requires annotated H2 frames; unknown bytes cannot be skipped')
                continue
            if part.frame_type == 9:
                raise CommitException('Orphan CONTINUATION frame')
            if part.frame_type == 5:
                raise CommitException('PUSH_PROMISE translation is not supported yet')
            if part.frame_type == 4:
                self._settings(part)
            if part.frame_type == 1:
                self._decode_headers(part, active)

        object.__setattr__(message, '_body_sizes', {
            id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
            for group in _h2_content_groups(message.parts)
        })

    def _decode_headers(self, part, active):
        """Resolve source indices without changing the receiver's table."""
        fields = self.decoder.decode(part.get_bytes(), raw=True)
        headers = H2Headers([
            HpackField(field[0], field[1], 'never' if not field.indexable else 'without', 0, 0)
            for field in fields
        ])
        self.decoded[id(part)] = headers

        if active and not getattr(part, '_translate_draft', False):
            part.headers = headers
            return

        if active:
            return  # Logical edits in a complete held part survive the next run.

        # Before opt-in, preserve the ordinary rewrite view. Remember how its
        # fields map to decoded values if the script later chooses translate.
        if part.headers is not None:
            values = iter(headers.entries)

            for field in part.headers.entries:
                resolved = None if field.indexing == 'table-size' else next(values)

                if resolved is not None:
                    # Enrich the facade, retaining original HPACK instructions.
                    # An unchanged rewrite must still emit its exact raw bytes.
                    field.name, field.value = resolved.name, resolved.value
                    field._initial = field._state()

                self.original_fields[id(field)] = (field._state(), resolved)

    @staticmethod
    def _settings(part):
        data = part.get_bytes()

        if part.stream_id or len(data) % 6 or (part.flags & 1 and data):
            raise CommitException('Invalid SETTINGS frame')

        for offset in range(0, len(data), 6):
            key = int.from_bytes(data[offset:offset + 2], 'big')
            value = int.from_bytes(data[offset + 2:offset + 6], 'big')

            if (key == 1 and value != 4096) or (key == 5 and value != 16384):
                raise CommitException('Translate currently requires default HPACK table and frame capacities')

    def _resolve_field(self, field):
        """Turn an activation-time rewrite field into a logical header."""
        previous = self.original_fields.get(id(field))

        if previous is None:
            return field

        state, resolved = previous
        current = field._state()

        if current == state:
            # None means a source table-size update, already handled by decoder.
            return resolved

        if current[2:] == state[2:]:
            indexing = 'never' if state[2] == 'never' else 'without'
            return HpackField(field.name, field.value, indexing, 0, 0)

        return field

    def _header_fields(self, part):
        if part._pending is not None:
            raise CommitException('Translate requires logical headers, not raw HPACK')

        headers = part.headers

        if headers is None or headers._encode() == part._data:
            headers = self.decoded[id(part)]

        fields = []

        for field in headers.entries:
            field = self._resolve_field(field)

            if field is None:
                continue

            logical_value = isinstance(field.name, bytes) and isinstance(field.value, bytes)
            explicit_index = field.index or field.name_index
            supported_indexing = field.indexing in ('without', 'incremental', 'never')

            if not logical_value or explicit_index or not supported_indexing:
                raise CommitException('Explicit HPACK indices are rewrite-only')

            fields.append((field.name, field.value, field.indexing == 'never'))

        return fields

    def translate(self):
        import copy
        import json

        message = self.message

        if self.result is not None:
            raise CommitException('Call translate exactly once per callback')
        if tuple(id(p) for p in message.parts) != self.identities:
            raise CommitException('Translate cannot insert, remove or reorder Parts yet')

        boundary = message.parts._held_from
        cut = len(message.parts)

        if boundary is not None:
            positions = [i for i, p in enumerate(message.parts) if p is boundary]

            if len(positions) != 1:
                raise CommitException('Hold boundary was removed or duplicated')

            cut = positions[0]

        output = bytearray()
        # A failed assembly can be retried. Publish neither bytes nor table
        # changes until the entire message and checkpoint have passed validation.
        encoder = copy.deepcopy(self.encoder)

        emitted = message.parts[:cut]

        for part, original in zip(emitted, self.originals):
            if not part.complete:
                raise CommitException('Incomplete H2 part: hold_from(part) before translate')

            if part.frame_type != 1:
                if part.commit() != original:
                    raise CommitException('Translate currently supports header edits only')
                output.extend(original)
            else:
                fields = self._header_fields(part)
                output.extend(part._assemble(encoder.encode(fields)))

            if len(output) > 1024 * 1024:
                raise CommitException('Translated output exceeds 1 MiB')

        decoder = self.decoder

        if cut < len(message.parts):
            # Views decoded the full input speculatively. Publish only the table
            # after the emitted prefix, so retained blocks are consumed once.
            decoder = _translate_hpack.Decoder()
            _translate_table_load(decoder, self.input_before)

            for part in emitted:
                if part.frame_type == 1:
                    decoder.decode(part._data, raw=True)

        checkpoint = {
            'version': 1,
            'input': _translate_table_dump(decoder),
            'output': _translate_table_dump(encoder),
        }

        if len(json.dumps(checkpoint)) > 65536:
            raise CommitException('Translate checkpoint exceeds 64 KiB')

        result = bytes(output)

        if boundary is not None:
            suffix = message.parts[cut:]
            saved = []

            try:
                for part in suffix:
                    if not part.complete and (part._pending is not None or
                            (part.frame_type, part.flags, part.stream_id) != part._initial):
                        raise CommitException('Cannot hold an edited incomplete H2 part')

                    if part.complete and part.frame_type == 1:
                        # Normalize only the checkpoint, never the user's live draft.
                        fields = self._header_fields(part)
                        saved.append((part, part.headers, getattr(part, '_translate_draft', None)))
                        part.headers = H2Headers([
                            HpackField(name, value, 'never' if sensitive else 'without', 0, 0)
                            for name, value, sensitive in fields
                        ])
                        part._translate_draft = True

                held = _checkpoint(suffix, message._body_sizes)
            finally:
                for part, headers, marker in saved:
                    part.headers = headers

                    if marker is None:
                        del part._translate_draft
                    else:
                        part._translate_draft = marker

            if len(json.dumps(held)) + (len(output) + 2) // 3 * 4 > 1400 * 1024:
                raise CommitException('Translate prefix and hold exceed worker response budget')

            result = HeldCommit(result, held, len(suffix))

        self.result = result
        self.checkpoint = checkpoint
        return self.result


def _prepare_translation(message, request):
    active = request.get('translate_active', False)

    if not active and not request.get('translate_allowed', False):
        return

    try:
        if active:
            _resume_translation(message, request.get('held_parts'))
        elif ((message.bytes and _H2_PREFACE.startswith(message.bytes[:len(_H2_PREFACE)])) or
              any(p.is_a(PartType.Http2.Part) for p in message.parts)):
            _resume_translation(message, None)
        transaction = _Translation(message, request.get('translate_state'), active)
        object.__setattr__(message, '_translation', transaction)
    except Exception as error:
        if active:
            raise CommitException(str(error)) from error

        # A normal rewrite callback must not fail just because it could have
        # chosen translate. Surface this error only if it actually chooses it.
        object.__setattr__(message, '_translation_error', str(error))
