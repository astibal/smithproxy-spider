"""Explicit, bounded HPACK translation. Embedded before entering the sandbox.

Only data is checkpointed. No pickle, Python globals or worker affinity.
The first live slice accepts complete annotated blocks and default SETTINGS.
"""
try:
    import hpack as _translate_hpack
except ImportError:
    _translate_hpack = None


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

        for part in message.parts:
            if part.type == PartType.Opaque:
                if part.get_bytes() != b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n':
                    raise CommitException('Translate requires annotated H2 frames; unknown bytes cannot be skipped')
                continue
            if not part.complete or part.frame_type == 9:
                raise CommitException('Translate requires complete header blocks; partial input is not supported yet')
            if part.frame_type == 5:
                raise CommitException('PUSH_PROMISE translation is not supported yet')
            if part.frame_type == 4:
                self._settings(part)
            if part.frame_type == 1:
                self._decode_headers(part, active)

        if active:
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

        if active:
            part.headers = headers
            return

        # Before opt-in, preserve the ordinary rewrite view. Remember how its
        # fields map to decoded values if the script later chooses translate.
        if part.headers is not None:
            values = iter(headers.entries)

            for field in part.headers.entries:
                resolved = None if field.indexing == 'table-size' else next(values)
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
        if message.parts._held_from is not None:
            raise CommitException('Translate with hold is not integrated yet')
        if tuple(id(p) for p in message.parts) != self.identities:
            raise CommitException('Translate cannot insert, remove or reorder Parts yet')

        output = bytearray()
        # A failed assembly can be retried. Publish neither bytes nor table
        # changes until the entire message and checkpoint have passed validation.
        encoder = copy.deepcopy(self.encoder)

        for part, original in zip(message.parts, self.originals):
            if part.frame_type != 1:
                if part.commit() != original:
                    raise CommitException('Translate currently supports header edits only')
                output.extend(original)
            else:
                fields = self._header_fields(part)
                output.extend(part._assemble(encoder.encode(fields)))

            if len(output) > 1024 * 1024:
                raise CommitException('Translated output exceeds 1 MiB')

        checkpoint = {
            'version': 1,
            'input': _translate_table_dump(self.decoder),
            'output': _translate_table_dump(encoder),
        }

        if len(json.dumps(checkpoint)) > 65536:
            raise CommitException('Translate checkpoint exceeds 64 KiB')

        self.result = bytes(output)
        self.checkpoint = checkpoint
        return self.result


def _prepare_translation(message, request):
    active = request.get('translate_active', False)

    if not active and not request.get('translate_allowed', False):
        return

    try:
        transaction = _Translation(message, request.get('translate_state'), active)
        object.__setattr__(message, '_translation', transaction)
    except Exception as error:
        if active:
            raise CommitException(str(error)) from error

        # A normal rewrite callback must not fail just because it could have
        # chosen translate. Surface this error only if it actually chooses it.
        object.__setattr__(message, '_translation_error', str(error))
