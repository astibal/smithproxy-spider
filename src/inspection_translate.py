"""Explicit, bounded HPACK translation. Embedded before entering the sandbox.

Only data is checkpointed. No pickle, Python globals or worker affinity.
SETTINGS are synchronized by ordered ACKs. Incomplete units require explicit hold.
"""
try:
    import hpack as _translate_hpack
except ImportError:
    _translate_hpack = None


_H2_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'


class Mode:
    """Connection processing modes. Translate requires every callback explicitly."""
    Rewrite = 'rewrite'
    Translate = 'translate'


class ConnectionHttp2:
    """Persistent HTTP/2 policy, applied only by an explicitly returned translate result."""

    def __init__(self, connection):
        self._connection = connection

    @api_method('limit: int', 'None',
                'Enforce a maximum HPACK table capacity in both directions. Idempotent; never increases a peer-advertised limit. SETTINGS and synthetic ACK handling occur only through message.translate().',
                'api.connection.set_mode(Mode.Translate)\napi.connection.http2.enforce_header_table_limit(0)\nreturn api.message.translate()',
                availability='Live H2 flow deployment; requires Translate mode. Each direction is updated on its next eligible callback, after its first SETTINGS.',
                access='staged connection policy')
    def enforce_header_table_limit(self, limit):
        if type(limit) is not int or not 0 <= limit <= 0xffffffff:
            raise CommitException('Header table limit must be an integer in 0..4294967295')

        connection = self._connection

        if not connection._requested:
            raise CommitException('Header table policy requires Mode.Translate')

        transaction = connection._transaction()
        transaction.control_before['header_limit'] = limit


@dataclass(init=False)
class Connection:
    """Connection intent is staged; setters never send or translate payloads by themselves."""
    http2: ConnectionHttp2 = documented('HTTP/2 connection policy.',
        'api.connection.set_mode(Mode.Translate)\napi.connection.http2.enforce_header_table_limit(0)\nreturn api.message.translate()',
        access='staged connection policy')

    def __init__(self, message=None, active=False, instance_mode='message', phase='content'):
        self._message = message
        self._requested = active
        self._instance_mode = instance_mode
        self._phase = phase
        self._rewrite_requested = False
        self.http2 = ConnectionHttp2(self)

    @api_method('', 'None',
                'Reserve rewrite capability before the first payload. Does not modify bytes or activate Translate. Repeated calls are harmless.',
                "if api.phase == 'setup':\n    api.connection.request_rewrite()\n    return\nreturn api.message.commit()",
                availability='Connection-start setup callback only. Easy and Expert require this permission for length changes, hold and Translate. Same-size raw replacements need no reservation and leave protocol consistency to the script.',
                access='staged setup permission')
    def request_rewrite(self):
        if self._phase != 'setup':
            raise CommitException('request_rewrite() is only allowed during connection-start setup')

        self._rewrite_requested = True

    def _transaction(self):
        transaction = getattr(self._message, '_translation', None)

        if transaction is None:
            error = getattr(self._message, '_translation_error', None)
            raise CommitException(error or 'Translate requires an eligible live H2 flow')

        if transaction.result is not None:
            raise CommitException('Set connection policy before message.translate()')

        return transaction

    @api_method('mode: str', 'None',
                'Request Mode.Translate explicitly. Requires flow instantiation and a live eligible connection. Mode.Rewrite is a no-op before activation; an active translated connection cannot revert.',
                'api.connection.set_mode(Mode.Translate)\nreturn api.message.translate()',
                availability='Live flow deployment. The returned translate result activates the mode atomically.',
                access='staged connection mode')
    def set_mode(self, mode):
        if mode == Mode.Rewrite:
            if self._requested:
                raise CommitException('Cannot return a translated connection to Rewrite')
            return

        if mode != Mode.Translate:
            raise CommitException('Expected Mode.Rewrite or Mode.Translate')

        if self._instance_mode != 'flow':
            raise CommitException('Mode.Translate requires flow instantiation')

        self._transaction()
        self._requested = True


class _TranslationSettings:
    """Shared state: a SETTINGS sender constrains the opposite direction.

    Only emitted frames publish state. Ordered ACKs delimit old in-flight
    traffic from traffic using new limits, even while either side holds Parts.
    """

    def __init__(self, saved=None, side='L'):
        import copy

        if side not in ('L', 'R'):
            raise CommitException('Translate requires an L/R side')

        self.side = side
        self.state = copy.deepcopy(saved) if saved is not None else {
            'version': 1,
            'L': {'table': 4096, 'frame': 16384, 'pending': []},
            'R': {'table': 4096, 'frame': 16384, 'pending': []},
        }

        if self.state.get('version') != 1:
            raise CommitException('Unsupported SETTINGS checkpoint')

    @property
    def limits(self):
        return self.state[self.side]

    def process(self, part, *, synthetic=False):
        """Return acknowledged changes for this direction, or None."""
        data = bytes(part._data)
        self.forward_wire = bytes(part._wire)

        if part.stream_id or len(data) % 6 or (part.flags & 1 and data):
            raise CommitException('Invalid SETTINGS frame')

        if part.flags & 1:
            queue = self.limits['pending']

            if not queue:
                raise CommitException('SETTINGS ACK has no pending peer SETTINGS')

            changes = queue.pop(0)

            if changes.get('synthetic'):
                self.forward_wire = b''  # This ACK belongs to our injected SETTINGS.

            for key in ('table', 'frame', 'push'):
                if key in changes:
                    self.limits[key] = changes[key]

            return changes

        changes = {}
        policy = self.state.get('header_limit')
        rewritten = bytearray()
        has_table = False

        for offset in range(0, len(data), 6):
            key = int.from_bytes(data[offset:offset + 2], 'big')
            value = int.from_bytes(data[offset + 2:offset + 6], 'big')

            if key == 1:
                has_table = True

                if not synthetic:
                    self.limits['advertised_table'] = value

                if policy is not None:
                    value = min(value, policy)

                changes['table'] = value
                changes['minimum'] = min(changes.get('minimum', value), value)
            elif key == 5:
                if not 16384 <= value <= 0xffffff:
                    raise CommitException('SETTINGS_MAX_FRAME_SIZE must be 16384..16777215')
                changes['frame'] = value
            elif key == 2:
                if value not in (0, 1) or (self.side == 'R' and value == 1):
                    raise CommitException('Invalid SETTINGS_ENABLE_PUSH')
                changes['push'] = value
            elif key == 4 and value > 0x7fffffff:
                raise CommitException('Invalid SETTINGS_INITIAL_WINDOW_SIZE')

            rewritten.extend(key.to_bytes(2, 'big') + value.to_bytes(4, 'big'))

        if policy is not None and not has_table:
            value = min(policy, self.limits.get('advertised_table', 4096))
            rewritten.extend(b'\x00\x01' + value.to_bytes(4, 'big'))
            changes.update(table=value, minimum=value)

        if policy is not None:
            self.limits['applied_limit'] = policy
            self.forward_wire = _h2_new_frame(4, part.flags, 0, bytes(rewritten)).commit()

        self.limits['settings_seen'] = True

        if synthetic:
            changes['synthetic'] = True

        peer = self.state['R' if self.side == 'L' else 'L']

        if len(peer['pending']) >= 64:
            raise CommitException('Too many unacknowledged SETTINGS frames')

        # Even empty/unknown-only SETTINGS consume one acknowledgment.
        peer['pending'].append(changes)
        return None

    def pending_policy_frame(self):
        """Inject only at a complete frame boundary, after this side's SETTINGS."""
        policy = self.state.get('header_limit')

        if (policy is None or not self.limits.get('settings_seen') or
                self.limits.get('applied_limit') == policy):
            return b''

        value = min(policy, self.limits.get('advertised_table', 4096))
        data = b'\x00\x01' + value.to_bytes(4, 'big')
        part = _h2_new_frame(4, 0, 0, data)
        self.process(part, synthetic=True)
        return self.forward_wire


def _translate_decoder_settings(decoder, changes):
    if changes is None or 'table' not in changes:
        return

    minimum = changes['minimum']
    pending = getattr(decoder, '_translate_minimum', None)

    if minimum < decoder.header_table.maxsize:
        decoder._translate_minimum = minimum if pending is None else min(pending, minimum)

    decoder.max_allowed_table_size = changes['table']


def _translate_decode(decoder, data):
    minimum = getattr(decoder, '_translate_minimum', None)

    if minimum is not None:
        if not data or data[0] & 0xe0 != 0x20:
            raise CommitException('Missing HPACK table-size update after SETTINGS reduction')

        size, _ = _hpack_read_integer(data, 0, 5)

        if size > minimum:
            raise CommitException('HPACK update omitted the smallest acknowledged table size')

    fields = decoder.decode(data, raw=True)
    decoder._translate_minimum = None
    return fields


def _translate_encoder_settings(encoder, changes):
    if changes is None or 'table' not in changes:
        return

    # The encoder may use less than the advertised limit. Keep its own table
    # bounded at 4096; the decoder accepts larger peer tables within quotas.
    encoder.header_table_size = min(changes['minimum'], 4096)
    encoder.header_table_size = min(changes['table'], 4096)
    updates = encoder.table_size_changes

    if updates:
        smallest, final = min(updates), updates[-1]
        encoder.table_size_changes = [smallest] if smallest == final else [smallest, final]
        encoder.header_table.resized = True


def _translate_parts(data, preface=False, settings=None):
    """Frame an established H2 direction, retaining its unfinished last unit.

    This is not protocol detection. Only translate's admitted H2 stream uses
    these boundaries; ordinary rewrite keeps using the supplied annotations.
    """
    parts, cursor = [], 0
    settings = settings or _TranslationSettings()

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

            if size > settings.limits['frame']:
                raise CommitException('Frame exceeds acknowledged SETTINGS_MAX_FRAME_SIZE')

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
        part.max_frame_size = settings.limits['frame']
        parts.append(part)

        if not complete:
            part._translate_fragment = 'frame'
            break

        if part.frame_type == 4:
            settings.process(part)

    return parts


def _resume_translation(message, checkpoint, settings=None):
    """Keep complete held drafts; only rebuild the unfinished physical tail."""
    held, _ = _restore(checkpoint) if checkpoint else ([], {})
    data = message.bytes
    preface = False
    settings = settings or _TranslationSettings()

    # Complete held ACKs precede fresh input and can change its frame limit.
    for part in held:
        if part.complete and part.frame_type == 4:
            settings.process(part)

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

    object.__setattr__(message, 'parts', PartList(held + _translate_parts(data, preface, settings)))


def _translate_table_dump(codec):
    import base64

    table = codec.header_table
    result = {'size': table.maxsize, 'entries': [
        [base64.b64encode(name).decode(), base64.b64encode(value).decode()]
        for name, value in table.dynamic_entries
    ]}

    if hasattr(codec, 'max_allowed_table_size'):
        result['allowed'] = codec.max_allowed_table_size
        result['minimum'] = getattr(codec, '_translate_minimum', None)
    else:
        result['updates'] = list(codec.table_size_changes)

    return result


def _translate_table_load(codec, saved):
    import base64

    size = saved['size']

    if type(size) is not int or not 0 <= size <= 0xffffffff:
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

    if hasattr(codec, 'max_allowed_table_size'):
        codec.max_allowed_table_size = saved.get('allowed', 4096)
        codec._translate_minimum = saved.get('minimum')
    else:
        codec.table_size_changes = list(saved.get('updates', []))
        codec.header_table.resized = bool(codec.table_size_changes)


class _Translation:
    def __init__(self, message, checkpoint, active, control=None, side='L'):
        if _translate_hpack is None:
            raise CommitException('H2 translate requires python-hpack')

        self.message = message
        self.decoder = _translate_hpack.Decoder()
        self.encoder = _translate_hpack.Encoder()
        self.result = None
        self.checkpoint = None
        self.control_checkpoint = None
        self.control_before = _TranslationSettings(control, side).state
        self.settings = _TranslationSettings(control, side)
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
            if part.frame_type == 4:
                _translate_decoder_settings(self.decoder, self.settings.process(part))
            if part.frame_type == 5:
                self._validate_push(part)
            if part.frame_type in (1, 5):
                # PUSH_PROMISE shares this direction's HPACK context with
                # HEADERS, including responses on the promised stream.
                self._decode_headers(part, active)

        object.__setattr__(message, '_body_sizes', {
            id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
            for group in _h2_content_groups(message.parts)
        })

    def _validate_push(self, part):
        """Check push envelope, without pretending to track every stream state."""
        promised = int.from_bytes(part._prefix[-4:], 'big') & 0x7fffffff

        if self.settings.side != 'R' or not self.settings.limits.get('push', 1):
            raise CommitException('PUSH_PROMISE requires server direction and enabled push')

        if not part.stream_id or not part.stream_id & 1 or not promised or promised & 1:
            raise CommitException('PUSH_PROMISE requires a client stream and an even nonzero promised stream')

    def _decode_headers(self, part, active):
        """Resolve source indices without changing the receiver's table."""
        fields = _translate_decode(self.decoder, part.get_bytes())
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
        settings = _TranslationSettings(self.control_before, self.settings.side)

        emitted = message.parts[:cut]

        for part, original in zip(emitted, self.originals):
            if not part.complete:
                raise CommitException('Incomplete H2 part: hold_from(part) before translate')

            if part._initial[0] == 0:
                output.extend(self._translate_data(part, original))
            elif part._initial[0] not in (1, 5):
                if part.commit() != original:
                    raise CommitException('Translate supports header edits and same-length DATA only')

                if part.frame_type == 4:
                    _translate_encoder_settings(encoder, settings.process(part))
                    output.extend(settings.forward_wire)
                else:
                    output.extend(original)

            else:
                if (part.frame_type, part.flags, part.stream_id) != part._initial:
                    raise CommitException('Translate headers must preserve frame type, flags and stream id')

                fields = self._header_fields(part)
                previous_size = part.max_frame_size

                try:
                    part.max_frame_size = min(previous_size, settings.limits['frame'])
                    output.extend(part._assemble(encoder.encode(fields)))
                finally:
                    part.max_frame_size = previous_size

            if len(output) > 1024 * 1024:
                raise CommitException('Translated output exceeds 1 MiB')

        # Appending after the emitted prefix cannot split HEADERS/CONTINUATION.
        # Do not emit around a held boundary: the user explicitly retained it.
        if boundary is None:
            output.extend(settings.pending_policy_frame())

        if len(output) > 1024 * 1024:
            raise CommitException('Translated output exceeds 1 MiB')

        decoder = self.decoder

        if cut < len(message.parts):
            # Views decoded the full input speculatively. Publish only the table
            # after the emitted prefix, so retained blocks are consumed once.
            decoder = _translate_hpack.Decoder()
            _translate_table_load(decoder, self.input_before)
            replay_settings = _TranslationSettings(self.control_before, self.settings.side)

            for part in emitted:
                if part.frame_type == 4:
                    _translate_decoder_settings(decoder, replay_settings.process(part))

                if part.frame_type in (1, 5):
                    _translate_decode(decoder, part._data)

        checkpoint = {
            'version': 1,
            'input': _translate_table_dump(decoder),
            'output': _translate_table_dump(encoder),
        }

        if len(json.dumps(checkpoint)) > 65536:
            raise CommitException('Translate checkpoint exceeds 64 KiB')

        if len(json.dumps(settings.state)) > 16384:
            raise CommitException('SETTINGS checkpoint exceeds 16 KiB')

        result = bytes(output)

        if boundary is not None:
            suffix = message.parts[cut:]
            saved = []

            try:
                for part in suffix:
                    if not part.complete and (part._pending is not None or
                            (part.frame_type, part.flags, part.stream_id) != part._initial):
                        raise CommitException('Cannot hold an edited incomplete H2 part')

                    if part.complete and part.frame_type in (1, 5):
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
        self.control_checkpoint = settings.state
        return self.result

    @staticmethod
    def _translate_data(part, original):
        """Replace only application bytes; preserve flow-control accounting exactly.

        Keep the frame header, pad-length byte and padding verbatim. Reusing the
        generic assembler could split a frame or change its END_STREAM flag.
        """
        if (part.frame_type, part.flags, part.stream_id) != part._initial:
            raise CommitException('Translate DATA must preserve frame type, flags and stream id')

        if part._pending is None:
            return original  # Untouched DATA does not need materialization.

        data = _h2_bytes(part.get_bytes())

        if len(data) != len(part._data):
            raise CommitException('Translate DATA requires the same length; flow-control translation is not supported yet')

        start = 9 + len(part._prefix)
        end = start + len(data)
        return original[:start] + data + original[end:]


def _prepare_translation(message, request):
    active = request.get('translate_active', False)

    if not active and not request.get('translate_allowed', False):
        return

    try:
        control = request.get('translate_control')
        side = request.get('event', {}).get('details', {}).get('info', {}).get('side', 'L')
        settings = _TranslationSettings(control, side)

        if active:
            _resume_translation(message, request.get('held_parts'), settings)
        elif ((message.bytes and _H2_PREFACE.startswith(message.bytes[:len(_H2_PREFACE)])) or
              any(p.is_a(PartType.Http2.Part) for p in message.parts)):
            _resume_translation(message, None, settings)
        transaction = _Translation(message, request.get('translate_state'), active, control, side)
        object.__setattr__(message, '_translation', transaction)
    except Exception as error:
        if active:
            raise CommitException(str(error)) from error

        # A normal rewrite callback must not fail just because it could have
        # chosen translate. Surface this error only if it actually chooses it.
        object.__setattr__(message, '_translation_error', str(error))
