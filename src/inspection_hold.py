"""Callback-local Parts transactions and bounded, typed hold checkpoints.

Embedded after inspection_h2. Checkpoints contain data only, never pickle/code.
Input enrichment has already run: resuming a draft never feeds the live decoder.
"""

class HeldCommit:
    """Opaque committed prefix plus retained Parts. Return it from the script; do not serialize it yourself."""

    def __init__(self, prefix, checkpoint, count):
        self.prefix = prefix
        self.checkpoint = checkpoint
        self.count = count


class PartList(list):
    """Ordered mutable parts with an explicit suffix hold boundary."""

    def __init__(self, parts=()):
        super().__init__(parts)
        self._held_from = None

    @api_method('part: RewritePart', 'None',
                'Hold this part and everything after it. Return message.commit() in rewrite or message.translate() in translate to publish the prefix and retain the suffix for the next callback. Translate processes RST_STREAM and GOAWAY even inside the suffix, discarding cancelled DATA while preserving HPACK history.',
                'if api.message.parts:\n    api.message.parts.hold_from(api.message.parts[0])\n    return api.message.commit()',
                availability='Live flow deployment at the end of the enabled chain.', access='mutable hold boundary')
    def hold_from(self, part):
        if not any(item is part for item in self):
            raise CommitException('Hold boundary must belong to message.parts')

        self._held_from = part


class _PartHoldBuffers:
    """Bounded Parts queues for one connection direction, indexed by stream.

    This is storage, not a publisher or a wire-protocol interpreter. Translate
    must resolve header drafts before retaining them and encode them against
    its current output state on release. No HPACK table belongs in this store.

    Each callback works on fork(). The owner adopts that candidate only after
    the whole publication succeeds; failed encoding must not consume a queue.
    This helper is deliberately internal until that lifecycle is wired in.
    """

    def __init__(self, *, max_bytes=1024 * 1024, max_streams=128,
                 max_batches=1024, max_parts=8192):
        limits = (max_bytes, max_streams, max_batches, max_parts)
        if any(type(value) is not int or value <= 0 for value in limits):
            raise ValueError('Parts hold limits must be positive integers')

        self._limits = limits
        self._queues = {}
        self.bytes_held = 0
        self.batches_held = 0
        self.parts_held = 0

    @property
    def stream_ids(self):
        return tuple(self._queues)

    @staticmethod
    def _check_stream(stream_id):
        # Zero can name a non-multiplexed exchange. Protocol-specific identity
        # and ordering checks belong to the caller, not this generic store.
        if type(stream_id) is not int or stream_id < 0:
            raise CommitException('Parts hold stream id must be a nonnegative integer')

    def fork(self):
        """Copy queue ownership, sharing only immutable serialized snapshots."""
        from collections import deque

        candidate = _PartHoldBuffers(
            max_bytes=self._limits[0], max_streams=self._limits[1],
            max_batches=self._limits[2], max_parts=self._limits[3],
        )
        candidate._queues = {
            stream: deque(batches) for stream, batches in self._queues.items()
        }
        candidate.bytes_held = self.bytes_held
        candidate.batches_held = self.batches_held
        candidate.parts_held = self.parts_held
        return candidate

    def hold(self, stream_id, parts, body_sizes):
        """Append an isolated typed batch; rejected admission changes nothing."""
        import json
        from collections import deque

        self._check_stream(stream_id)
        if not isinstance(parts, (list, tuple)) or not parts:
            raise CommitException('Parts hold requires a nonempty Parts sequence')
        if any(not isinstance(part, RewritePart) for part in parts):
            raise CommitException('Parts hold accepts only native Parts')
        if len({id(part) for part in parts}) != len(parts):
            raise CommitException('Parts hold cannot contain duplicate Parts')

        # Bound queue metadata as well as payload. Empty DATA and tiny headers
        # must not allow an unlimited number of retained objects or streams.
        max_bytes, max_streams, max_batches, max_parts = self._limits
        if stream_id not in self._queues and len(self._queues) >= max_streams:
            raise CommitException('Parts hold exceeds stream limit')
        if self.batches_held >= max_batches:
            raise CommitException('Parts hold exceeds batch limit')
        if self.parts_held + len(parts) > max_parts:
            raise CommitException('Parts hold exceeds part limit')

        # Reuse the existing data-only checkpoint format. Serialization captures
        # edits and shared body groups without retaining callback-owned objects.
        # Charge the complete representation, including original wire bytes,
        # logical drafts and base64 overhead, rather than just message.size.
        checkpoint = _checkpoint(parts, body_sizes)
        snapshot = json.dumps(checkpoint).encode('utf-8')
        if self.bytes_held + len(snapshot) > max_bytes:
            raise CommitException('Parts hold exceeds byte limit')

        batch = (snapshot, len(parts))
        queue = self._queues.get(stream_id)
        if queue is None:
            queue = deque([batch])
            self._queues[stream_id] = queue
        else:
            queue.append(batch)
        self.bytes_held += len(snapshot)
        self.batches_held += 1
        self.parts_held += len(parts)

    def release(self, stream_id):
        """Return fresh (Parts, body baselines) batches in FIFO order.

        Batches remain distinct: combining message/body groups is Translate's
        responsibility. Releasing a draft is not publishing its bytes.
        """
        import json

        self._check_stream(stream_id)
        queue = self._queues.get(stream_id)
        if queue is None:
            return []

        # Restore everything before removing anything. A decoding/allocation
        # failure cannot silently consume part of the suspended stream.
        restored = []
        for snapshot, _ in queue:
            restored.append(_restore(json.loads(snapshot)))
        self.discard(stream_id)
        return restored

    def discard(self, stream_id):
        """Forget one stream without encoding or releasing any of its Parts."""
        self._check_stream(stream_id)
        queue = self._queues.pop(stream_id, None)
        if queue is None:
            return False

        for snapshot, count in queue:
            self.bytes_held -= len(snapshot)
            self.batches_held -= 1
            self.parts_held -= count
        return True

    def checkpoint(self):
        """Export data only; neither callers nor the host receive live queues."""
        import json
        return {
            'version': 1,
            'streams': [
                {'id': stream, 'batches': [json.loads(snapshot) for snapshot, _ in queue]}
                for stream, queue in self._queues.items()
            ],
        }

    @classmethod
    def from_checkpoint(cls, checkpoint, **limits):
        """Restore through normal admission, so saved state cannot bypass limits."""
        import json
        result = cls(**limits)
        if checkpoint is None:
            return result
        if (not isinstance(checkpoint, dict) or checkpoint.get('version') != 1 or
                not isinstance(checkpoint.get('streams'), list)):
            raise CommitException('Invalid Parts buffer checkpoint')
        if len(json.dumps(checkpoint).encode('utf-8')) > result._limits[0] + 65536:
            raise CommitException('Parts buffer checkpoint exceeds byte limit')
        for entry in checkpoint['streams']:
            if (not isinstance(entry, dict) or 'id' not in entry or
                    not isinstance(entry.get('batches'), list)):
                raise CommitException('Invalid Parts buffer stream')
            stream = entry['id']
            result._check_stream(stream)
            if stream in result.stream_ids or not entry['batches']:
                raise CommitException('Duplicate or empty Parts buffer stream')
            for batch in entry['batches']:
                parts, body_sizes = _restore(batch)
                result.hold(stream, parts, body_sizes)
        return result


def _body_encoding(values):
    """Keep unsupported/stacked codings opaque until logical access is requested."""
    return ','.join(values).strip().lower()


def _decode_body(owner, wire, encoding, complete):
    if not encoding or encoding == 'identity':
        return wire

    if not complete:
        raise CommitException('Compressed body is incomplete: hold and await complete content')

    cached = getattr(owner, '_decoded_body', None)
    if cached is not None and cached[:2] == (encoding, wire):
        return cached[2]

    if encoding not in ('gzip', 'deflate'):
        raise CommitException('Logical Body supports only one gzip or zlib-wrapped deflate coding')

    import zlib
    try:
        decoder = zlib.decompressobj(31 if encoding == 'gzip' else 15)
        plain = decoder.decompress(wire, 1024 * 1024 + 1)
    except zlib.error as error:
        raise CommitException('Invalid compressed body: ' + str(error)) from error

    if len(plain) > 1024 * 1024 or decoder.unconsumed_tail:
        raise CommitException('Decoded body exceeds 1 MiB')
    if not decoder.eof or decoder.unused_data:
        raise CommitException('Truncated compressed body, trailing bytes or multiple gzip members')

    owner._decoded_body = (encoding, wire, plain)
    return plain


def _encode_body(owner, original, plain, encoding, complete):
    """No edit means no decode, no allocation of a decoder, and exact wire reuse."""
    if plain is None:
        return original

    if not encoding or encoding == 'identity':
        return plain

    if plain == _decode_body(owner, original, encoding, complete):
        return original

    import zlib
    encoder = zlib.compressobj(wbits=31 if encoding == 'gzip' else 15)
    return encoder.compress(plain) + encoder.flush()


def _copy_h1_draft(target, source):
    """Copy semantic HTTP/1 fields without sharing the mutable header list."""
    target.headers = list(source.headers)
    target.target = source.target
    target.method = source.method
    target.status_code = source.status_code
    target.reason = source.reason
    target.http_version = source.http_version


class _H1Group:
    """One annotated Content-Length message, retaining head/body meaning."""

    def __init__(self, head, body):
        lengths = []
        for line in head.split(b'\r\n')[1:]:
            name, colon, value = line.partition(b':')

            if colon and name.lower() == b'content-length':
                lengths.append(value.strip())

        if len(lengths) > 1:
            raise CommitException('H1 Parts require unambiguous Content-Length framing')
        if lengths and (not lengths[0].isdigit() or len(lengths[0]) > 10):
            raise CommitException('H1 Parts require a valid Content-Length')

        self.expected = int(lengths[0]) if lengths else 0

        if self.expected + len(head) > 1024 * 1024:
            raise CommitException('H1 message exceeds 1 MiB')

        probe = MessageSnapshot(head + b'\0' * self.expected)

        if probe._error:
            raise CommitException(probe._error)

        self.head, self.body = head, body[:self.expected]
        self.draft = probe.http1
        # Do not retain the synthetic validation body in a checkpoint.
        self.draft.body = b''
        self.header = _H1Part(self, True)
        self.content_part = _H1Part(self, False)
        self.refresh()

    def refresh(self):
        complete = len(self.body) == self.expected
        for part in (self.header, self.content_part):
            part.content = PartContent(complete)
        self.content_part.complete = complete
        self.content_part._data = self.body
        self.content_part._wire = self.body

    def assemble(self, *, safety=Safety.Easy):
        if len(self.body) != self.expected:
            raise CommitException('Incomplete H1 content: hold from the header and await more data')

        if self.draft.body:
            raise CommitException('Edit content through the H1 Body part, not header.http1.body')

        snapshot = MessageSnapshot(self.head + self.body)
        _copy_h1_draft(snapshot.http1, self.draft)
        snapshot.http1.body = self.content_part._encoded_bytes()
        snapshot._managed_body_encoding = True
        wire = snapshot.commit(safety=safety)
        boundary = wire.index(b'\r\n\r\n') + 4
        return wire[:boundary], wire[boundary:]


class _H1Part(RewritePart):
    def __init__(self, group, header):
        data = group.head if header else group.body
        super().__init__(data, data=data)
        self.group, self.is_header = group, header
        self.type = PartType.Http1.Header if header else PartType.Http1.Body
        self.http1 = group.draft if header else None
        self._encoding = _body_encoding(_header_values(group.draft.headers, 'content-encoding'))

    def get_bytes(self):
        if self.is_header or self._pending is not None:
            return super().get_bytes()
        return _decode_body(self, self._data, self._encoding, self.complete)

    def _encoded_bytes(self):
        current = _body_encoding(_header_values(self.group.draft.headers, 'content-encoding'))
        if current != self._encoding:
            raise CommitException('Changing Content-Encoding on a logical Body is not supported')
        return _encode_body(self, self._data, self._pending, self._encoding, self.complete)

    def _assemble(self, header_override=None, *, safety=Safety.Easy):
        if self.is_header and self._pending is not None:
            raise CommitException('Use part.http1 for header edits, not raw header replacement')
        return self.group.assemble(safety=safety)[0 if self.is_header else 1]


def _hold_ranges(info, size):
    result = []
    for item in info.get('content_annotations', []):
        if not isinstance(item, (list, tuple)) or len(item) < 3:
            continue
        a, b, kind = item[:3]
        if type(a) is int and type(b) is int and isinstance(kind, str) and 0 <= a < b <= size:
            result.append((a, b, kind))
    return result


class _H1PendingHeader(RewritePart):
    """Annotated header prefix retained through the ordinary Parts checkpoint."""

    def __init__(self, wire, annotations):
        super().__init__(wire, data=wire, complete=False)
        self.type = 'http1.header'
        self._annotations = annotations

    def _assemble(self, header_override=None, *, safety=Safety.Easy):
        raise CommitException('Incomplete H1 header: hold and await more content')


def _pending_h1_header(data, annotations, start):
    # Only producer-owned, contiguous header ranges admit a pending H1 Part.
    # Opaque bytes never become HTTP merely because they resemble a request.
    ranges = []
    cursor = start
    for begin, end, kind in annotations:
        if begin < start:
            continue
        if begin != cursor or kind not in ('http1.start_line', 'http1.headers'):
            break
        if not ranges and kind != 'http1.start_line':
            break
        if ranges and ranges[-1][2] == 'http1.headers' and kind == 'http1.start_line':
            break
        ranges.append((begin - start, end - start, kind))
        cursor = end

    if not ranges or cursor != len(data):
        return None

    wire = data[start:]
    if b'\r\n\r\n' in wire or b'\n\n' in wire:
        return None
    if len(wire) > 65536:
        raise CommitException('Incomplete H1 header exceeds 64 KiB')

    return _H1PendingHeader(wire, ranges)


def make_message_parts(data, info, enrichments):
    """H1 boundaries require supplied annotations, never protocol sniffing."""
    annotations = _hold_ranges(info, len(data))
    parts = []
    cursor = 0
    for start, end in _h1_head_ranges(annotations):
        if start < cursor:
            continue
        try:
            head = data[start:end]
            chunked = any(line.split(b':', 1)[0].lower() == b'transfer-encoding'
                          for line in head.split(b'\r\n')[1:])
            group = (_ChunkedGroup if chunked else _H1Group)(head, data[end:])
        except CommitException:
            continue

        if start > cursor:
            prefix = data[cursor:start]
            parts.append(RewritePart(prefix, data=prefix))
        parts.extend((group.header, group.content_part))
        body_end = end + len(group.body)
        cursor = body_end

        if not group.content_part.complete:
            break

    if cursor < len(data):
        pending = _pending_h1_header(data, annotations, cursor)
        if pending is not None:
            parts.append(pending)
            cursor = len(data)

    if not parts:
        return make_rewrite_parts(data, info, enrichments)
    if cursor < len(data):
        suffix = data[cursor:]
        parts.append(RewritePart(suffix, data=suffix))

    return parts


def _h1_head_ranges(annotations):
    """Match adjacent annotations without rescanning the list for every start."""
    headers_by_start = {}

    for start, end, kind in annotations:
        if kind == 'http1.headers':
            headers_by_start.setdefault(start, []).append(end)

    # Preserve annotation order, including multiple candidate header ranges.
    for start, end, kind in annotations:
        if kind == 'http1.start_line':
            for header_end in headers_by_start.get(end, ()):
                yield start, header_end


def _checkpoint_types():
    """Both directions use the same closed set of data-only checkpoint types."""
    classes = (
        RewritePart, HpackField, H2Headers, PartContent, _H1PendingHeader,
        _H1Part, _H1Group, _ChunkedGroup, H1ChunkedBody, _H1Chunk, Http1Draft, Header,
    )
    return {cls.__name__: cls for cls in classes}


def _checkpoint(parts, body_sizes):
    """Explicit type whitelist plus object references preserves shared H1 groups."""
    import base64
    import json
    allowed = _checkpoint_types()
    objects, seen = [], {}

    def encode(value):
        if value is None or type(value) in (bool, int, str):
            return value
        if isinstance(value, (bytes, memoryview)):
            return {'bytes': base64.b64encode(value).decode()}
        if type(value) in (list, tuple):
            return {'tuple' if isinstance(value, tuple) else 'list': [encode(v) for v in value]}
        name = type(value).__name__
        if name not in allowed or type(value) is not allowed[name]:
            raise CommitException('Unsupported value in held part')
        identity = id(value)
        if identity not in seen:
            index = len(objects)
            seen[identity] = index
            objects.append(None)
            objects[index] = {'type': name, 'fields': {
                k: encode(v) for k, v in vars(value).items() if k != '_decoded_body'}}
        return {'ref': seen[identity]}

    root = encode(list(parts))
    # Preserve dependency baselines too: removing/reordering DATA before a hold
    # must still trigger Content-Length repair after the next callback.
    sizes = {str(seen[id(group[0])]): body_sizes.get(id(group[0]))
             for group in _h2_content_groups(parts)}
    checkpoint = {'version': 1, 'root': root, 'objects': objects, 'body_sizes': sizes}
    if len(json.dumps(checkpoint).encode()) > 1024 * 1024:
        raise CommitException('Serialized hold exceeds 1 MiB')
    return checkpoint


def _restore(checkpoint):
    import base64
    allowed = _checkpoint_types()
    if checkpoint.get('version') != 1:
        raise CommitException('Unsupported hold checkpoint version')
    definitions = checkpoint['objects']
    objects = [object.__new__(allowed[item['type']]) for item in definitions]

    def decode(value):
        if not isinstance(value, dict):
            return value
        if 'bytes' in value:
            return base64.b64decode(value['bytes'], validate=True)
        if 'ref' in value:
            return objects[value['ref']]
        if 'tuple' in value:
            return tuple(decode(v) for v in value['tuple'])
        return [decode(v) for v in value['list']]

    for obj, definition in zip(objects, definitions):
        for key, value in definition['fields'].items():
            object.__setattr__(obj, key, decode(value))
    sizes = {id(objects[int(index)]): value for index, value in checkpoint.get('body_sizes', {}).items()}
    return decode(checkpoint['root']), sizes


def _resume_h1_body(part, data):
    group = part.group

    if group.content_part._pending is not None:
        raise CommitException('Cannot append input to an already edited incomplete H1 body')

    if isinstance(group, _ChunkedGroup):
        return group.feed(data)

    consumed = min(len(data), group.expected - len(group.body))
    group.body += data[:consumed]
    group.refresh()
    return consumed


def _remaining_parts(message, consumed, info, enrichments):
    """Rebase callback-local annotations after consuming a held continuation."""
    if not consumed:
        return message.parts

    remaining_info = dict(info)
    remaining_info['content_annotations'] = [
        [start - consumed, end - consumed, kind]
        for start, end, kind in _hold_ranges(info, len(message.bytes))
        if start >= consumed
    ]
    adjusted = []

    for item in enrichments:
        meta = item.get('metadata', {})
        source = meta.get('source', {})

        if 'payload_offset' in source:
            source = {**source, 'payload_offset': source['payload_offset'] - consumed}
            meta = {**meta, 'source': source}

        adjusted.append({**item, 'metadata': meta})

    return make_message_parts(message.bytes[consumed:], remaining_info, adjusted)


def _resume_h1_header(part, data, info):
    if part._pending is not None:
        raise CommitException('Cannot append input to an edited incomplete H1 header')

    old = bytes(part._wire)
    annotations = list(part._annotations)
    for start, end, kind in _hold_ranges(info, len(data)):
        start += len(old)
        end += len(old)
        if annotations and annotations[-1][1] == start and annotations[-1][2] == kind:
            begin, _, _ = annotations[-1]
            annotations[-1] = (begin, end, kind)
        else:
            annotations.append((start, end, kind))

    # Rebuild native Parts from retained producer boundaries. This does not
    # replay input through the producer or introduce a facade HTTP parser.
    combined = old + data
    header_end = combined.find(b'\r\n\r\n')
    header_size = len(combined) if header_end < 0 else header_end + 4
    if header_size > 65536:
        raise CommitException('Incomplete H1 header exceeds 64 KiB')

    result = make_message_parts(combined, {'content_annotations': annotations}, ())
    if not result or result[0].type != 'http1.header':
        raise CommitException('Held H1 header has no valid annotated continuation')
    return result


def resume_message(message, checkpoint, info, enrichments):
    held, baselines = _restore(checkpoint)
    old_sizes = {id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
                 for group in _h2_content_groups(held)}
    data, consumed = message.bytes, 0

    if held and isinstance(held[-1], _H1PendingHeader):
        if data:
            held[-1:] = _resume_h1_header(held[-1], data, info)
            consumed = len(data)
    elif held and isinstance(held[-1], _H1Part) and not held[-1].content.complete:
        consumed = _resume_h1_body(held[-1], data)
    elif held and not held[-1].complete and held[-1].frame_type is not None:
        part = held[-1]
        if part._pending is not None:
            raise CommitException('Cannot append input to an already edited incomplete H2 part')
        old = bytes(part._wire)
        combined = old + data
        annotations, offset = [], 0
        while offset + 9 <= len(old):
            annotations.append([offset, offset + 9, 'h2.frame.header'])
            offset += 9 + int.from_bytes(old[offset:offset + 3], 'big')
        annotations += [[a + len(old), b + len(old), kind]
                        for a, b, kind in _hold_ranges(info, len(data))]
        # The live decoder already completed this block. Attach its result to
        # the held origin locally; never run HPACK a second time on old bytes.
        local = []
        source_stream = part._initial[2]
        if part.frame_type == 5 and len(part._prefix) >= 4:
            source_stream = int.from_bytes(part._prefix[-4:], 'big') & 0x7fffffff
        for item in enrichments:
            meta = item.get('metadata', {})
            source = meta.get('source', {})
            if (meta.get('operation') == 'hpack.decode' and 'payload_offset' not in source
                    and source.get('stream_id') == source_stream):
                local.append({'metadata': {**meta, 'source': {**source, 'payload_offset': 0}}})
        parsed = make_rewrite_parts(combined, {'content_annotations': annotations}, local)[0]
        consumed = len(parsed._wire) - len(old)
        if consumed < 0:
            raise CommitException('Held H2 boundary cannot be continued')
        flags, stream = part.flags, part.stream_id
        part.__dict__.update(vars(parsed))
        part.flags, part.stream_id = flags, stream

    fresh = _remaining_parts(message, consumed, info, enrichments)
    object.__setattr__(message, 'parts', PartList(held + list(fresh)))

    # Add only newly received bytes to the original dependency baseline.
    # Draft edits made before a hold must remain visible to length repair.
    sizes = {
        id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
        for group in _h2_content_groups(message.parts)}
    for head, original in baselines.items():
        if head in sizes:
            sizes[head] = None if original is None else original + sizes[head] - old_sizes.get(head, 0)
    object.__setattr__(message, '_body_sizes', sizes)


def commit_message(message, update_content_length=True, *, safety=Safety.Easy):
    boundary = message.parts._held_from

    if boundary is None:
        return commit_rewrite_message(message, update_content_length, safety=safety)

    positions = [i for i, part in enumerate(message.parts) if part is boundary]

    if len(positions) != 1:
        raise CommitException('Hold boundary was removed or duplicated')

    cut = positions[0]

    if any(not isinstance(p, RewritePart) for p in message.parts):
        raise CommitException('Expected Parts in hold buffer')

    if len({id(p) for p in message.parts}) != len(message.parts):
        raise CommitException('A part cannot be held or emitted twice')

    checkpoint = _checkpoint(message.parts[cut:], message._body_sizes)

    # Private prefix view: a failed assembly leaves the caller's list intact.
    prefix = object.__new__(Message)
    object.__setattr__(prefix, 'parts', message.parts[:cut])
    object.__setattr__(prefix, '_body_sizes', message._body_sizes)
    wire = commit_rewrite_message(prefix, update_content_length, safety=safety)
    import json

    if len(json.dumps(checkpoint)) + (len(wire) + 2) // 3 * 4 > 1536 * 1024:
        raise CommitException('Combined prefix and hold exceed worker response budget')

    return HeldCommit(wire, checkpoint, len(message.parts) - cut)
