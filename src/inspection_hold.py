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
                'Hold this part and everything after it. Return message.commit() in rewrite or message.translate() in translate to publish the prefix and retain the suffix for the next callback.',
                'if api.message.parts:\n    api.message.parts.hold_from(api.message.parts[0])\n    return api.message.commit()',
                availability='Live flow deployment at the end of the enabled chain.', access='mutable hold boundary')
    def hold_from(self, part):
        if not any(item is part for item in self):
            raise CommitException('Hold boundary must belong to message.parts')

        self._held_from = part


class _H1Group:
    """One annotated Content-Length message, retaining head/body meaning."""

    def __init__(self, head, body):
        lengths = []
        for line in head.split(b'\r\n')[1:]:
            name, colon, value = line.partition(b':')

            if colon and name.lower() == b'content-length':
                lengths.append(value.strip())

        if len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 10:
            raise CommitException('H1 Parts require one Content-Length')

        self.expected = int(lengths[0])

        if self.expected + len(head) > 1024 * 1024:
            raise CommitException('H1 message exceeds 1 MiB')

        probe = MessageSnapshot(head + b'\0' * self.expected)

        if probe._error:
            raise CommitException(probe._error)

        if any(h.name.lower() == 'content-encoding' for h in probe.http1.headers):
            raise CommitException('Compressed H1 Parts are not supported yet')

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
        snapshot.http1.headers = list(self.draft.headers)
        snapshot.http1.target = self.draft.target
        snapshot.http1.body = self.content_part.get_bytes()
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


def make_message_parts(data, info, enrichments):
    """H1 boundaries require supplied annotations, never protocol sniffing."""
    annotations = _hold_ranges(info, len(data))
    for start, end in _h1_head_ranges(annotations):
        try:
            head = data[start:end]
            chunked = any(line.split(b':', 1)[0].lower() == b'transfer-encoding'
                          for line in head.split(b'\r\n')[1:])
            group = (_ChunkedGroup if chunked else _H1Group)(head, data[end:])
        except CommitException:
            continue

        parts = [group.header, group.content_part]

        if start:
            parts.insert(0, RewritePart(data[:start], data=data[:start]))

        body_end = end + len(group.body)

        if body_end < len(data):
            parts.append(RewritePart(data[body_end:], data=data[body_end:]))

        return parts

    return make_rewrite_parts(data, info, enrichments)


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
        RewritePart, HpackField, H2Headers, PartContent,
        _H1Part, _H1Group, _ChunkedGroup, _ChunkedBody, _H1Chunk, Http1Draft, Header,
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
            objects[index] = {'type': name, 'fields': {k: encode(v) for k, v in vars(value).items()}}
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


def resume_message(message, checkpoint, info, enrichments):
    held, baselines = _restore(checkpoint)
    old_sizes = {id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
                 for group in _h2_content_groups(held)}
    data, consumed = message.bytes, 0

    if held and isinstance(held[-1], _H1Part) and not held[-1].content.complete:
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
