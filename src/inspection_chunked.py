"""HTTP/1 chunked Body and physical chunk views over one owned wire sequence.

Embedded after inspection_hold. Only Header and Body participate in emission;
Body.chunks are nested views, never additional copies in the message stream.
"""


_CHUNK_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_CHUNK_QUOTED = rb'"(?:[\t\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t\x20-\x7e\x80-\xff])*"'
_CHUNK_LINE = re.compile(
    rb'([0-9a-fA-F]{1,8})((?:[ \t]*;[ \t]*' + _CHUNK_TOKEN
    + rb'(?:[ \t]*=[ \t]*(?:' + _CHUNK_TOKEN + rb'|' + _CHUNK_QUOTED + rb'))?)*)')

_FORBIDDEN_TRAILERS = frozenset({
    'authorization', 'cache-control', 'connection', 'content-encoding',
    'content-length', 'content-range', 'content-type', 'host',
    'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
})


class _H1Chunk(RewritePart):
    def __init__(self, wire, data, extension):
        super().__init__(wire, data=data)
        self.type = PartType.Http1.Chunk
        self._extension = extension

    def _assemble(self, header_override=None, *, safety=Safety.Easy):
        data = self.get_bytes()

        if data == self._data:
            return self._wire

        # An empty data chunk would terminate the entire message. Removing a
        # chunk's content therefore removes that chunk, not the final sentinel.
        if not data:
            return b''

        return f'{len(data):x}'.encode() + b'\r\n' + data + b'\r\n'


class H1ChunkedBody(_H1Part):
    """Complete logical body and trailers of one HTTP/1 chunked message."""

    @property
    def trailers(self):
        """Validated trailer fields as an immutable ordered snapshot."""
        return self.get_trailers()

    @api_method('', 'tuple[Header, ...]',
                'Return validated HTTP/1 chunked trailers in wire order. Duplicate names and observed casing are preserved.',
                'if not hasattr(part, "get_trailers"):\n    return None\nfor trailer in part.get_trailers():\n    api.print(trailer.name, trailer.value)',
                availability='On a complete HTTP/1 chunked Body part.',
                access='read private draft')
    def get_trailers(self):
        return tuple(self.group.trailers)

    @api_method('fields: iterable[tuple[str, str]]', 'None',
                'Replace ordered HTTP/1 chunked trailers and repair the Trailer declaration at commit. Duplicate fields are preserved; framing, routing and representation-control fields are rejected.',
                'if not hasattr(part, "replace_trailers"):\n    return None\npart.replace_trailers([("X-Checksum", "complete")])\nreturn api.message.commit()',
                availability='On a complete HTTP/1 chunked Body part.',
                access='edit private draft')
    def replace_trailers(self, fields):
        if not self.complete:
            raise CommitException('Chunked trailers are unavailable until the message is complete')

        replacements = []
        for item in fields:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise CommitException('Each trailer must be a name/value pair')
            name, value = item
            if not isinstance(name, str) or not isinstance(value, str):
                raise CommitException('Trailer names and values must be strings')
            if not _HTTP_TOKEN.fullmatch(name) or _has_control_characters(value):
                raise CommitException('Invalid HTTP trailer')
            if name.lower() in _FORBIDDEN_TRAILERS:
                raise CommitException('Trailer field is required before message completion: ' + name)
            replacements.append(Header(name, value))

        self.group.trailers = replacements

    def get_bytes(self):
        if self._pending is not None:
            return self._pending

        wire = b''.join(chunk.get_bytes() for chunk in self.chunks)
        return _decode_body(self, wire, self._encoding, self.complete)

    def _encoded_bytes(self):
        current = _body_encoding(_header_values(self.group.draft.headers, 'content-encoding'))
        if current != self._encoding:
            raise CommitException('Changing Content-Encoding on a logical Body is not supported')
        wire = b''.join(chunk.get_bytes() for chunk in self.chunks)
        return _encode_body(self, wire, self._pending, self._encoding, self.complete)


class _ChunkedGroup:
    """Incremental framing cursor; checkpoints preserve completed chunk views."""

    def __init__(self, head, data):
        if not head.endswith(b'\r\n\r\n') or len(head) > 65536:
            raise CommitException('Chunked H1 requires a complete head within 64 KiB')

        lines = head[:-4].split(b'\r\n')
        transfer, ordinary, trailers = [], [], []

        for line in lines[1:]:
            name, colon, value = line.partition(b':')

            if (not colon or not _HTTP_TOKEN.fullmatch(name.decode('latin-1'))
                    or _has_control_characters(value.decode('latin-1'))):
                raise CommitException('Invalid HTTP header')

            if name.lower() == b'transfer-encoding':
                transfer.append(value.strip().lower())
            elif name.lower() == b'content-length':
                raise CommitException('Ambiguous Content-Length with Transfer-Encoding')
            elif name.lower() == b'trailer':
                text = value.decode('latin-1').strip()

                if not all(_HTTP_TOKEN.fullmatch(token.strip()) for token in text.split(',')):
                    raise CommitException('Invalid Trailer declaration')

                trailers.append(Header('Trailer', text))
            else:
                ordinary.append(line)

        http11 = lines[0].endswith(b'HTTP/1.1') or lines[0].startswith(b'HTTP/1.1 ')

        if transfer != [b'chunked'] or not http11:
            raise CommitException('H1 Parts require HTTP/1.1 with one chunked transfer coding')

        self.normal_head = b'\r\n'.join([lines[0], *ordinary, b'Content-Length: 0', b'', b''])
        probe = MessageSnapshot(self.normal_head)

        if probe._error:
            raise CommitException(probe._error)

        self.head, self.body = head, b''
        self.draft = probe.http1
        self.draft.headers = [h for h in self.draft.headers if h.name.lower() != 'content-length']
        self.draft.headers.append(Header('Transfer-Encoding', 'chunked'))
        self.draft.headers.extend(trailers)
        self.initial_headers = tuple(self.draft.headers)
        self.initial_start_line = (
            self.draft.target,
            self.draft.method,
            self.draft.status_code,
            self.draft.reason,
            self.draft.http_version,
        )
        self.header = _H1Part(self, True)
        self.content_part = H1ChunkedBody(self, False)
        self.chunk_views = []
        self.cursor, self.finished = 0, False
        self.terminal = b''
        self.trailer_names = []
        self.trailers = []
        self.initial_trailers = ()
        self.feed(data)

    def feed(self, data):
        previous = len(self.body)
        self.body += data

        if len(self.body) + len(self.head) > 1024 * 1024:
            raise CommitException('H1 chunked message exceeds 1 MiB')

        while not self.finished:
            end = self.body.find(b'\r\n', self.cursor)

            if end < 0:
                break

            line = self.body[self.cursor:end]
            match = _CHUNK_LINE.fullmatch(line)

            if match is None:
                raise CommitException('Invalid chunk size or extension')

            size, extension = int(match[1], 16), match[2]

            if size + end + 4 + len(self.head) > 1024 * 1024:
                raise CommitException('H1 chunk exceeds 1 MiB')

            if size == 0:
                trailer_end = self._trailer_end(end + 2)

                if trailer_end is None:
                    break

                self.terminal = self.body[self.cursor:trailer_end]
                self.cursor, self.finished = trailer_end, True
                break

            stop = end + 2 + size

            if len(self.body) < stop + 2:
                break

            if self.body[stop:stop + 2] != b'\r\n':
                raise CommitException('Missing CRLF after chunk data')

            if len(self.chunk_views) >= 8192:
                raise CommitException('H1 chunk count exceeds 8192')

            self.chunk_views.append(_H1Chunk(
                self.body[self.cursor:stop + 2], self.body[end + 2:stop], extension))
            self.cursor = stop + 2

        consumed = self.cursor if self.finished else len(self.body)
        self.body = self.body[:consumed]
        self.content_part._wire = self.body
        self.content_part.chunks = tuple(self.chunk_views)
        self.content_part.complete = self.finished

        for part in (self.header, self.content_part):
            part.content = PartContent(self.finished)

        return consumed - previous

    def _trailer_end(self, start):
        cursor, fields = start, []

        while True:
            end = self.body.find(b'\r\n', cursor)

            if end < 0:
                return None

            if end == cursor:
                self.trailers = fields
                self.initial_trailers = tuple(fields)
                self.trailer_names = [field.name.lower() for field in fields]
                return end + 2

            name, colon, value = self.body[cursor:end].decode('latin-1').partition(':')

            if not colon or not _HTTP_TOKEN.fullmatch(name) or _has_control_characters(value):
                raise CommitException('Invalid chunked trailer')

            fields.append(Header(name, value.strip(' \t')))
            cursor = end + 2

    def assemble(self, *, safety=Safety.Easy):
        if not self.finished:
            raise CommitException('Incomplete chunked content: hold from the header and await more data')

        body = self.content_part

        if tuple(map(id, body.chunks)) != tuple(map(id, self.chunk_views)):
            raise CommitException('Chunk views cannot be removed, replaced or reordered; edit their bytes instead')

        chunk_changes = any(chunk.get_bytes() != chunk._data for chunk in body.chunks)

        if body._pending is not None and chunk_changes:
            raise CommitException('Cannot combine whole-body replacement with chunk edits')

        data = body._encoded_bytes()
        original = b''.join(chunk._data for chunk in body.chunks)
        current_start_line = (
            self.draft.target,
            self.draft.method,
            self.draft.status_code,
            self.draft.reason,
            self.draft.http_version,
        )
        unchanged = (data == original and not chunk_changes and
                     tuple(self.draft.headers) == self.initial_headers and
                     tuple(self.trailers) == self.initial_trailers and
                     current_start_line == self.initial_start_line and
                     not self.draft.body)

        if unchanged:
            return self.head, self.body

        if self.draft.body:
            raise CommitException('Edit content through the H1 Body part, not header.http1.body')

        if (_header_values(self.draft.headers, 'transfer-encoding') != ['chunked']
                or _header_values(self.draft.headers, 'content-length')):
            raise CommitException('Chunked Parts must retain chunked framing without Content-Length')

        declared = []
        declared_lower = set()
        for field in self.trailers:
            lowered = field.name.lower()
            if lowered not in declared_lower:
                declared.append(field.name)
                declared_lower.add(lowered)
        draft_headers = [header for header in self.draft.headers
                         if header.name.lower() != 'trailer']
        if declared:
            draft_headers.append(Header('Trailer', ', '.join(declared)))

        if safety == Safety.Easy and data != original and self.trailers:
            raise CommitException('Body edits with trailers require Expert: trailer dependencies cannot be repaired yet')

        # Reuse snapshot semantic validation/digest repair on the dechunked
        # representation. Framing is restored only after that transaction passes.
        normalized = self.normal_head.replace(b'Content-Length: 0\r\n',
                                              f'Content-Length: {len(original)}\r\n'.encode())
        snapshot = MessageSnapshot(normalized + original)
        _copy_h1_draft(snapshot.http1, self.draft)
        snapshot.http1.headers = [h for h in draft_headers
                                  if h.name.lower() not in ('transfer-encoding', 'trailer')]
        snapshot.http1.body = data
        snapshot._managed_body_encoding = True
        wire = snapshot.commit(safety=safety)
        head = wire.split(b'\r\n\r\n', 1)[0].split(b'\r\n')
        head = [line for line in head if not line.lower().startswith(b'content-length:')]
        head.append(b'Transfer-Encoding: chunked')
        head.extend(f'{h.name}: {h.value}'.encode('latin-1') for h in draft_headers
                    if h.name.lower() == 'trailer')

        trailers_changed = tuple(self.trailers) != self.initial_trailers
        terminal = self.terminal
        if trailers_changed:
            trailer_lines = [
                f'{field.name}: {field.value}'.encode('latin-1')
                for field in self.trailers
            ]
            terminal = b'\r\n'.join([b'0', *trailer_lines, b'', b''])

        if data == original and not chunk_changes and not trailers_changed:
            encoded = self.body
        elif body._pending is not None:
            encoded = (f'{len(data):x}'.encode() + b'\r\n' + data + b'\r\n') if data else b''
            encoded += terminal
        else:
            encoded = b''.join(chunk.commit(safety=safety) for chunk in body.chunks) + terminal

        return b'\r\n'.join([*head, b'', b'']), encoded


class _H1Suspension:
    """Pause an ordered H1 lane while the host owns its retained Parts.

    H1 has no independently publishable streams: id zero names the selected
    direction, and holding a message also holds its entire pipeline suffix.
    Only a later callback of this connection can publish a resumed lane.
    """

    def __init__(self, transaction, request):
        self.transaction = transaction
        self.side = transaction.side
        self.peer = 'R' if self.side == 'L' else 'L'
        self.allowed = request.get('hold_allowed') is True and transaction.reverse_capable
        self.saved = {
            self.side: request.get('held_parts'),
            self.peer: request.get('peer_held_parts'),
        }
        state = transaction.before or {}
        self.paused = dict(state.get('paused', {}))
        self.commands = {}
        self.peer_transaction = None
        self.peer_hold_changed = False
        self.peer_hold_result = None
        self.identities = tuple(id(part) for part in transaction.message.parts)
        self.boundary = None
        self.peer_boundary = None

        # A callback is not permission to publish a previously paused lane.
        # Reassembly has already restored the current lane before this point.
        for side in self.paused:
            if self.saved[side] is None:
                raise CommitException('HTTP/1 suspension lost its retained Parts')

        if self.side in self.paused:
            if not transaction.message.parts:
                raise CommitException('HTTP/1 suspension has no retained Parts')
            transaction.message.parts.hold_from(transaction.message.parts[0])
            self.boundary = transaction.message.parts[0]

    def _check(self, stream, side, *, allow_resuspend=False):
        if type(stream) is not int or stream != 0 or side not in ('L', 'R'):
            raise CommitException('HTTP/1 suspension requires id zero and an L/R side')
        if not self.allowed:
            raise CommitException('HTTP/1 suspension requires hold and content-reverse support')
        if self.transaction.result is not None:
            raise CommitException('HTTP/1 suspension must precede publication')
        if tuple(id(part) for part in self.transaction.message.parts) != self.identities:
            raise CommitException('Cannot suspend or resume reordered HTTP/1 Parts')
        resuspending = allow_resuspend and self.commands.get(side) == 'resume'
        if side in self.commands and not resuspending:
            raise CommitException('Duplicate or out-of-order HTTP/1 suspension command')
        self.check_deadlines()

    def check_deadlines(self):
        if any(deadline <= _suspension_now_ms() for deadline in self.paused.values()):
            raise CommitException('HTTP/1 suspension deadline expired')

    def suspend(self, part, timeout_ms):
        owner = self.transaction
        if self.peer_transaction is not None:
            if any(header is part for _, header, _ in self.peer_transaction._groups()):
                owner = self.peer_transaction
        side = owner.side

        # A pipeline may release its older message and pause a younger one in
        # the same atomic commit. Resumed peer drafts keep their original lane.
        self._check(0, side, allow_resuspend=True)
        if side in self.paused:
            raise CommitException('HTTP/1 direction is already suspended')
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 300000:
            raise CommitException('Suspension timeout must be 1 to 300000 milliseconds')
        message = owner.message
        if not any(header is part for _, header, _ in owner._groups()):
            raise CommitException('Suspend an owned HTTP/1 header Part')
        if message.parts._held_from is not None and message.parts._held_from is not part:
            raise CommitException('HTTP/1 suspension conflicts with an existing hold boundary')
        if self.transaction.termination is not None:
            raise CommitException('Cannot suspend a terminated HTTP/1 connection')

        message.parts.hold_from(part)
        if side == self.side:
            self.boundary = part
        else:
            self.peer_boundary = part
        self.paused[side] = _suspension_now_ms() + timeout_ms
        self.commands[side] = 'suspend'
        return 0

    def suspended_parts(self, stream, side):
        self._check(stream, side)
        if side not in self.paused or self.saved[side] is None:
            raise CommitException('HTTP/1 direction is not suspended by an earlier callback')
        parts, _ = _restore(self.saved[side])
        return tuple(parts)

    def resume(self, stream, side):
        self._check(stream, side)
        if side not in self.paused:
            raise CommitException('HTTP/1 direction is not suspended')

        if side == self.side:
            message = self.transaction.message
        else:
            # Detached native reassembly preserves original framing and body
            # baselines. Never parse retained bytes through the producer again.
            message = Message(b'', 0, {})
            resume_message(message, self.saved[side], {}, ())
            self.peer_transaction = _H1ResponseTransaction(
                message, self.transaction.before, side,
                self.transaction.reverse_capable,
                self.transaction.connection_close_capable,
            )

        # Resuming an incomplete message removes the logical pause, not the
        # ordinary reassembly hold. Only complete prefixes may reach the peer.
        message.parts._held_from = None
        for part in message.parts:
            if isinstance(part, _H1Part) and part.is_header and not part.content.complete:
                message.parts.hold_from(part)
                break

        del self.paused[side]
        self.commands[side] = 'resume'
        return tuple(message.parts)

    def assemble(self, result, checkpoint, reverse, update_content_length, safety):
        """Prepare both lanes before exposing either publication result."""
        if self.transaction.termination is not None:
            # H1 termination closes the connection, including a paused peer
            # lane. Neither its bytes nor its pause may survive that close.
            self.peer_hold_changed = self.saved[self.peer] is not None
            self.peer_hold_result = None
            return b'', self.transaction._dump([]), b''

        self.check_deadlines()

        if self.side in self.paused:
            message = self.transaction.message
            if (message.parts._held_from is not self.boundary or
                    tuple(id(part) for part in message.parts) != self.identities):
                raise CommitException('HTTP/1 suspension boundary was changed')

        peer = self.peer_transaction
        if peer is not None:
            if self.peer in self.paused and peer.message.parts._held_from is not self.peer_boundary:
                raise CommitException('HTTP/1 peer suspension boundary was changed')
            peer.slots = peer._load(checkpoint)
            peer.synchronized = True
            peer_result, checkpoint, peer_reverse = peer._assemble(update_content_length, safety)

            self.peer_hold_result = None
            if isinstance(peer_result, HeldCommit):
                self.peer_hold_result = peer_result.checkpoint
                peer_result = peer_result.prefix

            # Output from the resumed opposite lane is reverse output here.
            # Its local responses travel in this callback's original lane.
            reverse += peer_result
            if peer_reverse:
                if isinstance(result, HeldCommit):
                    result = HeldCommit(result.prefix + peer_reverse, result.checkpoint, result.count)
                else:
                    result += peer_reverse
            self.peer_hold_changed = True

        if self.paused:
            checkpoint = {**checkpoint, 'version': 2, 'paused': dict(self.paused)}
        return result, checkpoint, reverse


class _H1ResponseTransaction:
    """Order local responses with ordinary HTTP/1 pipeline responses.

    The checkpoint contains transport facts only: an origin slot marks a
    request whose upstream response is still due, while a byte slot is a
    complete local response waiting behind an earlier origin request.  The
    worker may disappear between callbacks; no ordering state lives solely in
    Python addon objects.
    """

    _MAX_SLOTS = 4096
    _MAX_QUEUED_BYTES = 512 * 1024
    _FORBIDDEN_FIELDS = frozenset({
        b'connection', b'keep-alive', b'proxy-connection',
        b'trailer', b'transfer-encoding', b'upgrade',
    })
    _FORBIDDEN_TRAILER_FIELDS = _FORBIDDEN_FIELDS | frozenset({
        b'content-length', b'host', b'te',
    })

    def __init__(self, message, checkpoint, side, reverse_capable,
                 connection_close_capable):
        if side not in ('L', 'R'):
            raise CommitException('HTTP/1 response ordering requires an L/R side')

        self.message = message
        self.side = side
        self.reverse_capable = reverse_capable
        self.connection_close_capable = connection_close_capable
        self.before = checkpoint
        self.synchronized = checkpoint is not None
        self.slots = self._load(checkpoint)
        self.local_responses = {}
        self.termination = None
        self.result = None
        self.checkpoint = checkpoint
        self.reverse_output = b''
        self.changed = False
        self.suspension = None

    def has_local_responses(self):
        """Include responses staged against a resumed opposite-lane request."""
        if self.local_responses:
            return True
        peer = None if self.suspension is None else self.suspension.peer_transaction
        return peer is not None and bool(peer.local_responses)

    @staticmethod
    def _termination_reason(reason):
        if not isinstance(reason, str):
            raise CommitException('HTTP/1 termination reason must be text')
        encoded = reason.encode('utf-8')
        if not 1 <= len(encoded) <= 1024:
            raise CommitException(
                'HTTP/1 termination reason must be 1..1024 UTF-8 bytes')
        if _has_control_characters(reason):
            raise CommitException(
                'HTTP/1 termination reason contains a control character')
        return reason

    def stage_termination(self, header, reason):
        """Stage close of only the connection which owns this callback."""
        if self.connection_close_capable is not True:
            raise CommitException(
                'HTTP/1 termination requires connection-close capability')
        if self.termination is not None:
            raise CommitException('HTTP/1 termination was already staged')
        if self.has_local_responses():
            raise CommitException(
                'HTTP/1 termination conflicts with a staged local response')

        candidates = [
            selected
            for _, selected, _ in self._groups()
            if selected.group.draft.method is not None
            or selected.group.draft.status_code is not None
        ]
        if self.suspension is not None and self.suspension.peer_transaction is not None:
            candidates.extend(
                selected for _, selected, _ in self.suspension.peer_transaction._groups())
        if not any(selected is header for selected in candidates):
            raise CommitException(
                'The selected HTTP/1 header is not part of this callback')

        self.termination = {
            'header': header,
            'reason': self._termination_reason(reason),
        }

    @classmethod
    def _load(cls, checkpoint):
        if checkpoint is None:
            return []
        if not isinstance(checkpoint, dict):
            raise CommitException('Unsupported HTTP/1 response-order checkpoint')

        version = checkpoint.get('version')
        fields = {'version', 'slots'}
        if version == 2:
            fields.add('paused')
        if (type(version) is not int or version not in (1, 2) or
                set(checkpoint) != fields or not isinstance(checkpoint['slots'], list)):
            raise CommitException('Unsupported HTTP/1 response-order checkpoint')

        if checkpoint['version'] == 2:
            paused = checkpoint['paused']
            if (not isinstance(paused, dict) or not paused or
                    any(side not in ('L', 'R') or type(deadline) is not int or deadline < 0
                        for side, deadline in paused.items())):
                raise CommitException('Invalid HTTP/1 suspension checkpoint')

        import base64
        slots = []
        for item in checkpoint['slots']:
            if item == 'origin':
                slots.append(None)
                continue
            if not isinstance(item, dict) or set(item) != {'response'}:
                raise CommitException('Invalid HTTP/1 response-order slot')
            try:
                wire = base64.b64decode(item['response'], validate=True)
            except (TypeError, ValueError) as error:
                raise CommitException('Invalid HTTP/1 queued response') from error
            if not wire:
                raise CommitException('An HTTP/1 queued response cannot be empty')
            slots.append(wire)

        cls._validate_slots(slots)
        return slots

    @classmethod
    def _validate_slots(cls, slots):
        if len(slots) > cls._MAX_SLOTS:
            raise CommitException('HTTP/1 response-order queue exceeds 4096 requests')
        queued = sum(len(item) for item in slots if item is not None)
        if queued > cls._MAX_QUEUED_BYTES:
            raise CommitException('Queued HTTP/1 local responses exceed 512 KiB')

    @classmethod
    def _dump(cls, slots):
        import base64
        cls._validate_slots(slots)
        encoded = []
        for item in slots:
            if item is None:
                encoded.append('origin')
            else:
                encoded.append({'response': base64.b64encode(item).decode('ascii')})
        return {'version': 1, 'slots': encoded}

    def _groups(self):
        groups = []
        cursor = 0
        while cursor < len(self.message.parts):
            header = self.message.parts[cursor]
            if (isinstance(header, _H1Part) and header.is_header
                    and cursor + 1 < len(self.message.parts)
                    and self.message.parts[cursor + 1] is header.group.content_part):
                groups.append((cursor, header, header.group.content_part))
                cursor += 2
                continue
            cursor += 1
        return groups

    @staticmethod
    def _fields(fields, *, trailers=False):
        try:
            items = tuple(fields)
        except TypeError as error:
            raise CommitException('Response fields must be an iterable of byte pairs') from error

        copied = []
        size = 0
        forbidden = (_H1ResponseTransaction._FORBIDDEN_TRAILER_FIELDS
                     if trailers else _H1ResponseTransaction._FORBIDDEN_FIELDS)
        for item in items:
            if (not isinstance(item, (tuple, list)) or len(item) != 2
                    or not isinstance(item[0], bytes) or not isinstance(item[1], bytes)):
                raise CommitException('Response fields must be byte pairs')
            name, value = item
            lowered = name.lower()
            if (not name or re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None
                    or lowered in forbidden):
                raise CommitException('Invalid HTTP/1 response field name')
            if _has_control_characters(value.decode('latin-1')):
                raise CommitException('Invalid control byte in response field')
            if lowered != b'content-length':
                copied.append((name, value))
            size += len(name) + len(value) + 4
            if size > 65536:
                raise CommitException('Response fields exceed 64 KiB')
        return tuple(copied)

    @staticmethod
    def _reason(status, reason):
        if reason is None:
            import http
            try:
                reason = http.HTTPStatus(status).phrase
            except ValueError:
                reason = ''
        if not isinstance(reason, str):
            raise CommitException('HTTP/1 response reason must be a string')
        try:
            encoded = reason.encode('latin-1')
        except UnicodeEncodeError as error:
            raise CommitException('HTTP/1 response reason must use Latin-1') from error
        if any(byte < 0x20 or byte == 0x7f for byte in encoded):
            raise CommitException('Invalid HTTP/1 response reason phrase')
        return encoded

    @classmethod
    def _serialize(cls, version, status, reason, headers, body, trailers):
        regular = list(cls._fields(headers))
        trailing = list(cls._fields(trailers, trailers=True))
        regular = [(name, value) for name, value in regular
                   if name.lower() not in (b'trailer', b'transfer-encoding')]
        reason_bytes = cls._reason(status, reason)
        start = version.encode('ascii') + b' ' + str(status).encode('ascii') + b' ' + reason_bytes

        if trailing:
            if version != 'HTTP/1.1':
                raise CommitException('HTTP/1 trailers require HTTP/1.1')
            names = []
            seen = set()
            for name, _ in trailing:
                lowered = name.lower()
                if lowered not in seen:
                    names.append(name)
                    seen.add(lowered)
            regular.append((b'Trailer', b', '.join(names)))
            regular.append((b'Transfer-Encoding', b'chunked'))
            chunks = b''
            if body:
                chunks = f'{len(body):x}'.encode('ascii') + b'\r\n' + body + b'\r\n'
            trailer_lines = b''.join(name + b': ' + value + b'\r\n'
                                     for name, value in trailing)
            payload = chunks + b'0\r\n' + trailer_lines + b'\r\n'
        else:
            regular.append((b'Content-Length', str(len(body)).encode('ascii')))
            payload = body

        head = start + b'\r\n'
        head += b''.join(name + b': ' + value + b'\r\n' for name, value in regular)
        wire = head + b'\r\n' + payload
        if len(wire) > 1024 * 1024:
            raise CommitException('Local HTTP/1 response exceeds 1 MiB')
        return wire

    def stage_local_response(self, request, status, headers, body, trailers, *, reason=None):
        if self.termination is not None:
            raise CommitException(
                'A local response conflicts with staged HTTP/1 termination')
        # A request resumed from an R callback still belongs to the L lane.
        # Its native transaction owns validation and response serialization.
        if self.suspension is not None and self.suspension.peer_transaction is not None:
            peer = self.suspension.peer_transaction
            if request is not None and any(header is request for _, header, _ in peer._groups()):
                peer.stage_local_response(request, status, headers, body, trailers, reason=reason)
                return
        if not self.reverse_capable:
            raise CommitException('Local responses require content-reverse from activation')
        if self.side != 'L':
            raise CommitException('A local response must be staged while publishing a request')
        if type(status) is not int or not 200 <= status <= 599:
            raise CommitException('Local response status must be an integer in 200..599')
        if not isinstance(body, bytes):
            raise CommitException('Local response body must be bytes')

        candidates = []
        for _, header, content in self._groups():
            draft = header.group.draft
            if draft.method is not None and header.content.complete and content.complete:
                candidates.append(header)

        if request is None:
            if len(candidates) != 1:
                raise CommitException(
                    'Local response requires exactly one complete request or an explicit request Part')
            selected = candidates[0]
        else:
            matches = [header for header in candidates if header is request]
            if len(matches) != 1:
                raise CommitException(
                    'The selected request Part is not a complete request in this callback')
            selected = matches[0]

        if id(selected) in self.local_responses:
            raise CommitException('A request can have only one local response')
        draft = selected.group.draft
        wire = self._serialize(
            draft.http_version, status, reason, headers, body, trailers)
        self.local_responses[id(selected)] = wire

    @staticmethod
    def _append_wire(parts, wire):
        part = RewritePart(wire, data=wire)
        parts.append(part)

    def _assemble(self, update_content_length, safety):
        if self.termination is not None:
            # The producer closes the callback-local connection. No current,
            # queued, held, forward, or reverse bytes may escape that decision.
            return b'', self._dump([]), b''

        slots = list(self.slots)
        output_parts = PartList()
        boundary = self.message.parts._held_from
        suppressed = set()

        groups = {index: (header, content)
                  for index, header, content in self._groups()}
        cursor = 0
        reverse = bytearray()
        while cursor < len(self.message.parts):
            # A hold retains the entire suffix, not merely its wire bytes.
            # Do not allocate request slots or consume response slots until
            # these Parts are actually published by a later transaction.
            if self.message.parts[cursor] is boundary:
                suffix = self.message.parts[cursor:]
                if any(id(part) in self.local_responses for part in suffix):
                    raise CommitException(
                        'A local response cannot replace a held request')

                output_parts.extend(suffix)
                break

            group = groups.get(cursor)
            if group is None:
                output_parts.append(self.message.parts[cursor])
                cursor += 1
                continue

            header, content = group
            draft = header.group.draft
            complete = bool(header.content.complete and content.complete)
            local = self.local_responses.get(id(header))

            if draft.method is not None and complete:
                slots.append(local)
                if local is None:
                    output_parts.extend((header, content))
                else:
                    suppressed.update((id(header), id(content)))
                cursor += 2
                continue

            output_parts.extend((header, content))
            if (draft.status_code is not None and draft.status_code >= 200 and complete):
                if not slots and not self.synchronized:
                    # A deployment may attach to an already active connection.
                    # Pass the unpaired prefix through, then synchronize on the
                    # first request observed by this generation.
                    cursor += 2
                    continue
                if not slots or slots[0] is not None:
                    raise CommitException(
                        'An HTTP/1 origin response has no ordered request slot')
                slots.pop(0)
                while slots and slots[0] is not None:
                    self._append_wire(output_parts, slots.pop(0))
            cursor += 2

        if self.side == 'L':
            while slots and slots[0] is not None:
                reverse.extend(slots.pop(0))
        elif slots and slots[0] is not None:
            raise CommitException('A queued local response lost its request-side publication')

        self._validate_slots(slots)
        if boundary is not None:
            if id(boundary) in suppressed:
                raise CommitException('A held request cannot be replaced before it is complete')
            output_parts._held_from = boundary

        private = object.__new__(Message)
        object.__setattr__(private, 'parts', output_parts)
        object.__setattr__(private, '_body_sizes', self.message._body_sizes)
        result = commit_message(private, update_content_length, safety=safety)
        checkpoint = self._dump(slots)
        return result, checkpoint, bytes(reverse)

    def _advance_observed(self, *, allow_publication):
        """Advance ordering for an unchanged/pass-through callback.

        This path never assembles script drafts. It records requests and final
        responses that the proxy will pass through unchanged. If advancing a
        response exposes queued local bytes, publication must switch to the
        normal commit path so those bytes can be inserted atomically.
        """
        slots = list(self.slots)
        for _, header, content in self._groups():
            if not (header.content.complete and content.complete):
                continue
            draft = header.group.draft
            if draft.method is not None:
                slots.append(None)
                continue
            if draft.status_code is None or draft.status_code < 200:
                continue
            if not slots and not self.synchronized:
                continue
            if not slots or slots[0] is not None:
                raise CommitException(
                    'An HTTP/1 origin response has no ordered request slot')
            slots.pop(0)
            if slots and slots[0] is not None and not allow_publication:
                return None
            while slots and slots[0] is not None:
                slots.pop(0)
        return slots

    def requires_publication(self):
        if self.suspension is not None and (self.suspension.paused or self.suspension.commands):
            return True
        if self.termination is not None:
            return True
        return self._advance_observed(allow_publication=False) is None

    def observe_passthrough(self):
        if self.result is not None:
            raise CommitException('HTTP/1 response transaction was already committed')
        if self.termination is not None:
            raise CommitException(
                'HTTP/1 termination requires message.commit() publication')
        slots = self._advance_observed(allow_publication=False)
        if slots is None:
            raise CommitException(
                'Queued HTTP/1 local response requires message.commit() publication')
        checkpoint = self._dump(slots)
        self.checkpoint = checkpoint
        self.changed = checkpoint != self.before
        return checkpoint

    def commit(self, update_content_length=True, *, safety=Safety.Easy):
        if self.result is not None:
            raise CommitException('HTTP/1 response transaction was already committed')
        result, checkpoint, reverse = self._assemble(update_content_length, safety)
        if self.suspension is not None:
            result, checkpoint, reverse = self.suspension.assemble(
                result, checkpoint, reverse, update_content_length, safety)
        self.result = result
        self.checkpoint = checkpoint
        self.reverse_output = reverse
        self.changed = checkpoint != self.before
        return result


def _prepare_h1_responses(message, request):
    """Attach the H1 ordering transaction only to live flow callbacks."""
    instance = request.get('instance', {})
    if instance.get('mode') != 'flow':
        return
    checkpoint = request.get('h1_response_state')
    if (not checkpoint and
            not any(isinstance(part, _H1Part) and part.is_header for part in message.parts)):
        return

    info = request.get('event', {}).get('details', {}).get('info', {})
    reverse_capable = info.get('webhook_control', {}).get('content-reverse') is True
    close_capable = info.get('webhook_control', {}).get('connection-close') is True
    transaction = _H1ResponseTransaction(
        message,
        request.get('h1_response_state'),
        info.get('side', ''),
        reverse_capable,
        close_capable,
    )
    object.__setattr__(message, '_h1_response', transaction)
    transaction.suspension = _H1Suspension(transaction, request)
