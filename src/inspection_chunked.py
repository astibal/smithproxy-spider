"""HTTP/1 chunked Body and physical chunk views over one owned wire sequence.

Embedded after inspection_hold. Only Header and Body participate in emission;
Body.chunks are nested views, never additional copies in the message stream.
"""


_CHUNK_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_CHUNK_QUOTED = rb'"(?:[\t\x20\x21\x23-\x5b\x5d-\x7e\x80-\xff]|\\[\t\x20-\x7e\x80-\xff])*"'
_CHUNK_LINE = re.compile(
    rb'([0-9a-fA-F]{1,8})((?:[ \t]*;[ \t]*' + _CHUNK_TOKEN
    + rb'(?:[ \t]*=[ \t]*(?:' + _CHUNK_TOKEN + rb'|' + _CHUNK_QUOTED + rb'))?)*)')


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


class _ChunkedBody(_H1Part):
    def get_bytes(self):
        if self._pending is not None:
            return self._pending

        return b''.join(chunk.get_bytes() for chunk in self.chunks)


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

        if _header_values(probe.http1.headers, 'content-encoding'):
            raise CommitException('Compressed H1 Parts are not supported yet')

        self.head, self.body = head, b''
        self.draft = probe.http1
        self.draft.headers = [h for h in self.draft.headers if h.name.lower() != 'content-length']
        self.draft.headers.append(Header('Transfer-Encoding', 'chunked'))
        self.draft.headers.extend(trailers)
        self.initial_headers = tuple(self.draft.headers)
        self.initial_target = self.draft.target
        self.header = _H1Part(self, True)
        self.content_part = _ChunkedBody(self, False)
        self.chunk_views = []
        self.cursor, self.finished = 0, False
        self.terminal = b''
        self.trailer_names = []
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
        cursor, names = start, []

        while True:
            end = self.body.find(b'\r\n', cursor)

            if end < 0:
                return None

            if end == cursor:
                self.trailer_names = names
                return end + 2

            name, colon, value = self.body[cursor:end].decode('latin-1').partition(':')

            if not colon or not _HTTP_TOKEN.fullmatch(name) or _has_control_characters(value):
                raise CommitException('Invalid chunked trailer')

            names.append(name.lower())
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

        data = body.get_bytes()
        original = b''.join(chunk._data for chunk in body.chunks)
        unchanged = (data == original and not chunk_changes and tuple(self.draft.headers) == self.initial_headers
                     and self.draft.target == self.initial_target and not self.draft.body)

        if unchanged:
            return self.head, self.body

        if self.draft.body:
            raise CommitException('Edit content through the H1 Body part, not header.http1.body')

        if (_header_values(self.draft.headers, 'transfer-encoding') != ['chunked']
                or _header_values(self.draft.headers, 'content-length')):
            raise CommitException('Chunked Parts must retain chunked framing without Content-Length')

        if _header_values(self.draft.headers, 'trailer') != _header_values(self.initial_headers, 'trailer'):
            raise CommitException('Editing Trailer declarations is not supported yet')

        if safety == Safety.Easy and data != original and self.trailer_names:
            raise CommitException('Body edits with trailers require Expert: trailer dependencies cannot be repaired yet')

        # Reuse snapshot semantic validation/digest repair on the dechunked
        # representation. Framing is restored only after that transaction passes.
        normalized = self.normal_head.replace(b'Content-Length: 0\r\n',
                                              f'Content-Length: {len(original)}\r\n'.encode())
        snapshot = MessageSnapshot(normalized + original)
        snapshot.http1.headers = [h for h in self.draft.headers
                                 if h.name.lower() not in ('transfer-encoding', 'trailer')]
        snapshot.http1.target = self.draft.target
        snapshot.http1.body = data
        wire = snapshot.commit(safety=safety)
        head = wire.split(b'\r\n\r\n', 1)[0].split(b'\r\n')
        head = [line for line in head if not line.lower().startswith(b'content-length:')]
        head.append(b'Transfer-Encoding: chunked')
        head.extend(f'{h.name}: {h.value}'.encode('latin-1') for h in self.draft.headers
                    if h.name.lower() == 'trailer')

        if data == original and not chunk_changes:
            encoded = self.body
        elif body._pending is not None:
            encoded = (f'{len(data):x}'.encode() + b'\r\n' + data + b'\r\n') if data else b''
            encoded += self.terminal
        else:
            encoded = b''.join(chunk.commit(safety=safety) for chunk in body.chunks) + self.terminal

        return b'\r\n'.join([*head, b'', b'']), encoded
