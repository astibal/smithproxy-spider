"""Experimental HTTP/1 Parts kernel; not connected to the live webhook yet.

The caller supplies a known HTTP/1 message boundary. This is not protocol sniffing.
The initial slice supports one Content-Length framed message, without compression.
"""
from dataclasses import dataclass

from inspection_api import CommitException, MessageSnapshot, _draft_http1


@dataclass(frozen=True)
class Replace:
    start: int
    length: int
    data: bytes


def assemble(source, changes):
    """Atomic replacements in original coordinates; ascending end wins conflicts."""
    changes = list(changes)
    winners = []

    for change in changes:
        if (not isinstance(change, Replace)
                or type(change.start) is not int or type(change.length) is not int
                or change.start < 0 or change.length < 0
                or change.start + change.length > len(source)
                or not isinstance(change.data, bytes)):
            raise CommitException('Invalid replacement range or bytes')

    for change in sorted(changes, key=lambda item: item.start + item.length):
        end = change.start + change.length
        survivors = []

        for old in winners:
            overlaps = (
                max(old.start, change.start) < min(old.start + old.length, end)
                or old.start == change.start
                or (old.length == 0 and change.start <= old.start < end)
                or (change.length == 0 and old.start <= change.start < old.start + old.length)
            )

            if not overlaps:
                survivors.append(old)

        winners = survivors
        winners.append(change)

    chunks, cursor = [], 0

    for change in sorted(winners, key=lambda item: item.start):
        chunks.extend((source[cursor:change.start], change.data))
        cursor = change.start + change.length

    chunks.append(source[cursor:])
    return b''.join(chunks)


class PartType:
    Opaque = 'opaque'

    class Http1:
        Part = 'http1'
        Header = 'http1.header'
        Body = 'http1.body'


class Part:
    stream_id = 1

    def __init__(self, message, kind, start, length):
        self.message = message
        self.type = kind
        self.start = start
        self.length = length
        self._pending = None

    def is_a(self, kind):
        return self.type == kind or self.type.startswith(kind + '.')

    @property
    def content_complete(self):
        return self.message.content_complete

    @property
    def complete(self):
        return self.type == PartType.Http1.Header or self.content_complete

    def get_bytes(self):
        if self._pending is not None:
            return self._pending

        return self.message.source[self.start:self.start + self.length]

    def set_bytes(self, value):
        if not isinstance(value, bytes):
            raise TypeError('Expected bytes')

        self._pending = value

    def commit(self):
        original = self.message.source[self.start:self.start + self.length]

        if self._pending is None or self._pending == original:
            return ()

        return (Replace(self.start, self.length, self._pending),)


class Http1Message:
    """One known HTTP/1 message; Parts retain identity while body fragments arrive."""
    limit = 1024 * 1024

    def __init__(self, data):
        head, separator, body = data.partition(b'\r\n\r\n')

        if not separator:
            raise CommitException('PoC requires a complete HTTP/1 head')

        lengths = []

        for line in head.split(b'\r\n')[1:]:
            name, colon, value = line.partition(b':')

            if name.lower() == b'content-length':
                lengths.append(value.strip())

        if len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 10:
            raise CommitException('PoC requires exactly one Content-Length')

        self.expected = int(lengths[0])
        self.body_start = len(head) + 4

        if self.expected + self.body_start > self.limit:
            raise CommitException('Held message exceeds 1 MiB')

        # Validate framing before accepting the hold, even with a partial body.
        probe = head + separator + b'\0' * self.expected
        draft, _, error = _draft_http1(probe)

        if error:
            raise CommitException(error)

        if any(h.name.lower() == 'content-encoding' for h in draft.headers):
            raise CommitException('Compressed Parts are not supported yet')

        self.source = b''
        self.parts = [Part(self, PartType.Http1.Header, 0, self.body_start),
                      Part(self, PartType.Http1.Body, self.body_start, 0)]
        self.feed(data)

    @property
    def content_complete(self):
        return len(self.source) == self.body_start + self.expected

    def feed(self, data):
        if len(self.source) + len(data) > self.body_start + self.expected:
            raise CommitException('Trailing bytes or pipelining are not supported yet')

        if self.parts[1]._pending is not None:
            raise CommitException('Cannot extend a body already edited by the script')

        self.source += data
        self.parts[1].length = len(self.source) - self.body_start

    def commit(self):
        if not self.content_complete:
            raise CommitException('Content is incomplete; request need-more')

        header, body = self.parts
        snapshot = MessageSnapshot(self.source)

        if header._pending is not None:
            raise CommitException('Raw header replacement is not supported in this PoC')

        snapshot.http1.body = body.get_bytes()
        snapshot.commit()
        changes = list(body.commit())

        # Preserve all header formatting: only replace the Content-Length value.
        offset = 0

        for line in self.source[:self.body_start].splitlines(keepends=True):
            name, colon, value = line.partition(b':')

            if colon and name.lower() == b'content-length':
                stripped = value.strip()
                start = offset + len(name) + 1 + len(value) - len(value.lstrip())
                replacement = str(len(body.get_bytes())).encode('ascii')

                if len(body.get_bytes()) != int(stripped):
                    changes.append(Replace(start, len(stripped), replacement))

            offset += len(line)

        result = assemble(self.source, changes)
        _, _, error = _draft_http1(result)

        if error or len(result) > self.limit:
            raise CommitException(error or 'Replacement exceeds 1 MiB')

        self.source = result
        self.body_start = result.index(b'\r\n\r\n') + 4
        self.expected = len(result) - self.body_start
        header.length = self.body_start
        body.start, body.length = self.body_start, self.expected
        body._pending = None
        return result
