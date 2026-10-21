"""Typed inspection views. Field metadata generates the browser reference and completion."""
from __future__ import annotations
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any


def documented(description, example, availability='Always available for a content callback.', *, access='read-only snapshot'):
    return field(metadata={'description': description, 'example': example,
                           'availability': availability, 'access': access})


def api_method(parameters, returns, description, example):
    def decorate(method):
        method.__api_doc__ = {'name': method.__name__, 'type': returns, 'parameters': parameters,
            'description': description, 'example': example, 'availability': 'Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.',
            'access': 'shared storage operation'}
        return method
    return decorate


class StorageBusy(RuntimeError):
    """Storage contention/infrastructure failure, not evidence of a faulty script."""


class StorageNamespace:
    """Explicit shared namespace. Each operation is atomic; a sequence of operations is not a transaction."""
    def __init__(self, storage, name):
        if not isinstance(name, str) or not 1 <= len(name.encode()) <= 128 or '\x00' in name:
            raise ValueError('namespace must be 1–128 UTF-8 bytes without NUL')
        self._storage, self._name = storage, name

    def _operation(self, operation, key, value=None):
        import json
        import math
        import sqlite3
        from contextlib import closing
        if not isinstance(key, str) or not 1 <= len(key.encode()) <= 256 or '\x00' in key:
            raise ValueError('key must be 1–256 UTF-8 bytes without NUL')
        def encode(item):
            encoded = json.dumps(item, allow_nan=False, ensure_ascii=False, separators=(',', ':'))
            if len(encoded.encode()) > 65536:
                raise ValueError('storage value exceeds 64 KiB')
            return encoded
        def increment(previous):
            if type(previous) not in (int, float) or type(value) not in (int, float):
                raise TypeError('increment requires numeric values, not bool')
            result = previous + value
            if isinstance(result, float) and not math.isfinite(result):
                raise ValueError('increment requires finite numbers')
            return result
        if self._storage._directory is None:
            values = self._storage._memory.setdefault(self._name, {})
            if operation == 'get': return json.loads(values[key]) if key in values else value
            if operation == 'delete': return values.pop(key, None) is not None
            result = increment(json.loads(values.get(key, '0'))) if operation == 'increment' else value
            values[key] = encode(result)
            return result if operation == 'increment' else None
        try:
            with closing(self._storage._connect()) as connection:
                connection.execute('BEGIN IMMEDIATE' if operation != 'get' else 'BEGIN')
                row = connection.execute('SELECT value FROM kv WHERE namespace=? AND key=?', (self._name, key)).fetchone()
                if operation == 'get':
                    return json.loads(row[0]) if row else value
                if operation == 'delete':
                    connection.execute('DELETE FROM kv WHERE namespace=? AND key=?', (self._name, key))
                    connection.commit()
                    return row is not None
                result = increment(json.loads(row[0]) if row else 0) if operation == 'increment' else value
                encoded = encode(result)
                connection.execute('INSERT INTO kv(namespace,key,value) VALUES(?,?,?) ON CONFLICT(namespace,key) DO UPDATE SET value=excluded.value',
                                   (self._name, key, encoded))
                count, size = connection.execute('SELECT COUNT(*), COALESCE(SUM(length(CAST(value AS BLOB))+length(CAST(key AS BLOB))+length(CAST(namespace AS BLOB))),0) FROM kv').fetchone()
                if count > 4096 or size > 16 * 1024 * 1024:
                    raise ValueError('shared storage quota exceeded (4096 keys / 16 MiB)')
                connection.commit()
                return result if operation == 'increment' else None
        except (sqlite3.OperationalError, OSError) as error:
            raise StorageBusy(str(error)) from error

    @api_method('key: str, default: Any = None', 'Any', 'Read a JSON value; absent keys return default.',
        'shared = api.storage.namespace("stats")\napi.print(shared.get("responses", 0))')
    def get(self, key: str, default: Any = None) -> Any:
        return self._operation('get', key, default)

    @api_method('key: str, value: Any', 'None', 'Atomically replace one JSON value. Independent of script success.',
        'shared = api.storage.namespace("example")\nshared.set("last_status", {"code": 200})')
    def set(self, key: str, value: Any) -> None:
        self._operation('set', key, value)

    @api_method('key: str', 'bool', 'Atomically remove a key. Returns whether it existed.',
        'shared = api.storage.namespace("example")\napi.print(shared.delete("last_status"))')
    def delete(self, key: str) -> bool:
        return self._operation('delete', key)

    @api_method('key: str, amount: int | float = 1', 'int | float', 'Atomic read-modify-write counter; missing key starts at zero. Use instead of get()+set() when concurrent scripts update counters.',
        'shared = api.storage.namespace("stats")\napi.print(shared.increment("responses", 1))')
    def increment(self, key: str, amount: int | float = 1) -> int | float:
        return self._operation('increment', key, amount)


class SharedStorage:
    """Backend-wide persistent JSON storage shared across scripts. Not a security boundary between trusted scripts."""
    def __init__(self, directory=None):
        self._directory, self._memory = directory, {}

    def _connect(self):
        import os
        import sqlite3
        import stat
        os.makedirs(self._directory, mode=0o700, exist_ok=True)
        if os.path.islink(self._directory):
            raise ValueError('storage directory must not be a symlink')
        filename = os.path.join(self._directory, 'shared.sqlite3')
        fd = os.open(filename, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError('storage must be a regular file')
        finally:
            os.close(fd)
        connection = sqlite3.connect(filename, timeout=0.1)
        try:
            connection.execute('PRAGMA max_page_count=8192')
            connection.execute('CREATE TABLE IF NOT EXISTS kv(namespace TEXT NOT NULL,key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(namespace,key))')
            return connection
        except BaseException:
            connection.close()
            raise

    @api_method('name: str', 'StorageNamespace', 'Select an explicitly named shared namespace. Names are database keys, never file paths.',
        'shared = api.storage.namespace("inspection-stats")\napi.print(shared.increment("callbacks"))')
    def namespace(self, name: str) -> StorageNamespace:
        return StorageNamespace(self, name)


@dataclass(frozen=True)
class InstanceContext:
    """Identity of the current logical instance, not a persistent Python process."""
    mode: str = documented('message, flow or endpoint; ad-hoc preview uses message.', 'api.print(api.instance.mode)')
    key: str = documented('Selected flow/endpoint key; empty for message mode.', 'api.print(api.instance.key)')
    deployment_id: str = documented('Backend deployment id; empty for ad-hoc runs.', 'api.print(api.instance.deployment_id)')
    version: int = documented('Deployed version; zero for ad-hoc runs. New versions have new state.', 'api.print(api.instance.version)')


@dataclass(frozen=True)
class Message:
    """Current webhook content fragment, not necessarily a complete application message."""
    bytes: bytes = documented('Original callback bytes. No decoding or reassembly.', '# Inspect a bounded prefix without assuming text or a complete message.\napi.print(api.message.bytes[:32].hex())')
    size: int = documented('Length of this fragment in bytes.', 'api.print(api.message.size)')


@dataclass(frozen=True)
class ContentMetadata:
    """Metadata reported by the current webhook; not connection history."""
    session_id: str = documented('Connection identifier from event.id; empty if absent.', 'api.print(api.metadata.session_id)')
    side: str = documented('Observed side: L (client), R (server), or empty when absent.', 'if api.metadata.side == "R":\n    api.print("Server fragment", api.message.size)')
    payload_layer: str | None = documented('Reported payload layer, without inferring a protocol.', 'if api.metadata.payload_layer is None:\n    api.print("Payload layer was not reported")\nelse:\n    api.print(api.metadata.payload_layer)', 'None when webhook omits payload_layer.')


@dataclass(frozen=True)
class Header:
    """One decoded HTTP header; order and duplicate names are preserved."""
    name: str = documented('Header name with observed casing.', 'for header in api.http1.headers:\n    if header.name.lower() == "content-type":\n        api.print(header.value)', 'Only on an existing Header; shared by HTTP/1 and HTTP/2.')
    value: str = documented('Decoded display value from Spider; non-printable bytes may appear as \\xNN.', '# Iterate instead of converting to a dict: duplicate fields are preserved.\nfor header in api.http1.headers:\n    api.print(header.name, header.value)', 'Only on an existing Header; shared by HTTP/1 and HTTP/2.')


@dataclass(frozen=True)
class Http1:
    """First complete HTTP/1 head decoded by Spider for this callback. Does not imply a complete body or enumerate pipelined messages."""
    available: bool = documented('True only when http1.parse-head enrichment provides a complete head.', 'if api.http1.available:\n    api.print("Decoded head; body may still be incomplete")\nelse:\n    api.print("No complete HTTP/1 head for this callback")')
    method: str | None = documented('Request method, e.g. GET. No inference from body bytes.', 'api.print(api.http1.method)', 'None for responses or unavailable heads.')
    target: str | None = documented('Request target as decoded by Spider; may contain escaped non-printable bytes.', 'if api.http1.target is not None:\n    api.print(api.http1.method, api.http1.target)  # e.g. GET /search?q=spider', 'None for responses or unavailable heads.')
    status: int | None = documented('HTTP response status code.', 'if api.http1.status is not None and api.http1.status >= 400:\n    api.print("HTTP error", api.http1.status)', 'None for requests or unavailable heads.')
    headers: tuple[Header, ...] = documented('Ordered headers including duplicates. Empty means no fields or unavailable; check available.', 'for header in api.http1.headers:\n    api.print(header.name, header.value)')


@dataclass(frozen=True)
class H2Frame:
    """Frame starting at an observed complete nine-byte frame-header annotation. No guessed boundaries or cross-callback reassembly."""
    offset: int = documented('Frame header offset in api.message.bytes.', 'for frame in api.http2.frames:\n    header = api.message.bytes[frame.offset:frame.offset + 9]\n    api.print(header.hex())', 'When frames is non-empty.')
    length: int = documented('Declared frame payload length, excluding its nine-byte header.', 'for frame in api.http2.frames:\n    api.print("Declared", frame.length, "available", len(frame.payload))')
    type: int = documented('Numeric HTTP/2 frame type; unknown types are preserved.', 'for frame in api.http2.frames:\n    if frame.type == 0:  # DATA; 1 = HEADERS, 9 = CONTINUATION\n        api.print("DATA on stream", frame.stream_id)')
    flags: int = documented('Raw frame flags; their meaning depends on frame type.', 'for frame in api.http2.frames:\n    if frame.type in (0, 1) and frame.flags & 0x01:  # END_STREAM, not SETTINGS ACK\n        api.print("Stream end declared", frame.stream_id, "frame complete:", frame.complete)')
    stream_id: int = documented('HTTP/2 stream ID; zero denotes connection-level frames.', 'for frame in api.http2.frames:\n    api.print(frame.stream_id)')
    complete: bool = documented('Entire declared frame payload is present in this callback. Does not imply a complete HTTP body or stream.', 'for frame in api.http2.frames:\n    if not frame.complete:\n        api.print("Partial frame", frame.stream_id, len(frame.payload), "/", frame.length)')
    payload: memoryview = documented('Read-only slice of the available frame payload, including padding and priority fields.', 'for frame in api.http2.frames:\n    prefix = bytes(frame.payload[:16])  # Explicitly copy only this prefix.\n    api.print(prefix.hex())')
    data: memoryview | None = documented('Unpadded DATA bytes only for a complete, valid DATA frame; otherwise None. Still wire content: gzip is not inflated here.', 'for frame in api.http2.frames:\n    if frame.data is not None:  # An empty DATA slice is valid too.\n        api.print(frame.stream_id, len(frame.data), bytes(frame.data[:16]).hex())')


@dataclass(frozen=True)
class H2HeaderBlock:
    """One complete backend-decoded HPACK block; may be headers, trailers or a PUSH_PROMISE."""
    stream_id: int = documented('Stream ID supplied by the backend decoder.', 'for block in api.http2.header_blocks:\n    api.print(block.stream_id)')
    kind: str = documented('Original backend header-block kind; does not by itself distinguish initial headers from trailers.', 'for block in api.http2.header_blocks:\n    api.print(block.stream_id, block.kind)')
    parent_stream_id: int | None = documented('Parent stream for PUSH_PROMISE, otherwise None.', 'for block in api.http2.header_blocks:\n    if block.parent_stream_id is not None:\n        api.print("Push from", block.parent_stream_id, "promises", block.stream_id)')
    spans_previous_envelopes: bool = documented('Block includes bytes from earlier callbacks; not all bytes are in api.message.', 'for block in api.http2.header_blocks:\n    if block.spans_previous_envelopes:\n        api.print("Decoded using earlier callbacks", block.stream_id)')
    headers: tuple[Header, ...] = documented('Ordered decoded fields, including pseudo-headers and duplicates.', 'for block in api.http2.header_blocks:\n    for header in block.headers:\n        api.print(block.stream_id, header.name, header.value)')


@dataclass(frozen=True)
class Http2:
    """Observed HTTP/2 callback view, not a whole request, stream or connection. Empty header_blocks does not imply no headers on the wire."""
    available: bool = documented('HTTP/2 annotation or complete HPACK enrichment was observed. Does not guarantee decoded headers or complete frames.', 'if api.http2.available and not api.http2.header_blocks:\n    api.print("H2 observed, but no complete decoded header block in this callback")')
    frames: tuple[H2Frame, ...] = documented('Frames with a complete annotated header in this callback, in wire order. Continuation fragments without a header are not guessed.', 'for frame in api.http2.frames:\n    api.print(frame.stream_id, frame.type, frame.complete)')
    header_blocks: tuple[H2HeaderBlock, ...] = documented('All complete HPACK enrichments emitted for this callback, in backend order.', 'for block in api.http2.header_blocks:\n    for header in block.headers:\n        if header.name in (":method", ":path", ":status"):\n            api.print(block.stream_id, header.name, header.value)')


def make_http2(info, payload, enrichments):
    frames, blocks, offsets = [], [], set()
    annotations = info.get('content_annotations', [])
    available = False
    for annotation in annotations:
        if not isinstance(annotation, (list, tuple)) or len(annotation) < 3:
            continue
        start, end, kind = annotation[:3]
        if not isinstance(kind, str) or not kind.startswith('h2.'):
            continue
        available = True
        if (kind != 'h2.frame.header' or type(start) is not int or type(end) is not int
                or not 0 <= start < end <= len(payload) or end - start != 9 or start in offsets):
            continue
        offsets.add(start)
        length = int.from_bytes(payload[start:start + 3], 'big')
        typ, flags = payload[start + 3:start + 5]
        stream = int.from_bytes(payload[start + 5:start + 9], 'big') & 0x7fffffff
        complete = start + 9 + length <= len(payload)
        raw = memoryview(payload)[start + 9:min(start + 9 + length, len(payload))]
        data = None
        if typ == 0 and complete:
            if not flags & 8:
                data = raw
            elif len(raw) and raw[0] < len(raw):
                data = raw[1:len(raw) - raw[0]]
        frames.append(H2Frame(start, length, typ, flags, stream, complete, raw, data))
    for item in enrichments:
        meta = item.get('metadata', {})
        if meta.get('operation') != 'hpack.decode' or meta.get('context') != 'complete':
            continue
        source = meta.get('source', {})
        stream = source.get('stream_id')
        if type(stream) is not int or not 0 < stream < 2**31:
            continue
        blocks.append(H2HeaderBlock(stream, source.get('kind', ''), source.get('parent_stream_id'),
            bool(source.get('spans_previous_envelopes', False)),
            tuple(Header(h['name'], h['value']) for h in meta.get('headers', []))))
    return Http2(available or bool(blocks), tuple(sorted(frames, key=lambda frame: frame.offset)), tuple(blocks))


@dataclass(frozen=True)
class InspectionViews:
    """Typed API v0.3. Protocol views are read-only; state and shared storage are explicitly writable."""
    message: Message = documented('Current content fragment.', 'api.print(api.message.size)')
    metadata: ContentMetadata = documented('Metadata of the current content callback.', 'api.print(api.metadata.side)')
    http1: Http1 = documented('HTTP/1 head supplied by backend enrichment.', 'if api.http1.available:\n    api.print(api.http1.target)')
    http2: Http2 = documented('Read-only HTTP/2 frame slices and decoded HPACK blocks.', 'for block in api.http2.header_blocks:\n    for header in block.headers:\n        api.print(block.stream_id, header.name, header.value)')
    state: dict[str, Any] = documented('JSON object local to this logical instance. Committed after success, discarded on error; 64 KiB maximum. No persistent Python globals.',
        'api.state["seen"] = api.state.get("seen", 0) + 1\napi.print(api.state["seen"])', access='mutable instance state')
    storage: SharedStorage = documented('Persistent shared JSON namespaces across scripts and versions. Writes commit per operation, even if the script later fails.',
        'shared = api.storage.namespace("stats")\napi.print(shared.increment("callbacks"))', access='shared persistent storage')
    instance: InstanceContext = documented('Identity and lifecycle mode of this invocation.', 'api.print(api.instance.mode, api.instance.key, api.instance.version)')


def make_views(event, payload, enrichments):
    info = event.get('details', {}).get('info', {})
    message = next((item.get('metadata', {}).get('message') for item in enrichments
                    if item.get('metadata', {}).get('operation') == 'http1.parse-head'
                    and item.get('metadata', {}).get('context') == 'complete'), None)
    head = message if isinstance(message, dict) else {}
    return InspectionViews(
        Message(payload, len(payload)),
        ContentMetadata(event.get('id', ''), info.get('side', ''), info.get('payload_layer')),
        Http1(bool(head), head.get('method'), head.get('target'), head.get('status'),
              tuple(Header(h['name'], h['value']) for h in head.get('headers', []))),
        make_http2(info, payload, enrichments), {}, SharedStorage(), InstanceContext('message', '', '', 0))


def api_schema():
    """Generate reference directly from runtime dataclasses, types and field comments."""
    types = [InspectionViews, Message, ContentMetadata, Http1, Header, Http2, H2Frame, H2HeaderBlock,
             InstanceContext, SharedStorage, StorageNamespace]
    return {'version': '0.3', 'root': 'InspectionViews', 'types': {
        cls.__name__: {'description': cls.__doc__, 'fields': [
            {'name': f.name, 'type': str(f.type).replace("<class '", '').replace("'>", ''),
             **dict(f.metadata)} for f in (fields(cls) if is_dataclass(cls) else ())],
             'methods': [method.__api_doc__ for method in vars(cls).values() if hasattr(method, '__api_doc__')]}
             for cls in types}}
