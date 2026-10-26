"""Typed inspection views. Field metadata generates the browser reference and completion."""
from __future__ import annotations
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any
import re
import base64
import hashlib


class Safety:
    """Commit safety, independent of Rewrite/Translate and never persisted implicitly."""
    Easy = 'easy'
    Expert = 'expert'


def _validate_safety(safety):
    if safety not in (Safety.Easy, Safety.Expert) or not isinstance(safety, str):
        raise CommitException('Expected Safety.Easy or Safety.Expert')


_SAME_SAFETY = 'This member has the same behavior in both modes. It does not select or persist commit safety.'


def documented(description, example, availability='Always available for a content callback.', *, access='read-only snapshot',
               easy=_SAME_SAFETY, expert=_SAME_SAFETY):
    return field(metadata={'description': description, 'example': example,
                           'availability': availability, 'access': access, 'easy': easy, 'expert': expert})


def api_method(parameters, returns, description, example, *,
               availability='Backend scripts, including Run on selected, use persistent storage. Standalone make_views examples use temporary memory.',
               access='shared storage operation', easy=_SAME_SAFETY, expert=_SAME_SAFETY):
    def decorate(method):
        method.__api_doc__ = {'name': method.__name__, 'type': returns, 'parameters': parameters,
            'description': description, 'example': example, 'availability': availability,
            'access': access, 'easy': easy, 'expert': expert}
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


@dataclass(frozen=True, init=False)
class Message:
    """Current webhook content fragment, not necessarily a complete application message."""
    bytes: bytes = documented('Original callback bytes. No decoding or reassembly.', '# Inspect a bounded prefix without assuming text or a complete message.\napi.print(api.message.bytes[:32].hex())')
    size: int = documented('Length of this fragment in bytes.', 'api.print(api.message.size)')
    parts: PartList = documented('Ordered drafts, including resumed held parts. hold_from(part) retains a suffix when the committed result is returned.', 'for part in api.message.parts:\n    if part.headers is not None:\n        part.headers.set_header(b"x-test", b"yes")\nreturn api.message.commit()', access='mutable rewrite draft')

    def __init__(self, data, size, info=None, enrichments=()):
        object.__setattr__(self, 'bytes', data)
        object.__setattr__(self, 'size', size)
        parts = PartList(make_message_parts(data, info or {}, enrichments))
        object.__setattr__(self, 'parts', parts)
        sizes = {id(group[0]): sum(len(p._data) for p in group if p.frame_type == 0)
                 for group in _h2_content_groups(parts)}
        object.__setattr__(self, '_body_sizes', sizes)

    @api_method('', 'tuple[RewritePart | H2Body, ...]',
                'Return H1 Body parts and logical H2 body views in header order. H2 views reference existing DATA parts; never append them to message.parts. Reacquire views after changing the parts list.',
                'for body in api.message.bodies():\n    if body.complete:\n        api.print(body.stream_id, len(body.get_bytes()))', access='views of mutable drafts',
                easy='H2 whole-body edits require complete known content and unedited DATA drafts. Commit repairs known Content-Length.',
                expert='The same view rules apply. Translate resizing requires negotiated content-reverse support and retained Content-Length headers, in both safety modes.')
    def bodies(self):
        groups = {id(group[0]): group for group in _h2_content_groups(self.parts)}
        return tuple(
            H2Body(groups[id(part)]) if id(part) in groups else part
            for part in self.parts
            if id(part) in groups or part.type == PartType.Http1.Body
        )

    @api_method('update_content_length: bool = True, *, safety: str = Safety.Easy', 'bytes | HeldCommit',
                'Assemble the emitted Parts atomically and checkpoint any held suffix. Recalculate known Content-Length; update_content_length=False disables H2 repair only (H1 typed assembly always recalculates it). Incomplete emitted content raises CommitException. Return the result to publish it. No future-message translation.',
                'return api.message.commit()', access='assemble private draft',
                easy='Default. Repair supported H1 Content-Digest (sha-256/sha-512 without parameters) and apply remaining H1 metadata guards and H2 frame-size guards. This is not full protocol validation.',
                expert='Allow H1 integrity/range/signature inconsistency and representable oversized H2 control frames. Supported H1 Content-Digest and Content-Length are still repaired, including managed Body coding; unsupported digests remain unchanged. Keep coding guards, quotas, atomicity and unambiguous framing.')
    def commit(self, update_content_length=True, *, safety=Safety.Easy):
        try:
            _validate_safety(safety)
            return commit_message(self, update_content_length, safety=safety)
        except CommitException:
            raise
        except (ValueError, TypeError, AttributeError, OverflowError) as error:
            raise CommitException(str(error)) from error

    @api_method('*, safety: str = Safety.Easy', 'bytes | HeldCommit',
                'Explicitly translate every callback of a pinned H2 flow. With content-reverse capability from activation, DATA resizing uses bounded directional queues and independent flow-control windows; legacy peers allow same-length DATA only. Hold incomplete Parts explicitly. No silent background runs.',
                'if api.instance.mode == "flow":\n    return api.message.translate()',
                availability='First observed content of a new flow, sole enabled deployment; every callback thereafter.',
                access='assemble translated output',
                easy='Require complete emitted frames, coherent HPACK state, unchanged frame identity and explicit callbacks. Resizing repairs retained Content-Length for complete content; already emitted lengths cannot be repaired. Pending output is limited to 384 KiB and 1024 live stream records per direction. Closed IDs use bounded compressed ranges. Full lifecycle and H2 digest repair are not provided.',
                expert='The same Translate invariants and quotas apply. Expert cannot bypass credit, retained Content-Length or capability requirements. RST_STREAM and GOAWAY cancel affected queued DATA while preserving encoded headers and HPACK ordering; use Rewrite for state-breaking experiments.')
    def translate(self, *, safety=Safety.Easy):
        _validate_safety(safety)
        transaction = getattr(self, '_translation', None)
        if transaction is None:
            raise CommitException(getattr(self, '_translation_error',
                'Translate requires a live flow deployment and a strict-control capable proxy'))
        return transaction.translate()

    @api_method('', 'MessageSnapshot', 'Create an independent editable draft of this callback. No live bytes change until the script returns draft.commit().',
        'draft = api.message.snapshot()\napi.print(draft.http1.available)',
        availability='Always available; HTTP/1 editing requires one complete supported message.', access='create private draft')
    def snapshot(self) -> MessageSnapshot:
        return MessageSnapshot(self.bytes)


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


class CommitException(Exception):
    """Draft cannot be assembled safely. Original bytes are unchanged; fix the draft and retry, or return None. Available directly in script scope."""


_DRAFT_EXAMPLE = ('draft = api.message.snapshot()\nif draft.http1.available:\n'
                  '    draft.http1.set_header("X-Spider", "inspected")\n'
                  '    try:\n'
                  '        result = draft.commit()\n'
                  '        api.print(len(result))  # Use return result to apply the edit.\n'
                  '    except CommitException as error:\n'
                  '        api.print("Cannot commit:", error)')


@dataclass
class Http1Draft:
    """Mutable HTTP/1 wire snapshot, not the escaped display headers in api.http1. Header strings round-trip via Latin-1; body is bytes. No reassembly or automatic decompression."""
    available: bool = documented('One complete supported HTTP/1 message was found. Informational, not a bypass for commit validation.',
        'draft = api.message.snapshot()\napi.print(draft.http1.available)')
    headers: list[Header] = documented('Ordered draft headers. Duplicates are preserved except Content-Length, which commit manages. Use set_header/remove_header for convenient edits.',
        _DRAFT_EXAMPLE, access='mutable private draft')
    body: bytes = documented('Complete wire body. Assign bytes; commit recalculates Content-Length and supported Content-Digest on unencoded content. No automatic compression or signature recomputation.',
        'draft = api.message.snapshot()\nif draft.http1.available:\n    api.print(len(draft.http1.body))', access='mutable private draft',
        easy='Commit repairs sha-256/sha-512 Content-Digest without parameters; rejects other encoding, integrity or range dependencies that cannot be rebuilt.',
        expert='Commit repairs supported Content-Digest and Content-Length. Unsupported digest dictionaries and other metadata may remain inconsistent; supply appropriate wire bytes yourself.')
    target: str | None = documented('Request target, or None for a response. May change length. Whitespace and control bytes are forbidden.',
        'draft = api.message.snapshot()\nif draft.http1.available and draft.http1.target is not None:\n    draft.http1.target = "/inspection"', access='mutable private draft')

    @api_method('name: str, value: str', 'None', 'Replace all case-insensitive occurrences at the first occurrence, or append a new header. Validation happens at commit.',
        _DRAFT_EXAMPLE, availability='On a private HTTP/1 draft.', access='edit private draft')
    def set_header(self, name: str, value: str) -> None:
        matches = [i for i, header in enumerate(self.headers) if header.name.lower() == name.lower()]
        position = matches[0] if matches else len(self.headers)
        self.headers[:] = [header for i, header in enumerate(self.headers) if i not in matches]
        self.headers.insert(position, Header(name, value))

    @api_method('name: str', 'None', 'Remove every case-insensitive occurrence. Removing Content-Length does not disable framing: commit recreates it when needed.',
        'draft = api.message.snapshot()\nif draft.http1.available:\n    draft.http1.remove_header("X-Debug")',
        availability='On a private HTTP/1 draft.', access='edit private draft')
    def remove_header(self, name: str) -> None:
        self.headers[:] = [header for header in self.headers if header.name.lower() != name.lower()]


_HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_REQUEST_TARGET = re.compile(r'[^\x00-\x20\x7f]+')
_MAX_HEAD_BYTES = 64 * 1024
_MAX_REPLACEMENT_BYTES = 1024 * 1024
_BODY_METADATA = frozenset({
    'content-encoding', 'content-md5', 'digest', 'content-digest',
    'repr-digest', 'etag', 'content-range',
})
_SIGNATURE_METADATA = frozenset({'signature', 'signature-input'})


def _header_values(headers, name):
    return [header.value for header in headers if header.name.lower() == name]


def _has_control_characters(value):
    return any((ord(char) < 32 and char != '\t') or ord(char) == 127 for char in value)


def _bodyless_status(status):
    return status is not None and (status < 200 or status in (204, 304))


def _draft_http1(payload):
    """Conservative framing gate; never trust display enrichments or guessed body boundaries."""
    draft = Http1Draft(False, [], b'', None)
    error, start = '', ''
    try:
        head, separator, body = payload.partition(b'\r\n\r\n')
        if not separator or len(head) > _MAX_HEAD_BYTES:
            raise CommitException('HTTP/1 head is incomplete or exceeds 64 KiB')
        lines = head.decode('latin-1').split('\r\n')
        start = lines[0]
        request = re.fullmatch(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([^\x00-\x20\x7f]+) (HTTP/1\.[01])", start)
        response = re.fullmatch(r'HTTP/1\.[01] ([1-5][0-9]{2}) ([^\x00-\x1f\x7f]*)', start)
        if not request and not response:
            raise CommitException('Only HTTP/1.0 and HTTP/1.1 messages can be edited; H2 writes are not supported')
        if request and request[1] == 'CONNECT':
            raise CommitException('CONNECT tunnel transitions are not supported')
        for line in lines[1:]:
            name, colon, value = line.partition(':')
            if not colon or not _HTTP_TOKEN.fullmatch(name):
                raise CommitException('Invalid or folded HTTP header')
            if _has_control_characters(value):
                raise CommitException('Control byte in HTTP header')
            draft.headers.append(Header(name, value.strip(' \t')))
        names = {header.name.lower() for header in draft.headers}
        if names & {'transfer-encoding', 'trailer'}:
            raise CommitException('Transfer-Encoding/chunked and trailers are not supported yet')
        connection_tokens = {
            token.strip().lower()
            for value in _header_values(draft.headers, 'connection')
            for token in value.split(',')
        }
        if 'upgrade' in names or 'upgrade' in connection_tokens:
            raise CommitException('Protocol upgrades are not supported')
        lengths = _header_values(draft.headers, 'content-length')
        if len(lengths) > 1 or (lengths and not re.fullmatch(r'[0-9]{1,10}', lengths[0])):
            raise CommitException('Ambiguous or invalid Content-Length')
        status = int(response[1]) if response else None
        no_body = _bodyless_status(status)
        if status == 101 or (no_body and body):
            raise CommitException('Unexpected body or protocol switch')
        if no_body and status != 304 and lengths:
            raise CommitException('Content-Length is forbidden for this response status')
        if not no_body:
            if not lengths and response:
                raise CommitException('Close-delimited response has no provable end in this callback')
            expected = int(lengths[0]) if lengths else 0
            if len(body) != expected:
                raise CommitException('Incomplete body, trailing bytes, or pipelined messages')
        draft.body, draft.target = body, request[2] if request else None
        draft.available = True
    except CommitException as exc:
        error = str(exc)
    return draft, start, error


@dataclass(init=False)
class MessageSnapshot:
    """Independent draft. commit() assembles and returns bytes, never sends them. Return those bytes from the script to publish; returning None discards changes. A failed commit leaves the original and draft untouched."""
    http1: Http1Draft = documented('Editable HTTP/1 view. Unsupported or incomplete fragments remain available as unchanged no-op snapshots only.',
        _DRAFT_EXAMPLE, access='mutable private draft')

    def __init__(self, payload: bytes):
        self._original = bytes(payload)
        self.http1, self._start, self._error = _draft_http1(self._original)
        self._initial = (tuple(self.http1.headers), self.http1.body, self.http1.target)

    @api_method('*, safety: str = Safety.Easy', 'bytes', 'Validate and rebuild a single HTTP/1 message, recalculating Content-Length. Returns at most 1 MiB. No-op preserves exact original bytes. Raises CommitException for unsupported framing or invalid edits; catch it in the script. No partial publication.',
        _DRAFT_EXAMPLE, availability='On a message snapshot. H2, chunked, partial and pipelined edits are rejected.', access='assemble private draft',
        easy='Repair changed or newly set Content-Digest using sha-256/sha-512 byte sequences without parameters on unencoded H1 content. Reject unsupported digest dictionaries and remaining encoding, integrity, range or signature dependencies; require Host and bodyless-status semantics.',
        expert='Repair supported Content-Digest and Content-Length; preserve unsupported digest dictionaries unchanged. Allow other semantic inconsistencies, including missing Host and a body on a bodyless status. No automatic compression, signing, or chunked encoder. Syntax, known input framing and quotas remain mandatory.')
    def commit(self, *, safety=Safety.Easy) -> bytes:
        try:
            _validate_safety(safety)
            self._validate_draft()
            unchanged = (tuple(self.http1.headers), self.http1.body, self.http1.target) == self._initial
            result = self._original if unchanged else self._assemble(safety=safety)
            if len(result) > _MAX_REPLACEMENT_BYTES:
                raise CommitException('Replacement exceeds 1 MiB')
            return result
        except (TypeError, ValueError, AttributeError, OverflowError) as exc:
            raise CommitException(str(exc)) from exc

    def _validate_draft(self):
        draft = self.http1

        if (
            not isinstance(draft, Http1Draft)
            or not isinstance(draft.headers, list)
            or not isinstance(draft.body, bytes)
        ):
            raise CommitException('Expected Http1Draft, list of Header and bytes body')

        if len(draft.body) > _MAX_REPLACEMENT_BYTES:
            raise CommitException('Replacement body exceeds 1 MiB')

    def _validate_edits(self, safety=Safety.Easy):
        """Reject changes whose dependent metadata we cannot rebuild."""
        if self._error:
            raise CommitException(self._error)

        headers = self.http1.headers

        for header in headers:
            if (
                not isinstance(header, Header)
                or not isinstance(header.name, str)
                or not isinstance(header.value, str)
            ):
                raise CommitException('Each header must have string name and value')

            if not _HTTP_TOKEN.fullmatch(header.name):
                raise CommitException('Invalid HTTP header name')

            if _has_control_characters(header.value):
                raise CommitException('Control byte in HTTP header value')

        original_headers, original_body, _ = self._initial
        names = {header.name.lower() for header in headers}
        all_names = names | {header.name.lower() for header in original_headers}

        if names & {'transfer-encoding', 'trailer', 'upgrade'}:
            raise CommitException(
                'Cannot change framing to chunked, trailers or upgrade'
            )

        if safety == Safety.Expert:
            return  # Raw body/header metadata is the researcher's responsibility.

        encodings = _header_values(headers, 'content-encoding')
        original_encodings = _header_values(original_headers, 'content-encoding')

        if encodings != original_encodings:
            raise CommitException('Content-Encoding changes require an encoder')

        repaired = {'content-digest'}
        if getattr(self, '_managed_body_encoding', False):
            repaired.add('content-encoding')

        if self.http1.body != original_body and all_names & (_BODY_METADATA - repaired):
            raise CommitException(
                'Body has encoding, integrity or range metadata '
                'that cannot be recalculated yet'
            )

        if all_names & _SIGNATURE_METADATA:
            raise CommitException('Signed messages require signature recomputation')

    def _edited_start_line(self, safety=Safety.Easy):
        if self._initial[2] is None:
            if self.http1.target is not None:
                raise CommitException('A response has no request target')

            return self._start

        target = self.http1.target

        if not isinstance(target, str) or not _REQUEST_TARGET.fullmatch(target):
            raise CommitException('Invalid request target')

        method, _, version = self._start.split(' ')
        hosts = _header_values(self.http1.headers, 'host')

        if safety == Safety.Easy and version == 'HTTP/1.1' and (len(hosts) != 1 or not hosts[0]):
            raise CommitException('HTTP/1.1 request requires exactly one nonempty Host')

        return f'{method} {target} {version}'

    def _framed_headers(self, safety=Safety.Easy):
        """Compute framing on a copy; even successful commits leave the draft alone."""
        headers = list(self.http1.headers)
        original_headers, _, original_target = self._initial
        lengths = _header_values(headers, 'content-length')
        original_lengths = _header_values(original_headers, 'content-length')
        status = int(self._start.split(' ')[1]) if original_target is None else None

        if _bodyless_status(status):
            if safety == Safety.Expert and not self.http1.body:
                return headers

        if _bodyless_status(status) and safety == Safety.Easy:
            if self.http1.body:
                raise CommitException('This status forbids a response body')

            # A 304 length describes the selected representation, not this empty body.
            if lengths != original_lengths:
                raise CommitException(
                    'Cannot infer Content-Length for a bodyless response'
                )

            return headers

        needs_length = (
            bool(self.http1.body or lengths or original_lengths)
            or original_target is None
        )
        position = next(
            (
                i for i, header in enumerate(headers)
                if header.name.lower() == 'content-length'
            ),
            len(headers),
        )
        headers = [
            header for header in headers
            if header.name.lower() != 'content-length'
        ]

        if needs_length:
            length_header = Header('Content-Length', str(len(self.http1.body)))
            headers.insert(position, length_header)

        return headers

    def _digest_headers(self, headers, safety):
        """Repair a supported dictionary atomically, without mutating the draft.

        This intentionally supports only SHA-256/SHA-512 byte-sequence members
        without parameters. Unsupported dictionaries stay untouched in Expert;
        Easy rejects them rather than silently dropping an integrity claim.
        """
        values = _header_values(headers, 'content-digest')
        original_headers, original_body, _ = self._initial
        original_values = _header_values(original_headers, 'content-digest')

        if not values or (self.http1.body == original_body and values == original_values):
            return headers

        try:
            all_headers = list(original_headers) + headers

            if (_header_values(all_headers, 'content-encoding')
                    and not getattr(self, '_managed_body_encoding', False)):
                raise CommitException('Content-Digest repair requires unencoded H1 content')

            algorithms = []
            for member in ','.join(values).split(','):
                match = re.fullmatch(r'(sha-256|sha-512)=:([A-Za-z0-9+/]*={0,2}):', member.strip())

                if match is None or match[1] in algorithms:
                    raise CommitException('Unsupported Content-Digest: expected unique sha-256/sha-512 byte sequences without parameters')

                try:
                    base64.b64decode(match[2], validate=True)
                except ValueError as error:
                    raise CommitException('Invalid Content-Digest base64') from error

                algorithms.append(match[1])

            digests = []
            for algorithm in algorithms:
                digest = hashlib.new(algorithm.replace('-', ''), self.http1.body).digest()
                encoded = base64.b64encode(digest).decode('ascii')
                digests.append(f'{algorithm}=:{encoded}:')

        except CommitException:
            if safety == Safety.Expert:
                return headers
            raise

        result = []
        for header in headers:
            if header.name.lower() != 'content-digest':
                result.append(header)
            elif digests:
                result.append(Header(header.name, ', '.join(digests)))
                digests = []

        return result

    def _assemble(self, *, safety=Safety.Easy):
        self._validate_edits(safety)
        start = self._edited_start_line(safety)
        headers = self._framed_headers(safety)
        headers = self._digest_headers(headers, safety)

        header_lines = ''.join(f'{h.name}: {h.value}\r\n' for h in headers)
        head = start + '\r\n' + header_lines + '\r\n'
        result = head.encode('latin-1') + self.http1.body

        # Apply the same framing gate to input and output; no second interpretation.
        _, _, error = _draft_http1(result)

        if error and safety == Safety.Easy:
            raise CommitException(error)

        return result


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


    @api_method('name: bytes, value: bytes, indexing: str = "without"', 'HpackField', 'Create a literal HPACK field. Indexing may affect future peer state, which REWRITE does not repair.', 'part.headers.entries.append(api.http2.Header(b"x-test", b"yes"))', access='create private draft')
    def Header(self, name, value, indexing='without'):
        return HpackField(name, value, indexing, 0, 0)

    @api_method('index: int', 'HpackField', 'Create an explicit HPACK field reference. Existence in the peer table is the script author\'s responsibility.', 'part.headers.entries.append(api.http2.HeaderIndex(62))', access='create private draft')
    def HeaderIndex(self, index):
        return HpackField(None, None, 'indexed', index, 0)

    @api_method('size: int', 'HpackField', 'Create an HPACK table-size update; insert before header fields.', 'part.headers.entries.insert(0, api.http2.TableSize(4096))', access='create private draft')
    def TableSize(self, size):
        return HpackField(None, None, 'table-size', size, 0)

    @api_method('frame_type: int, flags: int, stream_id: int, payload: bytes', 'RewritePart', 'Construct a frame from its raw payload, including any padding/priority fields. Known DATA/header blocks are interpreted for subsequent editing.', 'api.message.parts.append(api.http2.Frame(0, 1, 3, b"body"))', access='create private draft')
    def Frame(self, frame_type, flags, stream_id, payload):
        return _h2_new_frame(frame_type, flags, stream_id, payload)

    @api_method('data: bytes = b"12345678", ack: bool = False', 'RewritePart', 'Construct a connection-level PING with exactly eight opaque bytes.', 'api.message.parts.append(api.http2.Ping())', access='create private draft')
    def Ping(self, data=b'12345678', ack=False):
        if not isinstance(data, bytes) or len(data) != 8:
            raise CommitException('PING requires eight bytes')
        return _h2_new_frame(6, int(bool(ack)), 0, data)


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
    """Typed API v0.6. Read-only input views, editable Parts, H1 snapshots and explicit live H2 translation."""
    message: Message = documented('Current content fragment; None during connection-start setup.', 'api.print(api.message.size)',
        availability='Content callbacks and offline previews only; check api.phase before reading.')
    metadata: ContentMetadata = documented('Metadata of the current content callback.', 'api.print(api.metadata.side)')
    http1: Http1 = documented('HTTP/1 head supplied by backend enrichment.', 'if api.http1.available:\n    api.print(api.http1.target)')
    http2: Http2 = documented('Read-only HTTP/2 frame slices and decoded HPACK blocks.', 'for block in api.http2.header_blocks:\n    for header in block.headers:\n        api.print(block.stream_id, header.name, header.value)')
    state: dict[str, Any] = documented('JSON object local to this logical instance. Committed after success, discarded on error; 64 KiB maximum. No persistent Python globals.',
        'api.state["seen"] = api.state.get("seen", 0) + 1\napi.print(api.state["seen"])', access='mutable instance state')
    storage: SharedStorage = documented('Persistent shared JSON namespaces across scripts and versions. Writes commit per operation, even if the script later fails.',
        'shared = api.storage.namespace("stats")\napi.print(shared.increment("callbacks"))', access='shared persistent storage')
    instance: InstanceContext = documented('Identity and lifecycle mode of this invocation.', 'api.print(api.instance.mode, api.instance.key, api.instance.version)')
    connection: Connection = documented('Explicit live connection mode and HTTP/2 policy.',
        'api.connection.set_mode(Mode.Translate)\nreturn api.message.translate()', access='staged connection policy')
    phase: str = documented('Callback phase: setup at connection-start, content for payloads and offline previews.',
        'api.print(api.phase)', availability='Every callback. Setup has metadata but no Message.')


def make_views(event, payload, enrichments):
    info = event.get('details', {}).get('info', {})
    message = next((item.get('metadata', {}).get('message') for item in enrichments
                    if item.get('metadata', {}).get('operation') == 'http1.parse-head'
                    and item.get('metadata', {}).get('context') == 'complete'), None)
    head = message if isinstance(message, dict) else {}
    return InspectionViews(
        Message(payload, len(payload), info, enrichments),
        ContentMetadata(event.get('id', ''), info.get('side', ''), info.get('payload_layer')),
        Http1(bool(head), head.get('method'), head.get('target'), head.get('status'),
              tuple(Header(h['name'], h['value']) for h in head.get('headers', []))),
        make_http2(info, payload, enrichments), {}, SharedStorage(), InstanceContext('message', '', '', 0), Connection(),
        'setup' if event.get('action') == 'connection-start' else 'content')


def api_schema():
    """Generate reference directly from runtime dataclasses, types and field comments."""
    types = [InspectionViews, Message, ContentMetadata, Http1, Header, Http2, H2Frame, H2HeaderBlock,
             InstanceContext, SharedStorage, StorageNamespace, MessageSnapshot, Http1Draft, CommitException,
             RewritePart, H2Body, PartContent, H2Headers, HpackField, PartList, HeldCommit, Connection, ConnectionHttp2]
    return {'version': '0.6', 'root': 'InspectionViews', 'types': {
        cls.__name__: {'description': cls.__doc__, 'fields': [
            {'name': f.name, 'type': str(f.type).replace("<class '", '').replace("'>", ''),
             **dict(f.metadata)} for f in (fields(cls) if is_dataclass(cls) else ())],
             'methods': [method.__api_doc__ for method in vars(cls).values() if hasattr(method, '__api_doc__')]}
             for cls in types}}


# The isolated worker embeds these sources before entering the sandbox. Standalone
# schema generation and tests load the same trusted source into this namespace.
if '__file__' in globals():
    from pathlib import Path as _ApiPath
    _h2_source = _ApiPath(__file__).with_name('inspection_h2.py')
    exec(compile(_h2_source.read_text(), str(_h2_source), 'exec'), globals())
    _hold_source = _ApiPath(__file__).with_name('inspection_hold.py')
    exec(compile(_hold_source.read_text(), str(_hold_source), 'exec'), globals())
    _chunked_source = _ApiPath(__file__).with_name('inspection_chunked.py')
    exec(compile(_chunked_source.read_text(), str(_chunked_source), 'exec'), globals())
    _translate_source = _ApiPath(__file__).with_name('inspection_translate.py')
    exec(compile(_translate_source.read_text(), str(_translate_source), 'exec'), globals())
