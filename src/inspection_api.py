"""Typed inspection views. Field metadata generates the browser reference and completion."""
from __future__ import annotations
from dataclasses import dataclass, field, fields


def documented(description, example, availability='Always available for a content callback.'):
    return field(metadata={'description': description, 'example': example,
                           'availability': availability, 'access': 'read-only snapshot'})


@dataclass(frozen=True)
class Message:
    """Current webhook content fragment, not necessarily a complete application message."""
    bytes: bytes = documented('Original callback bytes. No decoding or reassembly.', 'api.print(len(api.message.bytes))')
    size: int = documented('Length of this fragment in bytes.', 'api.print(api.message.size)')


@dataclass(frozen=True)
class ContentMetadata:
    """Metadata reported by the current webhook; not connection history."""
    session_id: str = documented('Connection identifier from event.id; empty if absent.', 'api.print(api.metadata.session_id)')
    side: str = documented('Observed side: L (client), R (server), or empty when absent.', 'api.print(api.metadata.side)')
    payload_layer: str | None = documented('Reported payload layer, without inferring a protocol.', 'api.print(api.metadata.payload_layer)', 'None when webhook omits payload_layer.')


@dataclass(frozen=True)
class Header:
    """One decoded HTTP/1 header; order and duplicate names are preserved."""
    name: str = documented('Header name with observed casing.', 'api.print(api.http1.headers[0].name)', 'Only when headers is non-empty.')
    value: str = documented('Decoded display value from Spider; non-printable bytes may appear as \\xNN.', 'api.print(api.http1.headers[0].value)', 'Only when headers is non-empty.')


@dataclass(frozen=True)
class Http1:
    """First complete HTTP/1 head decoded by Spider for this callback. Does not imply a complete body or enumerate pipelined messages."""
    available: bool = documented('True only when http1.parse-head enrichment provides a complete head.', 'if api.http1.available:\n    api.print(api.http1.method)')
    method: str | None = documented('Request method, e.g. GET. No inference from body bytes.', 'api.print(api.http1.method)', 'None for responses or unavailable heads.')
    target: str | None = documented('Request target as decoded by Spider; may contain escaped non-printable bytes.', 'api.print(api.http1.target)', 'None for responses or unavailable heads.')
    status: int | None = documented('HTTP response status code.', 'api.print(api.http1.status)', 'None for requests or unavailable heads.')
    headers: tuple[Header, ...] = documented('Ordered headers including duplicates. Empty means no fields or unavailable; check available.', 'for header in api.http1.headers:\n    api.print(header.name, header.value)')


@dataclass
class InspectionViews:
    """Typed API preview v0.1. Views do not mutate outgoing traffic; legacy api.bytes/print/hexdump remain supported."""
    message: Message = documented('Current content fragment.', 'api.print(api.message.size)')
    metadata: ContentMetadata = documented('Metadata of the current content callback.', 'api.print(api.metadata.side)')
    http1: Http1 = documented('HTTP/1 head supplied by backend enrichment.', 'if api.http1.available:\n    api.print(api.http1.target)')


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
              tuple(Header(h['name'], h['value']) for h in head.get('headers', []))))


def api_schema():
    """Generate reference directly from runtime dataclasses, types and field comments."""
    types = [InspectionViews, Message, ContentMetadata, Http1, Header]
    return {'version': '0.1', 'root': 'InspectionViews', 'types': {
        cls.__name__: {'description': cls.__doc__, 'fields': [
            {'name': f.name, 'type': str(f.type).replace("<class '", '').replace("'>", ''),
             **dict(f.metadata)} for f in fields(cls)]} for cls in types}}
