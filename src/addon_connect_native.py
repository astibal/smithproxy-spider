"""Bounded native CONNECT messages and addon lifecycle publication.

Smithproxy owns framing and socket decisions. This boundary translates its
complete observations into addon values and returns one atomic wire decision.
"""

import base64
import binascii
import time

from addon_connection import ConnectionState
from addon_connect_events import HTTPConnectEvent, HTTPConnectTransportError
from addon_http import Headers
from addon_http_message import Request, Response


HEADER_LIMIT = 8192
RESPONSE_LIMIT = 256 * 1024


def _decode(value, limit):
    if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
        raise HTTPConnectTransportError('CONNECT bytes exceed the native limit')

    # Check the encoded bound before allocating the decoded payload.
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise HTTPConnectTransportError('Invalid CONNECT base64') from error

    if len(raw) > limit:
        raise HTTPConnectTransportError('CONNECT bytes exceed the native limit')

    return raw


def _head(raw):
    head, separator, body = raw.partition(b'\r\n\r\n')
    if not separator or len(head) + 4 >= HEADER_LIMIT:
        raise HTTPConnectTransportError('Incomplete or oversized CONNECT headers')

    # Preserve field order and duplicates for the public Headers object.
    lines = head.split(b'\r\n')
    fields = []

    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        if (
            not separator
            or not name
            or any(byte <= 32 or byte >= 127 or byte == 58 for byte in name)
            or b'\r' in value
            or b'\n' in value
            or b'\0' in value
        ):
            raise HTTPConnectTransportError('Invalid CONNECT header')

        fields.append((name, value.strip(b' \t')))

    return lines[0], Headers(fields), body


def address(value, *, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise HTTPConnectTransportError('CONNECT endpoint requires host and port')

    host, port = value
    if (
        not isinstance(host, str)
        or not host
        or len(host) > 255
        or any(ord(char) <= 32 or ord(char) == 127 for char in host)
        or type(port) is not int
        or not 1 <= port <= 65535
    ):
        raise HTTPConnectTransportError('Invalid CONNECT endpoint')

    return host, port


def request_value(observation):
    raw = _decode(observation['request_base64'], HEADER_LIMIT - 1)
    line, headers, body = _head(raw)
    parts = line.split(b' ')
    if (
        len(parts) != 3
        or parts[0] != b'CONNECT'
        or parts[2] not in (b'HTTP/1.0', b'HTTP/1.1')
        or body
    ):
        raise HTTPConnectTransportError('Invalid native CONNECT request')

    host, port = address(observation['target'])
    authenticated = observation.get('authenticated', False)
    if type(authenticated) is not bool:
        raise HTTPConnectTransportError('Invalid CONNECT authentication flag')

    # Accepted credentials have already served their native AAA purpose.
    # Rejected credentials remain observable to the CONNECT hook.
    if authenticated:
        headers.pop('proxy-authorization', None)

    now = time.time()
    return Request(
        host=host,
        port=port,
        method=b'CONNECT',
        scheme=b'',
        authority=b'',
        path=parts[1],
        http_version=parts[2],
        headers=headers,
        content=b'',
        trailers=None,
        timestamp_start=now,
        timestamp_end=now,
    )


def response_value(encoded):
    if encoded is None:
        return None

    raw = _decode(encoded, RESPONSE_LIMIT)
    line, headers, body = _head(raw)
    parts = line.split(b' ', 2)
    if (
        len(parts) != 3
        or parts[0] not in (b'HTTP/1.0', b'HTTP/1.1')
        or len(parts[1]) != 3
        or not parts[1].isdigit()
    ):
        raise HTTPConnectTransportError('Invalid native CONNECT response')

    status = int(parts[1])
    if not 200 <= status <= 599:
        raise HTTPConnectTransportError('CONNECT requires a final response')

    now = time.time()
    return Response(
        http_version=parts[0],
        status_code=status,
        reason=parts[2],
        headers=headers,
        content=body,
        trailers=None,
        timestamp_start=now,
        timestamp_end=now,
    )


def response_bytes(response):
    # Addon values are mutable. Validate before serializing, and normalize
    # framing so a header mutation cannot leak bytes into the future tunnel.
    if not isinstance(response, Response) or not isinstance(response.raw_content, bytes):
        raise HTTPConnectTransportError('CONNECT requires a complete response')
    if response.http_version not in ('HTTP/1.0', 'HTTP/1.1'):
        raise HTTPConnectTransportError('CONNECT requires an HTTP/1 response')
    if not 200 <= response.status_code <= 599 or response.trailers:
        raise HTTPConnectTransportError('Unsupported CONNECT response')

    reason = response.reason.encode('latin-1')
    if any(byte < 32 or byte == 127 for byte in reason):
        raise HTTPConnectTransportError('Invalid CONNECT response reason')

    # Derive framing from the final body, not from mutable addon headers.
    body = response.raw_content
    headers = response.headers.copy()
    headers.pop('transfer-encoding', None)
    headers.pop('content-length', None)
    if not 200 <= response.status_code < 300 or body:
        headers['content-length'] = str(len(body))

    line = (
        response.http_version.encode('ascii') + b' '
        + str(response.status_code).encode('ascii') + b' ' + reason
    )
    fields = []

    for name, value in headers.fields:
        if (
            not name
            or any(byte <= 32 or byte >= 127 or byte == 58 for byte in name)
            or b'\r' in value
            or b'\n' in value
            or b'\0' in value
        ):
            raise HTTPConnectTransportError('Invalid CONNECT response header')

        fields.append(name + b': ' + value)

    head = b'\r\n'.join([line, *fields]) + b'\r\n\r\n'
    raw = head + body
    if len(head) >= HEADER_LIMIT or len(raw) > RESPONSE_LIMIT:
        raise HTTPConnectTransportError('CONNECT response exceeds the native limit')

    return base64.b64encode(raw).decode('ascii')


async def dispatch(adapter, observation, request=None, response=None):
    """Apply one regular-proxy event to an already registered native connection."""
    envelope = observation['envelope']
    event = HTTPConnectEvent.parse(envelope, envelope.get('event'))
    if event.mode != 'regular' or event.event not in ('request', 'connected', 'error'):
        raise HTTPConnectTransportError('Unsupported native CONNECT lifecycle')

    registered = adapter._connections[event.connection_id]
    if event.event == 'request':
        decision, failures = await adapter.connect.request(
            envelope,
            request,
            registered.client,
            registered.server,
            response,
        )
    else:
        # Server descriptors are shared with the subsequent HTTP flow. Set the
        # address while closed, before publishing the observed connection state.
        server = registered.server
        server.state = ConnectionState.CLOSED
        server.address = address(observation['target'])
        server.peername = address(observation.get('peername'), nullable=True)
        server.sockname = address(observation.get('sockname'), nullable=True)

        if event.event == 'connected':
            if server.peername is None:
                raise HTTPConnectTransportError('Connected target requires a native peer')

            server.state = ConnectionState.OPEN
            server.timestamp_tcp_setup = time.time()
            decision, failures = await adapter.connect.connected(envelope, response)
        else:
            decision, failures = await adapter.connect.error(envelope, response)

    if failures:
        raise HTTPConnectTransportError('CONNECT addon callback failed')

    # Return a complete decision; no partial mutation crosses the IPC boundary.
    result = {'action': decision.action}
    if decision.request is not None:
        result['target'] = address((decision.request.host, decision.request.port))
    if decision.response is not None:
        result['response_base64'] = response_bytes(decision.response)

    return result
