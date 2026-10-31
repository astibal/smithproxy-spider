"""Editable HTTP addon messages, independent of the transport and wire codec.

The compatibility layer stores application-level objects here. Publishing them
is a separate operation owned by Spider's native Parts/Translate adapter.
"""

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from email.message import Message as MimeMessage
from email.utils import formatdate, mktime_tz, parsedate_tz
from http import HTTPStatus
import json
import re
import time
import uuid
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlsplit, urlunparse, urlunsplit
import addon_encoding
from addon_http import Headers
from addon_serializable import Serializable
from addon_multipart import boundary as _multipart_boundary
from addon_multipart import decode_multipart as _multipart_fields
from addon_multipart import encode_multipart
from addon_multidict import CookieAttrs, MultiDictView


def _bytes(value, encoding="utf-8"):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(encoding, "surrogateescape")
    raise TypeError("HTTP text fields must be str or bytes")


def _text(value, encoding="utf-8"):
    return value.decode(encoding, "surrogateescape")


def _headers(value):
    if isinstance(value, Headers):
        return value
    if isinstance(value, Mapping):
        return Headers([(_bytes(name), _bytes(item)) for name, item in value.items()])
    return Headers(value)


def _request_cookie_fields(header):
    """Read the permissive addon Cookie view, preserving duplicate names.

    Cookie syntax is an application-level view, not HTTP framing. In particular,
    do not use SimpleCookie: it drops duplicates and treats reserved names as
    attributes instead of ordinary request-cookie fields.
    """
    position = 0
    while position < len(header):
        while position < len(header) and (header[position].isspace() or
                                          header[position] == ";"):
            position += 1
        if position == len(header):
            return
        start = position
        while position < len(header) and header[position] not in "=;":
            position += 1
        name = header[start:position]
        value = ""
        if position < len(header) and header[position] == "=":
            position += 1
            if position < len(header) and header[position] == '"':
                position += 1
                characters = []
                while position < len(header) and header[position] != '"':
                    if header[position] == "\\":
                        position += 1
                    if position < len(header):
                        characters.append(header[position])
                        position += 1
                value = "".join(characters)
                # The public view consumes the closing quote and the next
                # separator, even for malformed input without a semicolon.
                position += 1
            else:
                start = position
                while position < len(header) and header[position] != ";":
                    position += 1
                value = header[start:position]
        position += 1
        if name or value:
            yield [name, value]


def _format_request_cookie(name, value):
    needs_quotes = any(ord(char) < 33 or ord(char) > 126 or char in ';,"\\'
                       for char in value)
    if needs_quotes:
        value = value.replace("\\", "\\\\").replace('"', '\\"')
        value = '"' + value + '"'
    return name + "=" + value


def _response_cookie_fields(header):
    """Read Set-Cookie fields, including legacy comma-separated cookies.

    An Expires date may contain a weekday comma. Quoted values also protect
    delimiters; other commas start another cookie, not another attribute.
    """
    position = 0
    pairs = []
    while position < len(header):
        while position < len(header) and (header[position].isspace() or
                                          header[position] == ";"):
            position += 1
        if position == len(header):
            break
        start = position
        while position < len(header) and header[position] not in "=;,":
            position += 1
        name = header[start:position]
        value = None
        if position < len(header) and header[position] == "=":
            position += 1
            if position < len(header) and header[position] == '"':
                position += 1
                characters = []
                while position < len(header) and header[position] != '"':
                    if header[position] == "\\":
                        position += 1
                    if position < len(header):
                        characters.append(header[position])
                        position += 1
                value = "".join(characters)
                position += 1
            else:
                start = position
                while position < len(header) and header[position] != ";":
                    if header[position] == ",":
                        prefix = header[start:position].strip().lower()
                        weekday = prefix in ("mon", "tue", "wed", "thu", "fri", "sat", "sun",
                                             "monday", "tuesday", "wednesday", "thursday",
                                             "friday", "saturday", "sunday")
                        if name.lower() != "expires" or not weekday:
                            break
                    position += 1
                value = header[start:position]
        pairs.append((name, value))
        if position < len(header) and header[position] == ",":
            cookie_name, cookie_value = pairs[0]
            yield cookie_name, (cookie_value, CookieAttrs(pairs[1:]))
            pairs = []
        position += 1
    if pairs:
        cookie_name, cookie_value = pairs[0]
        yield cookie_name, (cookie_value, CookieAttrs(pairs[1:]))


def _format_response_cookie(name, value, attributes):
    if isinstance(attributes, CookieAttrs):
        attributes = attributes.fields
    pairs = [(name, value), *attributes]
    fields = []
    for key, item in pairs:
        if item is None:
            fields.append(key)
        elif key.lower() in ("expires", "path"):
            fields.append(key + "=" + item)
        else:
            fields.append(_format_request_cookie(key, item))
    return "; ".join(fields)


def parse_cookie_header(line):
    """Parse one Cookie header into ordered name/value pairs."""
    return list(_request_cookie_fields(line))


def parse_cookie_headers(cookie_headers):
    """Parse multiple Cookie header fields without merging duplicates."""
    fields = []
    for header in cookie_headers:
        fields.extend(parse_cookie_header(header))
    return fields


def format_cookie_header(fields):
    """Format ordered request-cookie pairs as one Cookie header value."""
    formatted = []
    for name, value in fields:
        if value is None:
            formatted.append(name)
        else:
            formatted.append(_format_request_cookie(name, value))
    return '; '.join(formatted)


def parse_set_cookie_header(line):
    """Parse one Set-Cookie header, including legacy comma-separated values."""
    return [
        (name, value, attributes)
        for name, (value, attributes) in _response_cookie_fields(line)
    ]


def parse_set_cookie_headers(headers):
    """Parse multiple Set-Cookie header fields in wire order."""
    cookies = []
    for header in headers:
        cookies.extend(parse_set_cookie_header(header))
    return cookies


def format_set_cookie_header(set_cookies):
    """Format one or more cookies as a legacy comma-separated field value."""
    return ', '.join(
        _format_response_cookie(name, value, attributes)
        for name, value, attributes in set_cookies
    )


_COOKIE_ATTRIBUTE_NAMES = frozenset({
    'expires', 'path', 'comment', 'max-age',
    'secure', 'httponly', 'version',
})


def group_cookies(pairs):
    """Group a flat cookie/attribute sequence into public cookie triples."""
    current_name = None
    current_value = None
    attributes = []

    for name, value in pairs:
        if current_name is not None and name.lower() in _COOKIE_ATTRIBUTE_NAMES:
            attributes.append((name, value))
            continue

        if current_name is not None:
            yield current_name, current_value, CookieAttrs(attributes)
        current_name = name
        current_value = value
        attributes = []

    if current_name is not None:
        yield current_name, current_value, CookieAttrs(attributes)


def get_expiration_ts(cookie_attrs):
    """Return an absolute expiry timestamp, or ``None`` for a session cookie."""
    expires = cookie_attrs.get('expires')
    if expires is not None:
        parsed = parsedate_tz(expires)
        return None if parsed is None else mktime_tz(parsed)

    if 'max-age' in cookie_attrs:
        try:
            return time.time() + int(cookie_attrs['max-age'])
        except ValueError:
            return None
    return None


def is_expired(cookie_attrs):
    """Report whether the cookie's valid expiry is in the past."""
    expiration = get_expiration_ts(cookie_attrs)
    return expiration is not None and expiration <= time.time()


def refresh_set_cookie_header(cookie, delta):
    """Shift a valid Expires attribute while retaining other cookie fields."""
    parsed = parse_set_cookie_header(cookie)
    if len(parsed) != 1 or not parsed[0][0] or parsed[0][1] is None:
        raise ValueError('Invalid Cookie')

    name, value, attributes = parsed[0]
    refreshed = []
    for attribute, attribute_value in attributes.fields:
        if attribute.lower() != 'expires':
            refreshed.append((attribute, attribute_value))
            continue

        timestamp = None
        if attribute_value is not None:
            date = parsedate_tz(attribute_value)
            if date is not None:
                timestamp = mktime_tz(date)
        if timestamp is not None:
            refreshed.append((attribute, formatdate(timestamp + delta, usegmt=True)))

    return _format_response_cookie(name, value, CookieAttrs(refreshed))


def _convert_content(value, encoding, compress=False):
    """Apply an HTTP content coding, without parsing HTTP framing."""
    if not encoding:
        return value
    operation = addon_encoding.encode if compress else addon_encoding.decode
    try:
        return operation(value, encoding)
    except ValueError as error:
        raise ValueError(f"Invalid {encoding.lower()} content") from error


def _mime(content_type):
    message = MimeMessage()
    if content_type:
        message["content-type"] = content_type
    return message


def _charset(content_type, body=b""):
    mime = _mime(content_type)
    explicit = mime.get_param("charset")
    if explicit:
        return explicit
    media_type = mime.get_content_type()
    if media_type == "application/json" or media_type.endswith("+json"):
        return "utf-8"
    if media_type == "text/html":
        match = re.search(br"charset\s*=\s*[\"']?([A-Za-z0-9_-]+)", body, re.I)
        if match:
            return match.group(1).decode("ascii")
    return "iso-8859-1"


@dataclass
class MessageData(Serializable):
    http_version: bytes
    headers: Headers
    content: bytes | None
    trailers: Headers | None
    timestamp_start: float
    timestamp_end: float | None

    def get_state(self):
        state = vars(self).copy()
        state["headers"] = None if self.headers is None else self.headers.get_state()
        state["trailers"] = None if self.trailers is None else self.trailers.get_state()
        return state

    def set_state(self, state):
        # Public data objects accept partial updates and retain extra fields.
        # This permissive state behavior belongs to the detached data object;
        # Message construction still consumes only its declared fields.
        for name, value in state.items():
            if name in ("headers", "trailers") and value is not None:
                value = Headers.from_state(value)
            setattr(self, name, value)

    @classmethod
    def from_state(cls, state):
        values = dict(state)
        for name in ("headers", "trailers"):
            if values.get(name) is not None:
                values[name] = Headers.from_state(values[name])
        return cls(**values)

    def copy(self):
        return deepcopy(self)


@dataclass
class RequestData(MessageData):
    host: str
    port: int
    method: bytes
    scheme: bytes
    authority: bytes
    path: bytes


@dataclass
class ResponseData(MessageData):
    status_code: int
    reason: bytes


class Message(Serializable):
    """Shared body, header and timestamp behavior for HTTP addon objects."""

    stream = False

    @property
    def http_version(self):
        return _text(self.data.http_version, "ascii")

    @http_version.setter
    def http_version(self, value):
        self.data.http_version = _bytes(value, "ascii")

    @property
    def is_http10(self):
        return self.http_version == "HTTP/1.0"

    @property
    def is_http11(self):
        return self.http_version == "HTTP/1.1"

    @property
    def is_http2(self):
        return self.http_version == "HTTP/2.0"

    @property
    def is_http3(self):
        return self.http_version == "HTTP/3"

    @property
    def headers(self):
        return self.data.headers

    @headers.setter
    def headers(self, value):
        self.data.headers = _headers(value)

    @property
    def trailers(self):
        return self.data.trailers

    @trailers.setter
    def trailers(self, value):
        self.data.trailers = None if value is None else _headers(value)

    @property
    def raw_content(self):
        return self.data.content

    @raw_content.setter
    def raw_content(self, value):
        # Raw assignment intentionally does not repair Content-Length. This is
        # different from assigning decoded content and is observable by addons.
        self.data.content = value

    @property
    def content(self):
        return self.get_content()

    @content.setter
    def content(self, value):
        self.set_content(value)

    def get_content(self, strict=True):
        if self.raw_content is None:
            return None
        try:
            return _convert_content(self.raw_content, self.headers.get("content-encoding", ""))
        except ValueError:
            if strict:
                raise
            return self.raw_content

    def set_content(self, value):
        if value is None:
            self.raw_content = None
            return
        if not isinstance(value, bytes):
            raise TypeError("Message content must be bytes; use text for strings")
        encoding = self.headers.get("content-encoding", "")
        try:
            encoded = _convert_content(value, encoding, compress=True)
        except ValueError:
            self.headers.pop("content-encoding", None)
            encoded = value
        self.raw_content = encoded
        if "transfer-encoding" not in self.headers:
            self.headers["content-length"] = str(len(encoded))

    @property
    def text(self):
        return self.get_text()

    @text.setter
    def text(self, value):
        self.set_text(value)

    def get_text(self, strict=True):
        body = self.get_content(strict)
        if body is None:
            return None
        encoding = _charset(self.headers.get("content-type", ""), body)
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeError) as error:
            if strict:
                raise ValueError(f"Cannot decode text as {encoding}") from error
            return body.decode("utf-8", "surrogateescape")

    def set_text(self, value):
        if value is None:
            self.content = None
            return
        if not isinstance(value, str):
            raise TypeError("Message text must be str; use content for bytes")
        content_type = self.headers.get("content-type", "")
        encoding = _charset(content_type)
        try:
            body = value.encode(encoding, "surrogateescape")
        except (LookupError, UnicodeError):
            body = value.encode("utf-8", "surrogateescape")
            mime = _mime(content_type)
            parameters = mime.get_params()[1:] if mime.get_params() else []
            parameters = [(key, item) for key, item in parameters if key.lower() != "charset"]
            parameters.append(("charset", "utf-8"))
            self.headers["content-type"] = mime.get_content_type() + "; " + "; ".join(
                f"{key}={item}" for key, item in parameters
            )
        self.content = body

    def decode(self, strict=True):
        if self.raw_content:
            body = self.get_content(strict)
            self.headers.pop("content-encoding", None)
            self.content = body

    def encode(self, encoding):
        self.headers["content-encoding"] = encoding
        self.content = self.raw_content
        if "content-encoding" not in self.headers:
            raise ValueError(f"Invalid content encoding '{encoding}'")

    def json(self, **kwargs):
        return json.loads(self.content, **kwargs)

    @property
    def timestamp_start(self):
        return self.data.timestamp_start

    @timestamp_start.setter
    def timestamp_start(self, value):
        self.data.timestamp_start = value

    @property
    def timestamp_end(self):
        return self.data.timestamp_end

    @timestamp_end.setter
    def timestamp_end(self, value):
        self.data.timestamp_end = value

    def get_state(self):
        state = vars(self.data).copy()
        state["headers"] = self.headers.get_state()
        if self.trailers is not None:
            state["trailers"] = self.trailers.get_state()
        return state

    def set_state(self, state):
        restored = type(self).from_state(state)
        self.data = restored.data

    @classmethod
    def from_state(cls, state):
        return cls(**state)

    def copy(self):
        return deepcopy(self)


def _endpoint(host, port, scheme):
    if (scheme, port) in (("https", 443), ("http", 80)):
        return host
    return f"{host}:{port}"


class Request(Message):
    def anticache(self):
        """Remove validators that could turn a response into a cache hit."""
        for name in ("if-modified-since", "if-none-match"):
            self.headers.pop(name, None)

    def anticomp(self):
        """Ask the upstream server for an uncompressed representation."""
        self.headers["accept-encoding"] = "identity"

    def constrain_encoding(self):
        """Normalize the advertised encodings using the addon API contract.

        This is a header operation, not a declaration of available local codecs.
        Preserve the reference's case-sensitive substring matching, including
        its treatment of quality parameters, rather than silently improving it.
        Its output order varies with Python's hash seed; use a stable order here.
        """
        if "accept-encoding" not in self.headers:
            return
        advertised = self.headers["accept-encoding"]
        accepted = []
        for encoding in ("identity", "br", "gzip", "zstd", "deflate"):
            if encoding in advertised:
                accepted.append(encoding)
        self.headers["accept-encoding"] = ", ".join(accepted)

    def __init__(self, host, port, method, scheme, authority, path, http_version,
                 headers, content, trailers, timestamp_start, timestamp_end):
        self.data = RequestData(
            _bytes(http_version, "ascii"), _headers(headers), content,
            None if trailers is None else _headers(trailers), timestamp_start,
            timestamp_end, host, port, _bytes(method), _bytes(scheme),
            _bytes(authority), _bytes(path),
        )

    @classmethod
    def make(cls, method, url, content="", headers=()):
        now = time.time()
        request = cls("", 0, method, b"", b"", b"", b"HTTP/1.1",
                      _headers(headers), None, None, now, now)
        request.url = url
        if isinstance(content, str):
            request.text = content
        elif isinstance(content, bytes):
            request.content = content
        else:
            raise TypeError(
                "Expected content to be str or bytes, but is "
                + type(content).__name__
                + "."
            )
        return request

    @property
    def method(self):
        return _text(self.data.method).upper()

    @method.setter
    def method(self, value):
        self.data.method = _bytes(value)

    @property
    def scheme(self):
        return _text(self.data.scheme)

    @scheme.setter
    def scheme(self, value):
        self.data.scheme = _bytes(value)

    @property
    def authority(self):
        return _text(self.data.authority)

    @authority.setter
    def authority(self, value):
        self.data.authority = _bytes(value)

    @property
    def path(self):
        return _text(self.data.path)

    @path.setter
    def path(self, value):
        self.data.path = _bytes(value)

    @property
    def host(self):
        return self.data.host

    @host.setter
    def host(self, value):
        self.data.host = value
        self._update_host_header()

    @property
    def port(self):
        return self.data.port

    @port.setter
    def port(self, value):
        self.data.port = value
        self._update_host_header()

    def _update_host_header(self):
        value = _endpoint(self.host, self.port, self.scheme)
        if self.authority:
            self.authority = value
        if "host" in self.headers:
            self.headers["host"] = value

    @property
    def host_header(self):
        if (self.is_http2 or self.is_http3) and self.authority:
            return self.authority
        return self.headers.get("host")

    @host_header.setter
    def host_header(self, value):
        if value is None:
            self.headers.pop("host", None)
            if self.is_http2 or self.is_http3:
                self.authority = ""
        elif self.is_http2 or self.is_http3:
            self.authority = value
        else:
            self.headers["host"] = value

    @property
    def url(self):
        if self.first_line_format == "authority":
            return self.authority
        return f"{self.scheme}://{_endpoint(self.host, self.port, self.scheme)}{self.path}"

    @url.setter
    def url(self, value):
        # URL assignment is an application-object operation, not wire parsing.
        # Keep validation ahead of mutation so an invalid URL cannot half-edit
        # the destination while an addon is handling an exception.
        value.encode("ascii")
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError("An absolute URL with a host is required")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, parsed.fragment))
        self.data.scheme = _bytes(parsed.scheme)
        self.data.host = parsed.hostname
        self.data.port = port
        self.data.path = _bytes(path)
        self._update_host_header()

    @property
    def pretty_host(self):
        if self.host_header:
            try:
                return urlsplit("//" + self.host_header).hostname or self.host
            except ValueError:
                return self.host_header
        return self.host

    @property
    def pretty_url(self):
        if not self.host_header or self.first_line_format == "authority":
            return self.url
        return f"{self.scheme}://{self.host_header}{self.path}"

    @property
    def first_line_format(self):
        if self.method == "CONNECT":
            return "authority"
        return "absolute" if self.authority else "relative"

    @property
    def path_components(self):
        # This view follows the request URL, not an independently parsed path:
        # a leading double slash is still a path, not a replacement authority.
        # Keep undecodable octets round-trippable for binary URL components.
        path = urlparse(self.url).path
        return tuple(unquote(segment, errors='surrogateescape')
                     for segment in path.split('/') if segment)

    @path_components.setter
    def path_components(self, components):
        parsed = urlparse(self.url)
        path = "/" + "/".join(quote(segment, safe="", errors='surrogateescape')
                              for segment in components)
        self.path = urlunparse(("", "", path, parsed.params, parsed.query, parsed.fragment))

    @property
    def query(self):
        return MultiDictView(self._query_fields, self._set_query_fields)

    @query.setter
    def query(self, fields):
        self._set_query_fields(fields)

    def _query_fields(self):
        return tuple(parse_qsl(urlsplit(self.path).query, keep_blank_values=True,
                               errors="surrogateescape"))

    def _set_query_fields(self, fields):
        parsed = urlsplit(self.path)
        query = urlencode(list(fields), errors="surrogateescape")
        self.path = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                               query, parsed.fragment))

    @property
    def cookies(self):
        return MultiDictView(self._cookie_fields, self._set_cookie_fields)

    @cookies.setter
    def cookies(self, fields):
        self._set_cookie_fields(fields)

    def _cookie_fields(self):
        fields = []
        for header in self.headers.get_all("cookie"):
            fields.extend(_request_cookie_fields(header))
        return tuple(fields)

    def _set_cookie_fields(self, fields):
        # Build first: an invalid field must not partially rewrite headers.
        header = "; ".join(_format_request_cookie(name, value)
                           for name, value in fields)
        self.headers["cookie"] = header

    @property
    def urlencoded_form(self):
        return MultiDictView(self._form_fields, self._set_form_fields)

    @urlencoded_form.setter
    def urlencoded_form(self, fields):
        self._set_form_fields(fields)

    def _form_fields(self):
        media_type = self.headers.get("content-type", "").lower()
        # Match the public view's permissive media-type recognition. This is
        # only an application view, never a transport framing decision.
        if "application/x-www-form-urlencoded" not in media_type:
            return ()
        content = self.content
        if content is None:
            return ()
        return tuple(parse_qsl(_text(content), keep_blank_values=True,
                               errors="surrogateescape"))

    def _set_form_fields(self, fields):
        content = urlencode(list(fields), errors="surrogateescape").encode("ascii")
        self.headers["content-type"] = "application/x-www-form-urlencoded"
        self.content = content

    @property
    def multipart_form(self):
        return MultiDictView(self._multipart_fields, self._set_multipart_fields)

    @multipart_form.setter
    def multipart_form(self, fields):
        self._set_multipart_fields(fields)

    def _multipart_fields(self):
        return _multipart_fields(self.headers.get("content-type", ""), self.content)

    def _set_multipart_fields(self, fields):
        content_type = self.headers.get("content-type", "")
        if content_type.split(";", 1)[0].strip().lower() != "multipart/form-data":
            boundary = "--------------------" + uuid.uuid4().hex
            content_type = "multipart/form-data; boundary=" + boundary
            self.headers["content-type"] = content_type
        self.content = encode_multipart(content_type, fields)


class Response(Message):
    def refresh(self, now=None):
        """Shift replay-related dates by the age of this response.

        This changes message headers only. It does not send a response, alter
        observation timestamps or make an expired credential valid upstream.
        """
        delta = (now or time.time()) - self.timestamp_start
        for name in ("date", "expires", "last-modified"):
            if name not in self.headers:
                continue
            parsed = parsedate_tz(self.headers[name])
            if parsed is not None:
                self.headers[name] = formatdate(mktime_tz(parsed) + delta, usegmt=True)

        refreshed = []
        for header in self.headers.get_all("set-cookie"):
            parsed_cookies = tuple(_response_cookie_fields(header))
            if any(not name for name, _ in parsed_cookies):
                # Invalid cookie names are not rewritten. Keeping the original
                # field also avoids normalizing malformed evidence during
                # detached replay preparation.
                refreshed.append(header)
                continue
            cookies = []
            for name, (value, attributes) in parsed_cookies:
                if "expires" in attributes:
                    expiry = attributes["expires"]
                    parsed = parsedate_tz(expiry) if expiry else None
                    if parsed is None:
                        del attributes["expires"]
                    else:
                        attributes["expires"] = formatdate(mktime_tz(parsed) + delta,
                                                           usegmt=True)
                cookies.append(_format_response_cookie(name, value, attributes))
            refreshed.append(", ".join(cookies))
        self.headers.set_all("set-cookie", refreshed)

    @property
    def cookies(self):
        return MultiDictView(self._cookie_fields, self._set_cookie_fields)

    @cookies.setter
    def cookies(self, fields):
        self._set_cookie_fields(fields)

    def _cookie_fields(self):
        fields = []
        for header in self.headers.get_all("set-cookie"):
            fields.extend(_response_cookie_fields(header))
        return tuple(fields)

    def _set_cookie_fields(self, fields):
        headers = []
        for name, (value, attributes) in fields:
            headers.append(_format_response_cookie(name, value, attributes))
        self.headers.set_all("set-cookie", headers)

    def __init__(self, http_version, status_code, reason, headers, content,
                 trailers, timestamp_start, timestamp_end):
        self.data = ResponseData(
            _bytes(http_version, "ascii"), _headers(headers), content,
            None if trailers is None else _headers(trailers), timestamp_start,
            timestamp_end, status_code, _bytes(reason, "iso-8859-1"),
        )

    @classmethod
    def make(cls, status_code=200, content=b"", headers=()):
        try:
            reason = HTTPStatus(status_code).phrase
        except ValueError:
            reason = ""
        now = time.time()
        response = cls(b"HTTP/1.1", status_code, reason, _headers(headers),
                       None, None, now, now)
        if isinstance(content, str):
            response.text = content
        elif isinstance(content, bytes):
            response.content = content
        else:
            raise TypeError(
                "Expected content to be str or bytes, but is "
                + type(content).__name__
                + "."
            )
        return response

    @property
    def status_code(self):
        return self.data.status_code

    @status_code.setter
    def status_code(self, value):
        self.data.status_code = value

    @property
    def reason(self):
        return _text(self.data.reason, "iso-8859-1")

    @reason.setter
    def reason(self, value):
        self.data.reason = _bytes(value, "iso-8859-1")
