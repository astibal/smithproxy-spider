"""Clean-room flow-filter parser and matcher over Spider-owned flow models."""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
import re

from addon_flow import Flow, HTTPFlow, TCPFlow, UDPFlow


def _compile(pattern, extra_flags=0):
    flags = extra_flags
    if not os.environ.get('MITMPROXY_CASE_SENSITIVE_FILTERS'):
        flags |= re.IGNORECASE
    try:
        return re.compile(pattern, flags)
    except re.error as error:
        raise ValueError(str(error)) from error


def _search(expression, value):
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'surrogateescape')
    return expression.search(str(value)) is not None


def _address(value):
    if value is None:
        return ''
    if isinstance(value, tuple):
        return ':'.join(str(item) for item in value)
    return str(value)


def _header_lines(message):
    if message is None:
        return ()
    return tuple(f'{name}: {value}' for name, value in message.headers.items(multi=True))


class TFilter(ABC):
    """Callable predicate produced by :func:`parse`."""

    @abstractmethod
    def __call__(self, flow: Flow) -> bool:
        raise NotImplementedError


class FAll(TFilter):
    def __call__(self, flow):
        return True

    def __str__(self):
        return 'all flows'


class FErr(TFilter):
    def __call__(self, flow):
        return flow.error is not None

    def __str__(self):
        return 'has error'


class FMarked(TFilter):
    def __call__(self, flow):
        return bool(flow.marked)

    def __str__(self):
        return 'is marked'


class FHTTP(TFilter):
    def __call__(self, flow):
        return isinstance(flow, HTTPFlow)

    def __str__(self):
        return 'is an HTTP Flow'


class FWebSocket(TFilter):
    def __call__(self, flow):
        return isinstance(flow, HTTPFlow) and flow.websocket is not None

    def __str__(self):
        return 'is a Websocket Flow'


class FTCP(TFilter):
    def __call__(self, flow):
        return isinstance(flow, TCPFlow)

    def __str__(self):
        return 'is a TCP Flow'


class FUDP(TFilter):
    def __call__(self, flow):
        return isinstance(flow, UDPFlow)

    def __str__(self):
        return 'is a UDP Flow'


class FDNS(TFilter):
    def __call__(self, flow):
        return getattr(flow, 'type', None) == 'dns'

    def __str__(self):
        return 'is a DNS Flow'


class FReq(TFilter):
    def __call__(self, flow):
        return isinstance(flow, HTTPFlow) and flow.response is None

    def __str__(self):
        return 'has no response'


class FResp(TFilter):
    def __call__(self, flow):
        return isinstance(flow, HTTPFlow) and flow.response is not None

    def __str__(self):
        return 'has response'


class FReplay(TFilter):
    def __call__(self, flow):
        return bool(flow.is_replay)

    def __str__(self):
        return 'flow has been replayed'


class FReplayClient(TFilter):
    def __call__(self, flow):
        return flow.is_replay == 'request'

    def __str__(self):
        return 'request has been replayed'


class FReplayServer(TFilter):
    def __call__(self, flow):
        return flow.is_replay == 'response'

    def __str__(self):
        return 'response has been replayed'


class _RegexFilter(TFilter):
    description = 'value'
    extra_flags = 0

    def __init__(self, pattern):
        self.pattern = pattern
        self.expression = _compile(pattern, self.extra_flags)
        self.flag_description = ''
        if self.expression.flags & re.IGNORECASE:
            self.flag_description += 'i'
        if self.expression.flags & re.MULTILINE:
            self.flag_description += 'm'
        if self.expression.flags & re.DOTALL:
            self.flag_description += 's'

    def __str__(self):
        return f'{self.description} matches /{self.pattern}/{self.flag_description}'


class FUrl(_RegexFilter):
    description = 'url'

    def __call__(self, flow):
        return isinstance(flow, HTTPFlow) and _search(self.expression, flow.request.pretty_url)


class FMethod(_RegexFilter):
    description = 'method'

    def __call__(self, flow):
        return isinstance(flow, HTTPFlow) and _search(self.expression, flow.request.method)


class FDomain(_RegexFilter):
    description = 'domain'

    def __call__(self, flow):
        return isinstance(flow, HTTPFlow) and _search(self.expression, flow.request.pretty_host)


class FComment(_RegexFilter):
    description = 'comment'
    extra_flags = re.MULTILINE

    def __call__(self, flow):
        return _search(self.expression, flow.comment)


class FMarker(_RegexFilter):
    description = 'marker'

    def __call__(self, flow):
        return _search(self.expression, flow.marked)


class FMeta(_RegexFilter):
    description = 'flow metadata'
    extra_flags = re.MULTILINE

    def __call__(self, flow):
        return any(_search(self.expression, f'{key}: {value}')
                   for key, value in flow.metadata.items())


class FSrc(_RegexFilter):
    description = 'source address'

    def __call__(self, flow):
        return _search(self.expression, _address(flow.client_conn.peername))


class FDst(_RegexFilter):
    description = 'destination address'

    def __call__(self, flow):
        return _search(self.expression, _address(flow.server_conn.address))


class _MessageRegex(_RegexFilter):
    request = True
    response = True

    def messages(self, flow):
        if not isinstance(flow, HTTPFlow):
            return ()
        result = []
        if self.request:
            result.append(flow.request)
        if self.response and flow.response is not None:
            result.append(flow.response)
        return result


class FHead(_MessageRegex):
    description = 'header'
    extra_flags = re.MULTILINE

    def __call__(self, flow):
        return any(_search(self.expression, line)
                   for message in self.messages(flow)
                   for line in _header_lines(message))


class FHeadRequest(FHead):
    description = 'req. header'
    request = True
    response = False


class FHeadResponse(FHead):
    description = 'resp. header'
    request = False
    response = True


class FBod(_MessageRegex):
    description = 'body'
    extra_flags = re.DOTALL

    def __call__(self, flow):
        return any(_search(self.expression, message.raw_content or b'')
                   for message in self.messages(flow))


class FBodRequest(FBod):
    description = 'body request'
    request = True
    response = False


class FBodResponse(FBod):
    description = 'body response'
    request = False
    response = True


class FContentType(_MessageRegex):
    description = 'content type'

    def __call__(self, flow):
        return any(_search(self.expression, message.headers.get('content-type', ''))
                   for message in self.messages(flow))


class FContentTypeRequest(FContentType):
    description = 'req. content type'
    request = True
    response = False


class FContentTypeResponse(FContentType):
    description = 'resp. content type'
    request = False
    response = True


class FCode(TFilter):
    def __init__(self, code):
        self.code = int(code)

    def __call__(self, flow):
        return (isinstance(flow, HTTPFlow) and flow.response is not None and
                flow.response.status_code == self.code)

    def __str__(self):
        return f'response code is {self.code}'


class FAsset(TFilter):
    _asset_types = ('image/', 'font/', 'text/css', 'javascript', 'application/font')

    def __call__(self, flow):
        if not isinstance(flow, HTTPFlow) or flow.response is None:
            return False
        content_type = flow.response.headers.get('content-type', '').lower()
        return any(token in content_type for token in self._asset_types)

    def __str__(self):
        return 'is asset'


class FNot(TFilter):
    def __init__(self, item):
        self.item = item

    def __call__(self, flow):
        return not self.item(flow)

    def __str__(self):
        if isinstance(self.item, _BinaryFilter):
            return f'not ({self.item})'
        return f'not {self.item}'


class _Grouped(TFilter):
    """Retain one grouping boundary produced by an adjacent operator token."""

    def __init__(self, item):
        self.item = item

    def __call__(self, flow):
        return self.item(flow)

    def __str__(self):
        return f'({self.item})'


class _BinaryFilter(TFilter):
    word = ''

    def __init__(self, left, right):
        self.left = left
        self.right = right

    def _format_item(self, item):
        if isinstance(item, _BinaryFilter) and type(item) is not type(self):
            return f'({item})'
        return str(item)

    def __str__(self):
        left = self._format_item(self.left)
        right = self._format_item(self.right)
        return f'{left} {self.word} {right}'


class FAnd(_BinaryFilter):
    word = 'and'

    def __call__(self, flow):
        return self.left(flow) and self.right(flow)


class FOr(_BinaryFilter):
    word = 'or'

    def __call__(self, flow):
        return self.left(flow) or self.right(flow)


_NO_ARGUMENT = {
    '~a': FAsset, '~all': FAll, '~dns': FDNS, '~e': FErr,
    '~http': FHTTP, '~marked': FMarked, '~q': FReq, '~replay': FReplay,
    '~replayq': FReplayClient, '~replays': FReplayServer, '~s': FResp,
    '~tcp': FTCP, '~udp': FUDP, '~websocket': FWebSocket,
}
_REGEX_ARGUMENT = {
    '~b': FBod, '~bq': FBodRequest, '~bs': FBodResponse,
    '~comment': FComment, '~d': FDomain, '~dst': FDst, '~h': FHead,
    '~hq': FHeadRequest, '~hs': FHeadResponse, '~m': FMethod,
    '~marker': FMarker, '~meta': FMeta, '~src': FSrc,
    '~t': FContentType, '~tq': FContentTypeRequest,
    '~ts': FContentTypeResponse, '~u': FUrl,
}


def _tokens(text):
    result = []
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        if text[offset] in '&|' and text[offset:offset + 2] == text[offset] * 2:
            result.append(text[offset:offset + 2])
            offset += 2
            continue
        if text[offset] in '()!&|':
            result.append(text[offset])
            offset += 1
            continue
        if text[offset] in ('"', "'"):
            quote = text[offset]
            offset += 1
            value = []
            while offset < len(text) and text[offset] != quote:
                if text[offset] == '\\' and offset + 1 < len(text):
                    offset += 1
                    escaped = text[offset]
                    value.append({
                        'b': '\b',
                        'f': '\f',
                        'n': '\n',
                        'r': '\r',
                        't': '\t',
                    }.get(escaped, escaped))
                else:
                    value.append(text[offset])
                offset += 1
            if offset >= len(text):
                raise ValueError('Invalid filter expression: ' + repr(text))
            offset += 1
            result.append(''.join(value))
            continue
        start = offset
        while offset < len(text) and not text[offset].isspace():
            character = text[offset]
            if character in '()!\'"':
                break
            if character == '~' and offset > start:
                break
            offset += 1
        if start == offset:
            raise ValueError('Invalid filter expression: ' + repr(text))
        token = text[start:offset]
        # Reference operators begin the next lexical item. When joined to the
        # preceding bare token they remain part of that token instead. A closing
        # parenthesis directly after a no-argument selector is rejected by the
        # same boundary rule; spelling it with a separating space is unambiguous.
        if token in _NO_ARGUMENT and offset < len(text) and text[offset] == ')':
            raise ValueError('Invalid filter expression: ' + repr(text))
        result.append(token)
    return result


class _Parser:
    def __init__(self, text):
        self.text = text
        self.tokens = _tokens(text)
        self.offset = 0

    def peek(self):
        return self.tokens[self.offset] if self.offset < len(self.tokens) else None

    def take(self):
        value = self.peek()
        self.offset += 1
        return value

    def expression(self):
        result = self.conjunction()
        while self.peek() in ('|', '||'):
            operator = self.take()
            if operator == '||':
                result = FOr(result, FUrl('|'))
                if self.peek() not in (None, ')', '|', '||'):
                    result = FAnd(result, self.conjunction())
                continue
            result = FOr(result, self.conjunction())
        return result

    def conjunction(self):
        result = self.unary()
        group_before_next = False
        while self.peek() is not None and self.peek() not in (')', '|', '||'):
            operator = self.peek()
            if operator == '&':
                self.take()
            elif operator == '&&':
                self.take()
                result = FAnd(result, FUrl('&'))
                group_before_next = True
                continue
            if group_before_next:
                result = _Grouped(result)
                group_before_next = False
            result = FAnd(result, self.unary())
        return result

    def unary(self):
        if self.peek() == '!':
            self.take()
            return FNot(self.unary())
        if self.peek() == '(':
            self.take()
            result = self.expression()
            if self.take() != ')':
                self.fail()
            return result
        token = self.take()
        if token is None or token == ')':
            self.fail()
        # The public grammar treats an operator token as a URL expression when
        # it appears where a primary expression is required. This makes a lone
        # '&' or '|' valid and gives repeated operators their observed meaning:
        # the first token is binary, the second is a URL regex.
        if token in ('&', '|', '&&', '||'):
            return FUrl(token)
        if token in _NO_ARGUMENT:
            return _NO_ARGUMENT[token]()
        if token == '~c':
            value = self.take()
            match = re.match(r'(\d+)(.*)', value or '')
            if match is None:
                self.fail()
            code, remainder = match.groups()
            if remainder:
                self.tokens.insert(self.offset, remainder)
            return FCode(code)
        if token in _REGEX_ARGUMENT:
            value = self.take()
            if value is None or value in ('(', ')', '!', '&', '|'):
                self.fail()
            return _REGEX_ARGUMENT[token](value)
        if token.startswith('~'):
            self.fail()
        return FUrl(token)

    def fail(self):
        raise ValueError('Invalid filter expression: ' + repr(self.text))


def parse(text: str) -> TFilter:
    if text == '':
        raise ValueError('Empty filter expression')
    try:
        parser = _Parser(text)
        result = parser.expression()
        if parser.peek() is not None:
            parser.fail()
        return result
    except ValueError as error:
        message = 'Invalid filter expression: ' + repr(text)
        if str(error) == message:
            raise
        raise ValueError(message) from error


def match(flt, flow: Flow) -> bool:
    if flt is None:
        return True
    if isinstance(flt, str):
        flt = parse(flt)
    return bool(flt(flow))


match_all = FAll()
