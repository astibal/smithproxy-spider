"""Public byte/text helpers used by addon examples and diagnostics."""

import codecs
import re


MULTILINE_CONTENT = r'[\s\S]*?'
MULTILINE_CONTENT_LINE_CONTINUATION = r'(?:.|(?<=\\)\n)*?'
NO_ESCAPE = r'(?<!\\)(?:\\\\)*'
SINGLELINE_CONTENT = r'.*?'


def clean_hanging_newline(value):
    """Remove one editor-added final newline from text values."""
    if isinstance(value, str) and value.endswith('\n'):
        return value[:-1]
    return value


def cut_after_n_lines(content, count):
    """Return at most ``count`` complete or partial lines."""
    assert count > 0
    return ''.join(content.splitlines(keepends=True)[:count])


def escape_control_characters(text, keep_spacing=True):
    """Replace C0 controls and DEL with a visible full stop."""
    spacing = '\t\n\r' if keep_spacing else ''
    result = []
    for character in text:
        value = ord(character)
        if character in spacing or value >= 32 and value != 127:
            result.append(character)
        else:
            result.append('.')
    return ''.join(result)


def hexdump(data):
    """Yield offset, padded hexadecimal bytes, and an ASCII view."""
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hexadecimal = ' '.join(f'{value:02x}' for value in chunk)
        text = ''.join(
            chr(value) if 32 <= value <= 126 else '.'
            for value in chunk
        )
        yield f'{offset:010x}', f'{hexadecimal:<47}', text


def is_mostly_bin(data):
    """Classify a byte prefix using the reference's control-byte heuristic."""
    sample = data[:100]
    if not sample:
        return False
    binary = sum(
        value < 9 or 13 < value < 32 or value > 126
        for value in sample
    )
    return binary / len(sample) > 0.3


def is_xml(data):
    """Recognize a byte string that starts like XML after ASCII whitespace."""
    if not isinstance(data, bytes):
        return False
    return bool(re.match(rb'\s*<', data))


def split_special_areas(data, area_delimiter):
    """Alternate ordinary text and regex-delimited special regions."""
    patterns = tuple(area_delimiter)
    if not patterns:
        return [data]
    return re.split('(' + '|'.join(patterns) + ')', data)


def escape_special_areas(data, area_delimiter, control_characters):
    """Protect selected characters inside regex-delimited special regions."""
    controls = frozenset(control_characters)
    if any(not 0 < ord(character) < 256 for character in controls):
        raise ValueError('Control characters must have values between 1 and 255')

    areas = split_special_areas(data, area_delimiter)
    for index in range(1, len(areas), 2):
        areas[index] = ''.join(
            chr(0xE000 + ord(character)) if character in controls else character
            for character in areas[index]
        )
    return ''.join(areas)


def unescape_special_areas(data):
    """Restore characters protected by :func:`escape_special_areas`."""
    result = []
    for character in data:
        value = ord(character)
        if 0xE000 <= value <= 0xE0FF:
            result.append(chr(value - 0xE000))
        else:
            result.append(character)
    return ''.join(result)


def always_bytes(value, *encode_args):
    if value is None or isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(*encode_args)
    raise TypeError(f'Expected str or bytes, but got {type(value).__name__}.')


def always_str(value, *decode_args):
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode(*decode_args)
    raise TypeError(f'Expected str or bytes, but got {type(value).__name__}.')


def bytes_to_escaped_str(data, keep_spacing=False, escape_single_quotes=False):
    if not isinstance(data, bytes):
        raise ValueError(f'data must be bytes, but is {type(data).__name__}')
    result = []
    for value in data:
        if value == 0x5c:
            result.append('\\\\')
        elif value == 0x27 and escape_single_quotes:
            result.append("\\'")
        elif value in (0x09, 0x0a, 0x0d):
            if keep_spacing:
                result.append(chr(value))
            else:
                result.append({0x09: '\\t', 0x0a: '\\n', 0x0d: '\\r'}[value])
        elif 0x20 <= value <= 0x7e:
            result.append(chr(value))
        else:
            result.append(f'\\x{value:02x}')
    return ''.join(result)


def escaped_str_to_bytes(data):
    if not isinstance(data, str):
        raise ValueError(f'data must be str, but is {type(data).__name__}')

    def preserve_unknown(match):
        token = match.group()
        if len(token) == 2 and token[1] in "\\abfnrtv'\"01234567x":
            return token
        if len(token) == 1:
            return token
        return '\\' + token

    escaped = re.sub(r'\\(?:.|$)', preserve_unknown, data, flags=re.DOTALL)
    if escaped.endswith('\\'):
        raise ValueError('Trailing \\ in string')
    return codecs.escape_decode(escaped.encode('utf-8'))[0]
