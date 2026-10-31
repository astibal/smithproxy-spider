"""Record public string-helper behavior from the isolated reference runtime."""

import json

from mitmproxy.utils import strutils


def normalize(value):
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if isinstance(value, tuple):
        return [normalize(item) for item in value]
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    return value


def outcome(callback):
    try:
        value = callback()
        if hasattr(value, '__next__'):
            value = list(value)
        return {'ok': True, 'value': normalize(value)}
    except Exception as error:
        return {
            'ok': False,
            'type': type(error).__name__,
            'message': str(error),
        }


cases = {}

for index, value in enumerate(('', 'line', 'line\n', 'line\n\n', b'line\n')):
    cases[f'clean_{index}'] = outcome(
        lambda value=value: strutils.clean_hanging_newline(value)
    )

for index, (value, count) in enumerate((
    ('', 0), ('one\ntwo\nthree', 0), ('one\ntwo\nthree', 1),
    ('one\ntwo\nthree', 2), ('one\ntwo\nthree', 3),
    ('one\ntwo\nthree', 4), ('one\ntwo\nthree', -1),
    ('one\r\ntwo\r\nthree', 2),
)):
    cases[f'cut_{index}'] = outcome(
        lambda value=value, count=count: strutils.cut_after_n_lines(value, count)
    )

for index, (value, keep_spacing) in enumerate((
    ('plain', True), ('a\x00b\x1fc\x7f', True),
    ('a\tb\nc\rd', True), ('a\tb\nc\rd', False), ('λ\x80', True),
)):
    cases[f'control_{index}'] = outcome(
        lambda value=value, keep_spacing=keep_spacing:
            strutils.escape_control_characters(value, keep_spacing)
    )

for index, value in enumerate((
    b'', b'plain text', b'\x00', b'abc\x00', bytes(range(32)),
    b'\x89PNG\r\n\x1a\n', bytes(range(256)), 'text',
)):
    cases[f'binary_{index}'] = outcome(
        lambda value=value: strutils.is_mostly_bin(value)
    )

for index, value in enumerate((
    b'', b' ', b'<root/>', b'<?xml version="1.0"?><root/>',
    b'\xef\xbb\xbf<root/>', b'not xml', b'  <broken', '<root/>',
)):
    cases[f'xml_{index}'] = outcome(lambda value=value: strutils.is_xml(value))

for index, value in enumerate((b'', b'abc', bytes(range(16)), bytes(range(20)), 'abc')):
    cases[f'hexdump_{index}'] = outcome(lambda value=value: strutils.hexdump(value))

area_patterns = [r'/\*[\s\S]*?\*/', r'".*?"']
for index, value in enumerate((
    '', 'plain', 'a /* secret */ b', 'a "one" b /* two */ c',
    'unterminated /* comment',
)):
    cases[f'split_{index}'] = outcome(
        lambda value=value: strutils.split_special_areas(value, area_patterns)
    )

quoted = ["'" + strutils.SINGLELINE_CONTENT + "'"]
for index, (value, controls) in enumerate((
    ("plain", '{}'), ("before '{}' after", '{}'),
    ("before '{x}' after", '{}'), ("'\\''", "'"),
)):
    cases[f'escape_area_{index}'] = outcome(
        lambda value=value, controls=controls:
            strutils.escape_special_areas(value, quoted, controls)
    )

for index, value in enumerate(('plain', '\ue000\ue07f\ue0ff', "before '\ue07b' after")):
    cases[f'unescape_area_{index}'] = outcome(
        lambda value=value: strutils.unescape_special_areas(value)
    )

cases['constants'] = {
    name: getattr(strutils, name)
    for name in (
        'MULTILINE_CONTENT', 'MULTILINE_CONTENT_LINE_CONTINUATION',
        'NO_ESCAPE', 'SINGLELINE_CONTENT',
    )
}

print(json.dumps({'reference': '12.3.1', 'cases': cases}, sort_keys=True))
