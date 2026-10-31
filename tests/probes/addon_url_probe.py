"""Record URL helper behavior from an isolated compatibility module."""

import json

from mitmproxy.net.http import url


def normalize(value):
    if isinstance(value, bytes):
        return {'bytes': value.hex()}
    if isinstance(value, (tuple, list)):
        return [normalize(item) for item in value]
    return value


def outcome(callback):
    try:
        return {'ok': True, 'value': normalize(callback())}
    except Exception as error:
        return {
            'ok': False,
            'type': type(error).__name__,
            'message': str(error),
        }


cases = {}

for value in ('http', 'https', 'HTTP', 'ws', '', b'http', b'https'):
    cases['port:' + repr(value)] = outcome(lambda value=value: url.default_port(value))

for arguments in (
    ('http', 'example.com', 80), ('http', 'example.com', 81),
    ('https', '::1', 443), ('https', '::1', 444),
    (b'http', b'example.com', 80),
):
    cases['hostport:' + repr(arguments)] = outcome(
        lambda arguments=arguments: url.hostport(*arguments)
    )

for value in (
    'example.com', 'a-b.example', '', 'bad host', '[::1]', '::1',
    'xn--bcher-kva.example', 'example.com.', 'example.com..',
    '-bad.example', 'bad-.example', '-', '.', 'a..b',
    'under_score.example', 'slash/example', 'bücher.example',
    'x' * 63 + '.example', 'x' * 64 + '.example',
    'x' * 256, None, 1,
    b'example.com', b'bad host', 'bücher.example'.encode(), b'\xff',
):
    cases['host:' + repr(value)] = outcome(lambda value=value: url.is_valid_host(value))

for value in (-1, 0, 1, 65535, 65536, '80', None, True):
    cases['valid-port:' + repr(value)] = outcome(
        lambda value=value: url.is_valid_port(value)
    )

for value in ('a=1&b=2', 'a=&a=2', 'a+b=c%20d', 'bad=%zz', '', b'a=1'):
    cases['decode:' + repr(value)] = outcome(lambda value=value: url.decode(value))

for fields, similar in (
    ([('a', '1'), ('b', '2')], None),
    ([('a', 'x y')], None),
    ([('a', 'x y')], 'a+b=c+d'),
    ([], None),
    ([('a', 'é')], None),
):
    key = 'encode:' + repr((fields, similar))
    cases[key] = outcome(
        lambda fields=fields, similar=similar: url.encode(fields, similar)
    )

for value in (
    'example.com:443', 'example.com', '[::1]:443', '[::1]', '::1',
    'bad:port', 'example.com:65536', 'user@example.com:80', '',
    b'example.com:443',
):
    for check in (True, False):
        key = 'authority:' + repr(value) + ':' + str(check)
        cases[key] = outcome(
            lambda value=value, check=check: url.parse_authority(value, check)
        )

for value in (
    'http://example.com/path', 'https://example.com:8443/a?b=1',
    'http://[::1]/', '//example.com/path', 'not a url',
    'http://example.com:bad/', 'http://example.com:65536/',
    b'http://example.com/a',
):
    cases['parse:' + repr(value)] = outcome(lambda value=value: url.parse(value))

for arguments in (
    ('http', 'example.com', 80, '/a'),
    ('http', 'example.com', 81, '/a'),
    ('https', '::1', 443, '/'),
    (b'http', b'example.com', 80, b'/a'),
):
    cases['unparse:' + repr(arguments)] = outcome(
        lambda arguments=arguments: url.unparse(*arguments)
    )

for value, safe in (('a b/c', '/'), ('a/b?c', '/'), ('é', '/')):
    cases['quote:' + repr((value, safe))] = outcome(
        lambda value=value, safe=safe: url.quote(value, safe)
    )

for value in ('a%20b', 'a+b', '%zz', '%C3%A9'):
    cases['unquote:' + repr(value)] = outcome(lambda value=value: url.unquote(value))

print(json.dumps({'reference': '12.3.1', 'cases': cases}, sort_keys=True))
