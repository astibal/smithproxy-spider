"""Public Content-Type helpers used by addon scripts.

These helpers intentionally parse a flat parameter list.  They are not the MIME
parser used by message form views, and must not be used for HTTP framing.
"""

from collections import OrderedDict
import re


def parse_content_type(value):
    fields = value.split(';')
    media_type = fields.pop(0)
    if '/' not in media_type:
        return None

    main_type, subtype = media_type.split('/', 1)
    parameters = OrderedDict()
    for field in fields:
        if '=' not in field:
            continue
        name, parameter_value = field.split('=', 1)
        parameters[name.strip()] = parameter_value.strip()
    return main_type.lower(), subtype.lower(), parameters


def assemble_content_type(main_type, subtype, parameters):
    value = main_type + '/' + subtype
    for name, parameter_value in parameters.items():
        value += '; ' + name + '=' + parameter_value
    return value


_UTF8_TYPES = frozenset({
    'application/javascript',
    'application/x-javascript',
    'text/css',
    'text/javascript',
})

_HTML_CHARSET = re.compile(
    br'<meta\s+[^>]*charset\s*=\s*["\']?\s*([^\s"\'/>;]+)',
    re.IGNORECASE,
)
_HTML_HTTP_EQUIV = re.compile(
    br'<meta\s+[^>]*http-equiv\s*=\s*["\']?content-type["\']?[^>]*'
    br'content\s*=\s*["\'][^>]*charset\s*=\s*([^\s"\';>]+)',
    re.IGNORECASE,
)
_XML_ENCODING = re.compile(
    br'^\s*<\?xml\s+[^>]*encoding\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def infer_content_encoding(content_type, content=b''):
    parsed = parse_content_type(content_type)
    if parsed is None:
        return 'latin-1'

    _, _, parameters = parsed
    if 'charset' in parameters:
        return parameters['charset']

    # Encoding inference is intentionally case-sensitive in the public v12
    # contract, even though parse_content_type() normalizes its returned media
    # type.  Preserve that observable asymmetry.
    media_type_field = content_type.split(';', 1)[0]
    main_type, subtype = media_type_field.split('/', 1)
    media_type = main_type + '/' + subtype
    if media_type == 'application/json' or subtype.endswith('+json'):
        return 'utf8'
    if media_type in _UTF8_TYPES:
        return 'utf8'

    if media_type in ('text/html', 'application/xhtml+xml'):
        for expression in (_HTML_CHARSET, _HTML_HTTP_EQUIV):
            match = expression.search(content)
            if match is not None:
                return match.group(1).decode('ascii')
        return 'utf8'

    if media_type in ('text/xml', 'application/xml') or subtype.endswith('+xml'):
        match = _XML_ENCODING.search(content)
        if match is not None:
            return match.group(1).decode('ascii')
        return 'utf8'

    return 'latin-1'
