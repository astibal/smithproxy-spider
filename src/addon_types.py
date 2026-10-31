"""Public command annotation markers owned by Spider's addon facade."""

from collections.abc import Sequence
import glob
import os
import string

import emoji


class Choice:
    """Select one string returned by another addon command."""

    def __init__(self, options_command):
        self.options_command = options_command


class Cmd(str):
    """Name of a command registered in the current addon generation."""


class CmdArgs(str):
    """An unmodified command argument string."""


class CutSpec(Sequence):
    """Annotation marker for comma-separated cut field names."""


class Data(Sequence):
    """Annotation marker for command results containing display data."""


class Marker(str):
    """A console marker name or one-character ASCII marker."""


class Path(str):
    """A filesystem path with user-home expansion for textual arguments."""


class Space(str):
    """Parser marker retained for import compatibility."""


class Unknown(str):
    """Parser marker retained for import compatibility."""


def _build_marker_choices():
    aliases = []
    for names in emoji.EMOJI_DATA.values():
        aliases.append(names['en'])
        aliases.extend(names.get('alias', ()))
    return ('true', 'false', ':default:', *sorted(set(aliases)),
            *string.ascii_lowercase, *string.ascii_uppercase, *string.digits)


_MARKER_CHOICES = _build_marker_choices()
ALL_MARKERS = list(_MARKER_CHOICES)


def marker_choices():
    """Return marker spellings accepted by the public textual command API."""
    return _MARKER_CHOICES


class TypeManager:
    """Map public annotation types to their command parser metadata."""

    def __init__(self, *type_classes):
        self.typemap = {}
        for type_class in type_classes:
            handler = type_class()
            self.typemap[handler.typ] = handler

    def get(self, annotation, default=None):
        handler = self.typemap.get(annotation)
        if handler is None:
            handler = self.typemap.get(type(annotation))
        return default if handler is None else handler


class _CommandType:
    typ = None
    display = None

    def parse(self, manager, annotation, value):
        from addon_commands import _convert_argument
        return _convert_argument(manager, value, annotation)

    def is_valid(self, manager, annotation, value):
        from addon_commands import _result_contract
        return _result_contract(manager, annotation, value)[0]

    def completion(self, manager, annotation, value):
        return []


class _StringType(_CommandType):
    typ = str
    display = 'str'


class _IntegerType(_CommandType):
    typ = int
    display = 'int'


class _BooleanType(_CommandType):
    typ = bool
    display = 'bool'

    def completion(self, manager, annotation, value):
        return ['false', 'true']


class _BytesType(_CommandType):
    typ = bytes
    display = 'bytes'


class _ArgumentsType(_CommandType):
    typ = CmdArgs
    display = 'arg'


class _ChoiceType(_CommandType):
    typ = Choice
    display = 'choice'

    def completion(self, manager, annotation, value):
        return manager.call(annotation.options_command)


class _CommandNameType(_CommandType):
    typ = Cmd
    display = 'cmd'

    def completion(self, manager, annotation, value):
        return list(manager.commands)


class _CutSpecType(_CommandType):
    typ = CutSpec
    display = 'cut[]'

    _fields = (
        'request.method', 'request.scheme', 'request.host',
        'request.http_version', 'request.port', 'request.path', 'request.url',
        'request.text', 'request.content', 'request.raw_content',
        'request.timestamp_start', 'request.timestamp_end', 'request.header[',
        'response.status_code', 'response.reason', 'response.text',
        'response.content', 'response.timestamp_start',
        'response.timestamp_end', 'response.raw_content', 'response.header[',
        'client_conn.peername.port', 'client_conn.peername.host',
        'client_conn.tls_version', 'client_conn.sni',
        'client_conn.tls_established', 'server_conn.address.port',
        'server_conn.address.host', 'server_conn.ip_address.host',
        'server_conn.tls_version', 'server_conn.sni',
        'server_conn.tls_established',
    )

    def completion(self, manager, annotation, value):
        # These are public cut-expression field names, not transport state.
        # Completion does not filter by the already-entered prefix.
        return list(self._fields)


class _DataType(_CommandType):
    typ = Data
    display = 'data[][]'

    def completion(self, manager, annotation, value):
        raise ValueError('data cannot be passed as argument')


class _MarkerType(_CommandType):
    typ = Marker
    display = 'marker'

    def completion(self, manager, annotation, value):
        return ALL_MARKERS.copy()


class _PathType(_CommandType):
    typ = Path
    display = 'path'

    def completion(self, manager, annotation, value):
        expanded = os.path.expanduser(value)
        if not expanded:
            pattern = './*'
        elif os.path.isdir(expanded):
            pattern = expanded.rstrip(os.sep) + os.sep + '*'
        else:
            pattern = expanded + '*'
        candidates = glob.glob(pattern)
        if not candidates:
            return [value]
        result = []
        home = os.path.expanduser('~')
        for candidate in candidates:
            if os.path.isdir(candidate):
                candidate += '/'
            if value.startswith('~') and candidate.startswith(home):
                candidate = '~' + candidate[len(home):]
            result.append(candidate)
        return sorted(result)


class _FlowType(_CommandType):
    display = 'flow'


class _FlowsType(_CommandType):
    display = 'flow[]'


class _StringsType(_CommandType):
    typ = Sequence[str]
    display = 'str[]'


from addon_flow import Flow

_FlowType.typ = Flow
_FlowsType.typ = Sequence[Flow]

CommandTypes = TypeManager(
    _ArgumentsType, _BooleanType, _ChoiceType, _CommandNameType,
    _CutSpecType, _DataType, _FlowType, _FlowsType, _IntegerType,
    _MarkerType, _PathType, _StringType, _StringsType, _BytesType,
)
