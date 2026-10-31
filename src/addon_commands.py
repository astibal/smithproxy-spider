"""Generation-local addon commands, without a proxy console or transport engine."""

from collections import OrderedDict
from collections.abc import Sequence
from functools import wraps
import inspect
import logging
import codecs
import re
from typing import NamedTuple

from addon_flow import Flow
from addon_types import (
    Choice, Cmd, CmdArgs, CommandTypes, CutSpec, Data, Marker, Path,
    Space, Unknown, marker_choices,
)
from addon_strutils import escaped_str_to_bytes


_ARGUMENT_TYPES = (str, int, bool, bytes, Flow, Sequence[Flow], Sequence[str],
                   Cmd, CmdArgs, CutSpec, Data, Marker, Path)


class CommandError(Exception):
    """A command name, signature or textual argument is invalid."""


class ParseResult(NamedTuple):
    value: str
    type: type
    valid: bool


class CommandParameter(NamedTuple):
    name: str
    type: type
    kind: inspect._ParameterKind = inspect.Parameter.POSITIONAL_OR_KEYWORD


def _command_words(text):
    """Split command words without shell expansion or backslash quoting.

    Adjacent quoted and unquoted sections are separate arguments. An unfinished
    quoted section consumes the remainder, retaining its opening quote.
    """
    words = []
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        start = offset
        if text[offset] in ('"', "'"):
            closing = text.find(text[offset], offset + 1)
            if closing < 0:
                words.append(text[offset:])
                break
            words.append(text[offset + 1:closing])
            offset = closing + 1
        else:
            while offset < len(text) and not text[offset].isspace() and text[offset] not in ('"', "'"):
                offset += 1
            words.append(text[start:offset])
    return words


def _partial_tokens(text):
    # mitmproxy's incremental parser displays tabs as conventional eight-column
    # tab stops. Expand the complete line so the token retains its real column.
    text = text.expandtabs(8)
    tokens = []
    offset = 0
    while offset < len(text):
        start = offset
        if text[offset].isspace():
            while offset < len(text) and text[offset].isspace():
                offset += 1
            tokens.append((text[start:offset], True))
            continue
        if text[offset] in ('"', "'"):
            closing = text.find(text[offset], offset + 1)
            if closing < 0:
                tokens.append((text[offset:], False))
                break
            offset = closing + 1
            tokens.append((text[start:offset], False))
            continue
        while offset < len(text) and not text[offset].isspace():
            offset += 1
        tokens.append((text[start:offset], False))
    return tokens


def _text_argument(value):
    # Preserve unrecognized escapes and a final slash without generating
    # Python's invalid-escape warnings. Consume pairs so an escaped slash is
    # not reconsidered as the start of another escape. Known malformed escapes
    # still fail in the codec with their original error position.
    def preserve_unknown(match):
        token = match.group()
        if len(token) == 2 and token[1] in "\\abfnrtv'\"01234567xuUN":
            return token
        return '\\' + token

    escaped = re.sub(r'\\(?:.|$)', preserve_unknown, value, flags=re.DOTALL)
    try:
        return codecs.decode(escaped.encode('raw_unicode_escape'), 'unicode_escape')
    except UnicodeError as error:
        raise CommandError(str(error)) from error


def _bytes_argument(value):
    try:
        return escaped_str_to_bytes(value)
    except ValueError as error:
        raise CommandError(str(error)) from error


def _bind(signature, args, kwargs):
    try:
        return signature.bind(*args, **kwargs)
    except TypeError as error:
        raise CommandError('command argument mismatch: ' + str(error)) from error


def _valid_collection(result, item_type):
    # The public command contract validates iterable elements, not the
    # container's declared type. Preserve the returned object; validation can
    # consume an iterator. String collections specifically exclude text/bytes.
    if item_type is str and isinstance(result, (str, bytes)):
        return False
    try:
        return all(isinstance(item, item_type) for item in result)
    except TypeError:
        return False


def _valid_data(result):
    if isinstance(result, str):
        return True
    try:
        return all(_valid_data(item) for item in result)
    except TypeError:
        return False


def _supported_annotation(annotation):
    return annotation in _ARGUMENT_TYPES or isinstance(annotation, Choice)


def typename(annotation):
    handler = CommandTypes.get(annotation)
    if handler is None:
        name = getattr(annotation, '__name__', str(annotation))
        raise CommandError('unsupported type: ' + name)
    return handler.display


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def parsearg(manager, spec, argtype):
    handler = CommandTypes.get(argtype)
    if handler is None:
        typename(argtype)
    return handler.parse(manager, argtype, spec)


def verify_arg_signature(function, args, kwargs):
    _bind(inspect.signature(function), args, kwargs)


def argument(name, type):
    def decorator(function):
        assert name in function.__annotations__
        function.__annotations__[name] = type
        return function
    return decorator


def _result_contract(manager, annotation, result):
    if annotation in (str, int, bool, bytes):
        return isinstance(result, annotation), annotation.__name__
    if annotation is Flow:
        return isinstance(result, Flow), 'flow'
    if annotation in (Sequence[Flow], Sequence[str]):
        item_type = Flow if annotation == Sequence[Flow] else str
        expected = 'flow[]' if item_type is Flow else 'str[]'
        return _valid_collection(result, item_type), expected
    if annotation in (CmdArgs, Path):
        expected = 'arg' if annotation is CmdArgs else 'path'
        return isinstance(result, str), expected
    if annotation is Marker:
        return result in marker_choices(), 'marker'
    if annotation is Cmd:
        return result in manager.commands, 'cmd'
    if annotation is CutSpec:
        return False, 'cut[]'
    if annotation is Data:
        return _valid_data(result), 'data[][]'
    if isinstance(annotation, Choice):
        valid = isinstance(result, str) and result in manager.call(annotation.options_command)
        return valid, 'choice'
    if annotation in (None, type(None), inspect.Signature.empty):
        return result is None, 'None'
    raise CommandError('Unsupported command return type: ' + str(annotation))


def _convert_argument(manager, value, annotation):
    if annotation is str:
        return _text_argument(value)
    if annotation is bytes:
        return _bytes_argument(value)
    if annotation is bool:
        if value not in ('true', 'false'):
            raise CommandError("Booleans are 'true' or 'false', got " + value)
        return value == 'true'
    if annotation is int:
        try:
            return annotation(value)
        except ValueError as error:
            raise CommandError(str(error)) from error
    if annotation == Sequence[str]:
        return value.split(',')
    if annotation is CmdArgs:
        return value
    if annotation is Cmd:
        manager._lookup(value)
        return value
    if annotation is Path:
        import os
        return os.path.expanduser(value)
    if annotation is Marker:
        if value == 'true':
            return ':default:'
        if value == 'false':
            return ''
        if value not in marker_choices():
            raise CommandError('Invalid choice.')
        return value
    if annotation is CutSpec:
        return value.split(',')
    if annotation is Data:
        raise CommandError('data cannot be passed as argument')
    if isinstance(annotation, Choice):
        if value not in manager.call(annotation.options_command):
            raise CommandError('Invalid choice.')
        return value
    if annotation is Flow or annotation == Sequence[Flow]:
        # Resolve through an explicitly registered command. Do not invent a
        # separate live-flow inventory or expose another generation.
        flows = manager.call('view.flows.resolve', value)
        if annotation is Flow:
            if len(flows) != 1:
                raise CommandError(f'Command requires one flow, specification matched {len(flows)}.')
            return flows[0]
        return flows
    raise CommandError('Unsupported textual command argument type: ' + str(annotation))


def command(name=None):
    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def invoke(*args, **kwargs):
            _bind(signature, args, kwargs)
            return function(*args, **kwargs)

        # An omitted or empty public name falls back to the callback name.
        # This also keeps collection from creating an unreachable empty key.
        invoke.command_name = name or function.__name__
        return invoke

    return decorate


class Command:
    """One validated addon command in a generation-local registry."""

    def __init__(self, manager, name, func):
        self.manager = manager
        self.name = name
        self.func = func
        self.signature = inspect.signature(func, eval_str=True)
        self.help = (inspect.getdoc(func) or '').replace('\n', ' ')
        for name, parameter in self.signature.parameters.items():
            if not _supported_annotation(parameter.annotation):
                raise CommandError(f'Argument {name} has an unknown type '
                                   f'{parameter.annotation} in {func}.')
        result_type = self.signature.return_annotation
        if not (_supported_annotation(result_type) or
                result_type in (None, type(None), inspect.Signature.empty)):
            raise CommandError(f'Return type has an unknown type ({result_type}) in {func}.')

    @property
    def return_type(self):
        return self.signature.return_annotation

    @property
    def parameters(self):
        return [
            CommandParameter(parameter.name, parameter.annotation, parameter.kind)
            for parameter in self.signature.parameters.values()
        ]

    def signature_help(self):
        names = []
        for parameter in self.signature.parameters.values():
            prefix = '*' if parameter.kind == inspect.Parameter.VAR_POSITIONAL else ''
            names.append(prefix + parameter.name)
        return f'{self.name} {" ".join(names)} -> {typename(self.return_type)}'

    def prepare_args(self, args):
        try:
            bound = self.signature.bind(*args)
        except TypeError as error:
            expected = OrderedDict(self.signature.parameters)
            raise CommandError('Command argument mismatch: \n'
                               f'    Expected: {expected}\n'
                               f'    Received: {args}') from error
        for name, value in tuple(bound.arguments.items()):
            parameter = self.signature.parameters[name]
            if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
                bound.arguments[name] = tuple(
                    _convert_argument(self.manager, item, parameter.annotation)
                    for item in value
                )
            else:
                bound.arguments[name] = _convert_argument(
                    self.manager, value, parameter.annotation)
        # Defaults are already typed Python values supplied by the addon. Only
        # textual arguments from the caller pass through command conversion.
        bound.apply_defaults()
        return bound

    def call(self, args):
        bound = self.prepare_args(args)
        result = self.func(*bound.args, **bound.kwargs)
        annotation = self.signature.return_annotation
        valid, expected = _result_contract(self.manager, annotation, result)
        if not valid:
            raise CommandError(f'{self.name} returned unexpected data - expected {expected}')
        return result


class CommandManager:
    """Keep addon commands in the same sandbox and generation as their owners.

    Removal from the active addon chain does not unregister a command in the
    reference API. Only retirement of this generation releases this registry.
    Native proxy commands are not synthesized here.
    """

    def __init__(self, master):
        self.master = master
        self.commands = {}

    def add(self, path, func):
        if path not in self.commands and len(self.commands) >= 1024:
            raise CommandError('Addon command limit reached')
        self.commands[path] = Command(self, path, func)

    def collect_commands(self, addon):
        for name in dir(addon):
            function = getattr(addon, name)
            path = getattr(function, 'command_name', None)
            if path is not None and callable(function):
                try:
                    self.add(path, function)
                except CommandError as error:
                    # Automatic collection skips only the invalid declaration.
                    # Direct add()/loader.add_command() still reports failure
                    # to its caller, and an earlier registration is retained.
                    logging.warning('Could not register addon command %s: %s', path, error)

    def _lookup(self, name):
        try:
            return self.commands[name]
        except KeyError:
            raise CommandError('Unknown command: ' + name) from None

    def call(self, command_name, *args):
        registered = self._lookup(command_name)
        _bind(registered.signature, args, {})
        # Typed calls deliberately bypass textual conversion and result checks.
        return registered.func(*args)

    def call_strings(self, command_name, args):
        return self._lookup(command_name).call(args)

    def execute(self, cmdstr):
        words = _command_words(cmdstr)
        if not words:
            raise CommandError('Invalid command: ' + repr(cmdstr))
        return self.call_strings(words[0], words[1:])

    def parse_partial(self, cmdstr):
        tokens = _partial_tokens(cmdstr)
        if not tokens:
            return [], [
                CommandParameter('', Cmd),
                CommandParameter('', CmdArgs),
            ]

        parsed = []
        command_entry = None
        command_seen = False
        parameters = []
        parameter_index = 0
        for token, is_space in tokens:
            if is_space:
                parsed.append(ParseResult(token, Space, True))
                continue
            if not command_seen:
                command_seen = True
                valid = token in self.commands
                parsed.append(ParseResult(token, Cmd, valid))
                if valid:
                    command_entry = self.commands[token]
                    parameters = list(command_entry.signature.parameters.values())
                continue
            if command_entry is None or parameter_index >= len(parameters):
                parsed.append(ParseResult(token, Unknown, False))
                continue
            parameter = parameters[parameter_index]
            try:
                parsearg(self, token, parameter.annotation)
                valid = True
            except (CommandError, ValueError):
                valid = False
            parsed.append(ParseResult(token, parameter.annotation, valid))
            if parameter.kind != inspect.Parameter.VAR_POSITIONAL:
                parameter_index += 1

        remaining = []
        if command_entry is not None:
            for parameter in parameters[parameter_index:]:
                remaining.append(CommandParameter(
                    parameter.name, parameter.annotation, parameter.kind))
        return parsed, remaining

    def dump(self, out=None):
        if out is None:
            import sys
            out = sys.stdout
        for name in sorted(self.commands):
            registered = self.commands[name]
            if registered.help:
                print('# ' + registered.help, file=out)
            print(registered.signature_help(), file=out)
            print(file=out)
