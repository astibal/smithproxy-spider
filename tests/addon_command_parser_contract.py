"""Public incremental command parsing observations shared with the reference."""

from collections.abc import Sequence
import inspect
from types import SimpleNamespace


EXPRESSIONS = (
    '', 'e', 'echo', 'echo ', ' echo h', 'echo h', 'echo "two words"',
    'echo "unfinished', 'add 1', 'add 1 ', 'add 1 x', 'add 1 2',
    'add 1 2 ', 'pick ', 'pick o', 'pick one', 'tail one two words',
    'missing x', 'echo   h', 'echo\th',
)


def collect(command, types):
    manager = command.CommandManager(SimpleNamespace())

    def choices() -> Sequence[str]:
        return ['one', 'two']

    def echo(text: str) -> str:
        return text

    def add(first: int, second: int = 2) -> int:
        return first + second

    def pick(value: types.Choice('choices')) -> str:
        return value

    def tail(value: types.CmdArgs) -> str:
        return value

    for name, function in (
        ('choices', choices), ('echo', echo), ('add', add),
        ('pick', pick), ('tail', tail),
    ):
        manager.add(name, function)

    def type_name(annotation):
        handler = types.CommandTypes.get(annotation)
        return handler.display if handler is not None else annotation.__name__

    cases = {}
    for expression in EXPRESSIONS:
        try:
            parsed, remaining = manager.parse_partial(expression)
            cases['partial/' + repr(expression)] = {
                'parsed': [[item.value, type_name(item.type), item.valid]
                           for item in parsed],
                'remaining': [[item.name, type_name(item.type), item.kind.name]
                              for item in remaining],
            }
        except Exception as error:
            cases['partial/' + repr(expression)] = {
                'error': type(error).__name__, 'message': str(error),
            }

    for name, annotation in (
        ('str', str), ('int', int), ('bool', bool), ('bytes', bytes),
        ('path', types.Path), ('choice', types.Choice('choices')),
        ('unknown', float), ('none', None),
    ):
        try:
            cases['typename/' + name] = {'value': command.typename(annotation)}
        except Exception as error:
            cases['typename/' + name] = {
                'error': type(error).__name__, 'message': str(error),
            }

    for text in ('hello', '"hello"', "'hello'", '"two words"',
                 r'"line\nnext"', '"unfinished', ''):
        cases['unquote/' + repr(text)] = command.unquote(text)

    for name, text, annotation in (
        ('int', '12', int), ('bad_int', 'twelve', int),
        ('quoted_str', '"two words"', str), ('bool', 'true', bool),
        ('bad_bool', 'True', bool), ('choice', 'one', types.Choice('choices')),
    ):
        try:
            cases['parsearg/' + name] = {'value': command.parsearg(manager, text, annotation)}
        except Exception as error:
            cases['parsearg/' + name] = {
                'error': type(error).__name__, 'message': str(error),
            }

    def annotated(value: str):
        return value

    decorated = command.argument('value', types.Path)(annotated)
    cases['argument/same'] = decorated is annotated
    cases['argument/type'] = command.typename(inspect.signature(decorated).parameters['value'].annotation)

    def signature(first, second=2, *rest):
        return first, second, rest

    for name, args, kwargs in (
        ('missing', [], {}), ('one', ['x'], {}), ('two', ['x', 2], {}),
        ('keyword', ['x'], {'second': 2}), ('unknown', ['x'], {'other': 2}),
        ('varargs', ['x', 2, 3], {}),
    ):
        try:
            result = command.verify_arg_signature(signature, args, kwargs)
            cases['verify/' + name] = {'value': result}
        except Exception as error:
            cases['verify/' + name] = {
                'error': type(error).__name__, 'message': str(error),
            }
    return cases
