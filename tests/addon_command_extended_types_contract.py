"""Public extended command-type observations shared with the reference probe."""

from collections.abc import Sequence
import os
import re
from types import SimpleNamespace


def collect(command, types):
    cases = {}

    def normalize(value):
        if isinstance(value, str):
            value = value.replace(os.path.expanduser('~'), '<HOME>')
            return re.sub(r'0x[0-9a-fA-F]+', '0xADDRESS', value)
        if isinstance(value, bytes):
            return {'bytes': list(value)}
        if isinstance(value, (list, tuple)):
            return [normalize(item) for item in value]
        return value

    def record(name, operation, observed=None):
        try:
            value = operation()
            entry = {'value': normalize(value)}
            if observed is not None:
                entry['argument'] = normalize(observed[-1])
            cases[name] = entry
        except Exception as error:
            cases[name] = {'error': type(error).__name__, 'message': normalize(str(error))}

    manager = command.CommandManager(SimpleNamespace())

    def existing() -> str:
        return 'existing'

    def choices() -> Sequence[str]:
        return ['one', 'two']

    manager.add('probe.existing', existing)
    manager.add('probe.choices', choices)
    annotations = {
        'bytes': bytes, 'args': types.CmdArgs, 'command': types.Cmd,
        'path': types.Path, 'marker': types.Marker, 'cut': types.CutSpec,
        'data': types.Data, 'choice': types.Choice('probe.choices'),
    }
    samples = {
        'bytes': ['hello', r'line\nnext', 'čaj', r'\xff', r'\u0041', r'\q', 'tail\\', r'\xZZ'],
        'args': ['hello', 'two words', r'line\nnext', '"quoted"', '$HOME', ''],
        'command': ['probe.existing', 'probe.missing', ''],
        'path': ['relative.txt', '~/file', '~not-a-user/file', '$HOME/file', 'a b', r'a\nb'],
        'marker': ['true', 'false', 'a', 'A', '9', ':warning:', ':not_real:', 'ab', ''],
        'cut': ['request.method', 'request.method,response.status_code', 'a,b,', r'a\,b', ''],
        'data': ['hello'],
        'choice': ['one', 'two', 'three', ''],
    }
    for type_name, annotation in annotations.items():
        for index, text in enumerate(samples[type_name]):
            observed = []

            def target(value):
                observed.append(value)
                return 'called'

            target.__annotations__ = {'value': annotation, 'return': str}
            path = f'probe.argument.{type_name}.{index}'
            manager.add(path, target)
            record(f'argument/{type_name}/{index}',
                   lambda path=path, text=text: manager.call_strings(path, [text]), observed)

    return_values = {
        'bytes/good': (bytes, b'value'), 'bytes/bad': (bytes, 'value'),
        'args/good': (types.CmdArgs, 'value'), 'path/good': (types.Path, 'value'),
        'marker/good': (types.Marker, 'not-a-choice'),
        'command/good': (types.Cmd, 'probe.existing'),
        'command/missing': (types.Cmd, 'probe.missing'),
        'cut/parsed': (types.CutSpec, ['request.method']),
        'data/string': (types.Data, 'value'),
        'data/nested': (types.Data, [['first', 'second']]),
        'data/mapping': (types.Data, {'first': 1}),
        'data/bad': (types.Data, [[1]]),
    }
    for name, (annotation, returned) in return_values.items():
        def target():
            return returned

        target.__annotations__ = {'return': annotation}
        path = 'probe.return.' + name.replace('/', '.')
        manager.add(path, target)
        record('return/' + name, lambda path=path: manager.call_strings(path, []))

    for name, annotation in annotations.items():
        marker = object()
        observed = []

        def target(value):
            observed.append(value)
            return 'called'

        target.__annotations__ = {'value': annotation, 'return': str}
        path = 'probe.typed.' + name
        manager.add(path, target)
        record('typed/' + name,
               lambda path=path, marker=marker: manager.call(path, marker))
        cases['typed/' + name]['identity'] = observed[-1] is marker

    for name, annotation in annotations.items():
        handler = types.CommandTypes.get(annotation)
        cases['metadata/' + name] = {
            'present': handler is not None,
            'display': handler.display,
            'choice_instance_lookup': (
                handler is types.CommandTypes.get(type(annotation))
                if isinstance(annotation, types.Choice) else None
            ),
        }
    cases['metadata/bool/completion'] = types.CommandTypes.get(bool).completion(
        manager, bool, 'ignored')
    cases['metadata/command/completion'] = types.CommandTypes.get(types.Cmd).completion(
        manager, types.Cmd, 'ignored')
    choice = annotations['choice']
    cases['metadata/choice/completion'] = types.CommandTypes.get(choice).completion(
        manager, choice, 'ignored')
    cases['metadata/unknown/default'] = types.CommandTypes.get(float, 'fallback')
    record(
        'metadata/unhashable/default',
        lambda: types.CommandTypes.get([], 'fallback'),
    )

    string_handler = types.CommandTypes.get(str)
    record(
        'metadata/string/parse',
        lambda: string_handler.parse(manager, str, 'value'),
    )
    record(
        'metadata/string/is-valid',
        lambda: [
            string_handler.is_valid(manager, str, 'value'),
            string_handler.is_valid(manager, str, 1),
        ],
    )
    record(
        'metadata/string/completion',
        lambda: string_handler.completion(manager, str, 'value'),
    )

    class First:
        typ = str

    class Replacement:
        typ = str

    custom = types.TypeManager(First, Replacement)
    cases['metadata/custom/replacement'] = type(custom.get(str)).__name__
    cases['metadata/custom/missing'] = custom.get(int, 'fallback')

    return cases
