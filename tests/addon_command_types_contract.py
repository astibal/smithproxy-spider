"""Public command argument-type observations without reference source access."""

from collections.abc import Sequence
from types import SimpleNamespace
import typing


def collect(command, flow, http):
    cases = {}
    annotations = {'flow': flow.Flow, 'http_flow': http.HTTPFlow,
                   'flows': Sequence[flow.Flow], 'typing_flows': typing.Sequence[flow.Flow],
                   'strings': Sequence[str], 'integers': Sequence[int],
                   'list_flows': list[flow.Flow]}
    for name, annotation in annotations.items():
        manager = command.CommandManager(SimpleNamespace())
        arguments = []

        def target(value):
            arguments.append(value)
            return 'called'

        target.__annotations__ = {'value': annotation, 'return': str}
        entry = {}
        try:
            manager.add('probe.target', target)
            entry['registration'] = 'ok'
        except Exception as error:
            entry['registration'] = type(error).__name__
            cases[name] = entry
            continue
        marker = object()
        entry['typed_result'] = manager.call('probe.target', marker)
        entry['typed_identity'] = arguments[-1] is marker
        for text in ('@all', 'first,second', ''):
            try:
                entry['text/' + text] = manager.call_strings('probe.target', [text])
                entry['argument/' + text] = arguments[-1]
            except Exception as error:
                entry['text/' + text] = {'error': type(error).__name__, 'message': str(error)}
        cases[name] = entry
    for annotation, name in ((flow.Flow, 'single'), (Sequence[flow.Flow], 'sequence')):
        for count in (0, 1, 2):
            selected = [http.HTTPFlow(None, None) for _ in range(count)]
            observed = []
            manager = command.CommandManager(SimpleNamespace())

            def resolve(expression: str):
                observed.append(expression)
                return selected

            resolve.__annotations__['return'] = Sequence[flow.Flow]

            def target(value):
                if name == 'single':
                    return value is selected[0]
                return value is selected

            target.__annotations__ = {'value': annotation, 'return': bool}
            manager.add('view.flows.resolve', resolve)
            manager.add('probe.target', target)
            try:
                result = {'value': manager.call_strings('probe.target', ['@all'])}
            except Exception as error:
                result = {'error': type(error).__name__, 'message': str(error)}
            result['resolver_calls'] = observed
            cases[f'resolver/{name}/{count}'] = result
    for annotation, name, good in ((flow.Flow, 'flow', http.HTTPFlow(None, None)),
                                   (Sequence[flow.Flow], 'flows', []),
                                   (Sequence[str], 'strings', ['first'])):
        for valid in (False, True):
            returned = good if valid else 42

            def target():
                return returned

            target.__annotations__ = {'return': annotation}
            manager = command.CommandManager(SimpleNamespace())
            manager.add('probe.result', target)
            try:
                value = manager.call_strings('probe.result', [])
                result = {'identity': value is returned}
            except Exception as error:
                result = {'error': type(error).__name__, 'message': str(error)}
            cases[f'return/{name}/{valid}'] = result
    # Validate containers and their elements separately. A type annotation is
    # not permission to normalize the callback's return object into a list.
    first_flow = http.HTTPFlow(None, None)
    return_values = {
        'empty_tuple': (),
        'flow_tuple': (first_flow,),
        'mixed_tuple': (first_flow, 'text'),
        'string_tuple': ('first', 'second'),
        'string': 'text',
        'empty_string': '',
        'bytes': b'text',
        'empty_bytes': b'',
        'mapping': {},
        'string_mapping': {'first': 1},
        'flow_mapping': {first_flow: 1},
        'string_set': {'first'},
        'flow_set': {first_flow},
        'empty_range': range(0),
        'integer_range': range(2),
        'none': None,
    }
    for annotation, name in ((Sequence[flow.Flow], 'flows'), (Sequence[str], 'strings')):
        for label, returned in return_values.items():
            def target():
                return returned

            target.__annotations__ = {'return': annotation}
            manager = command.CommandManager(SimpleNamespace())
            manager.add('probe.container', target)
            try:
                value = manager.call_strings('probe.container', [])
                result = {'identity': value is returned}
            except Exception as error:
                result = {'error': type(error).__name__, 'message': str(error)}
            cases[f'container/{name}/{label}'] = result
        for label, elements in (('empty', []), ('flows', [first_flow]), ('strings', ['first'])):
            returned = iter(elements)

            def target():
                return returned

            target.__annotations__ = {'return': annotation}
            manager = command.CommandManager(SimpleNamespace())
            manager.add('probe.iterator', target)
            try:
                value = manager.call_strings('probe.iterator', [])
                result = {'identity': value is returned, 'remaining': len(list(value))}
            except Exception as error:
                result = {'error': type(error).__name__, 'message': str(error)}
            cases[f'iterator/{name}/{label}'] = result
    return cases
