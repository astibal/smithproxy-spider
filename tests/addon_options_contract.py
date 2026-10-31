"""Own probes of public option typing and mutation behavior."""

from typing import Optional, Sequence
import gc


def collect_notifications(factory, rejection):
    """Observe notification order, weak ownership, and rejection boundaries."""
    options = factory()
    events = []

    def changed(updated):
        events.append(['changed', sorted(updated), options.count])
        if options.count == 4:
            raise rejection('Rejected four')
        if options.count == 5:
            raise ValueError('Rejected five')

    def errored(exc):
        events.append(['error', type(exc).__name__, str(exc), options.count])

    def subscribed(manager, updated):
        events.append(['subscription', manager is options, sorted(updated)])

    options.changed.connect(changed)
    options.errored.connect(errored)
    options.add_option('count', int, 1, 'Counter')
    options.add_option('label', str, '', 'Label')
    options.subscribe(subscribed, ['count'])
    for values in ({}, {'count': 1}, {'count': 2, 'label': 1},
                   {'count': 4}, {'count': 5}, {'count': 6, 'unknown': 7}):
        try:
            options.update(**values)
        except Exception as error:
            events.append(['raised', type(error).__name__, str(error)])
        events.append(['state', options.count, options.label])
    options.reset()
    with options.rollback({'count'}):
        options.count = 3
        raise rejection('Rejected transaction')

    options.changed.connect(changed)
    options.update(count=2)
    options.changed.disconnect(changed)
    options.update(count=3)

    def connect_temporary():
        def temporary(updated):
            events.append(['unexpected retained callback'])
        options.changed.connect(temporary)
        options.subscribe(temporary, ['count'])

    connect_temporary()
    gc.collect()
    options.update(count=6)
    try:
        options.subscribe(subscribed, ['missing'])
    except Exception as error:
        events.append(['raised', type(error).__name__, str(error)])
    return events


def collect(factory):
    observations = []
    specifications = [
        (bool, False, [1, None, 'yes', True]),
        (int, 3, [True, '2', 2, None]),
        (str, 'x', [b'x', None, 'y']),
        (Optional[str], None, ['a', None, 1]),
        (Sequence[str], [], [('a', 'b'), ['a'], ['a', 1], 'ab', None]),
    ]
    for typespec, default, values in specifications:
        options = factory()
        options.add_option('value', typespec, default, 'Help')
        for value in values:
            error = None
            try:
                options.update(value=value)
            except Exception as failure:
                error = [type(failure).__name__, str(failure)]
            observations.append([str(typespec), repr(value), repr(options.value),
                                 options.has_changed('value'), error])

    options = factory()
    options.add_option('count', int, 1, 'Counter')
    options.add_option('words', Sequence[str], ['a'], 'Words')
    detached = options.words
    detached.append('b')
    errors = []
    for operation in (
        lambda: options.update(count=2, words=[1]),
        lambda: options.update(count=3, missing=1),
        lambda: getattr(options, 'absent'),
        lambda: options.default('absent'),
    ):
        try:
            operation()
        except Exception as failure:
            errors.append([type(failure).__name__, str(failure), options.count])
    before_reset = [options.count, options.words, options.has_changed('count')]
    options.reset()
    choices = factory()
    choices.add_option('mode', str, 'first', 'Modes', choices=['first', 'second'])
    choices.mode = 'third'
    return {'typing': observations, 'errors': errors, 'before_reset': before_reset,
            'after_reset': [options.count, options.words, options.has_changed('count')],
            'unknown': options.update_known(count=4, absent='other'),
            'choice_metadata_does_not_validate': choices.mode}
