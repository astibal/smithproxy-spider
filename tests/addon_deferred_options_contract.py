"""Independent action sequences for deferred public option configuration."""


def collect(factory, rejection_type):
    sequences = {
        'late_registration': [('set', ['later=3']), ('process',), ('add', 'later'),
                              ('process',), ('process',)],
        'replace_pending': [('set', ['later=2']), ('set', ['later=3']),
                            ('add', 'later'), ('process',)],
        'duplicate_pending': [('set', ['later=2', 'later=3']), ('add', 'later'),
                              ('process',), ('process',)],
        'known_and_unknown': [('set', ['count=4', 'later=3']), ('add', 'later'),
                              ('process',)],
        'invalid_known': [('set', ['later=3', 'count=bad']), ('add', 'later'),
                          ('process',)],
        'invalid_pending': [('set', ['later=bad']), ('add', 'later'), ('process',),
                            ('process',), ('set', ['later=5']), ('process',)],
        'ordinary_update': [('set', ['later=3']), ('add', 'later'),
                            ('set', ['later=5']), ('process',)],
        'partial_registration': [('set', ['later=3', 'other=4']), ('add', 'later'),
                                 ('process',), ('add', 'other'), ('process',)],
        'rejected_pending': [('set', ['later=7']), ('add', 'later'), ('process',),
                             ('process',)],
        'registered_together': [('set', ['later=3', 'other=4']), ('add', 'later'),
                                ('add', 'other'), ('process',), ('process',)],
        'invalid_batch': [('set', ['later=3', 'other=bad']), ('add', 'later'),
                          ('add', 'other'), ('process',), ('process',)],
        'rejected_known': [('set', ['later=3', 'count=7']), ('add', 'later'),
                           ('process',)],
    }
    results = {}
    for name, actions in sequences.items():
        options = factory()
        options.add_option('count', int, 1, 'Count')
        events = []

        def changed(updated):
            events.append(sorted(updated))
            if ('later' in updated and options.later == 7) or options.count == 7:
                raise rejection_type('Rejected seven')

        options.changed.connect(changed)
        observations = []
        for action in actions:
            error = None
            events.clear()
            try:
                if action[0] == 'set':
                    options.set(*action[1], defer=True)
                elif action[0] == 'add':
                    options.add_option(action[1], int, 1, 'Late option')
                else:
                    options.process_deferred()
            except Exception as failure:
                error = type(failure).__name__
            observations.append({
                'action': list(action), 'error': error,
                'values': {key: getattr(options, key) for key in sorted(options.keys())},
                'events': list(events),
            })
        results[name] = observations
    return results
