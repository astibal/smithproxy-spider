"""Public registration scenarios shared by reference and adapter tests."""



async def collect(factory, running_event):
    results = {}
    scenarios = ('plain', 'tree', 'register_only', 'duplicate_name',
                 'remove_child', 'deferred', 'late_add', 'load_adds_child',
                 'add_during_event', 'remove_during_event', 'child_during_event',
                 'child_load_error', 'duplicate_child', 'invalid_deferred')
    for scenario in scenarios:
        master = factory()
        events = []
        observations = []

        class Addon:
            def __init__(self, name, children=()):
                self.name = name
                self.addons = list(children)

            def load(self, loader):
                events.append(['load', self.name,
                               master.addons.get(self.name) is self])
                if scenario == 'deferred':
                    loader.add_option('probe_count', int, 1, 'Probe count')
                if scenario == 'load_adds_child' and self.name == 'parent':
                    self.addons.append(Addon('child'))
                if scenario == 'child_load_error' and self.name == 'child':
                    raise ValueError('Child load failed')
                if scenario == 'invalid_deferred' and self.name == 'parent':
                    loader.add_option('probe_count', int, 1, 'Probe count')

            def configure(self, updated):
                events.append(['configure', self.name, sorted(updated)])

            def running(self):
                events.append(['running', self.name])
                if self.name == 'parent':
                    if scenario == 'add_during_event':
                        master.addons.add(child)
                    elif scenario == 'remove_during_event':
                        master.addons.remove(child)
                    elif scenario == 'child_during_event':
                        self.addons.append(child)

            def done(self):
                events.append(['done', self.name,
                               master.addons.get(self.name) is self])

        child = Addon('child')
        parent = Addon('parent', (child,) if scenario in (
            'tree', 'remove_child', 'child_load_error', 'duplicate_child') else ())
        if scenario == 'duplicate_child':
            parent.addons.append(Addon('child'))

        def observe(label, operation):
            events.clear()
            error = None
            returned = None
            try:
                returned = operation()
            except Exception as failure:
                error = type(failure).__name__
            observations.append({
                'operation': label,
                'error': error,
                'returned_parent': returned is parent,
                'events': list(events),
                'chain': [addon.name for addon in master.addons.chain],
                'known': {name: master.addons.get(name) is not None
                          for name in ('parent', 'child')},
                'pending_value': getattr(master.options, 'probe_count', None),
            })

        if scenario == 'deferred':
            master.options.set('probe_count=3', defer=True)
        if scenario == 'invalid_deferred':
            master.options.set('probe_count=invalid', defer=True)
        if scenario == 'late_add':
            await master.running()
        if scenario == 'register_only':
            observe('register', lambda: master.addons.register(parent))
        else:
            observe('add', lambda: master.addons.add(parent))
        if scenario == 'duplicate_name':
            observe('duplicate', lambda: master.addons.add(Addon('parent')))
        if scenario == 'remove_during_event':
            observe('add child root', lambda: master.addons.add(child))
        observe('running', lambda: running_event(master))
        if scenario == 'remove_child':
            observe('remove child', lambda: master.addons.remove(child))
            observe('running after child removal',
                    lambda: running_event(master))
        observe('remove parent', lambda: master.addons.remove(parent))
        observe('remove missing', lambda: master.addons.remove(parent))
        observe('clear', master.addons.clear)
        results[scenario] = observations
    return results
