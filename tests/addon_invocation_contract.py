"""Public targeted invocation without registering the target addon."""


async def collect(factory, running_hook):
    results = {}
    for scenario in ('tree', 'failure', 'async', 'noncallable', 'missing', 'new_child'):
        for mode in ('sync', 'async'):
            manager = factory()
            events = []

            class Child:
                def running(self):
                    events.append('child')

            class Parent:
                def __init__(self):
                    self.addons = [Child()] if scenario == 'tree' else []

                def running(self):
                    events.append('parent')
                    if scenario == 'failure':
                        raise ValueError('Rejected callback')
                    if scenario == 'new_child':
                        self.addons.append(Child())

            async def async_callback():
                events.append('async parent')

            parent = Parent()
            if scenario == 'async':
                parent.running = async_callback
            elif scenario == 'noncallable':
                parent.running = 3
            elif scenario == 'missing':
                parent.running = None
            error = None
            returned_none = False
            try:
                if mode == 'sync':
                    result = manager.invoke_addon_sync(parent, running_hook())
                else:
                    result = await manager.invoke_addon(parent, running_hook())
                returned_none = result is None
            except Exception as failure:
                error = type(failure).__name__
            results[scenario + '/' + mode] = {
                'events': events, 'error': error, 'returned_none': returned_none,
            }
    return results
