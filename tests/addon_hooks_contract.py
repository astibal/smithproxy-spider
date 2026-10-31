"""Independent public Hook value observations."""

from dataclasses import dataclass


def collect(hooks, load_hook):
    results = {}
    for cls in (hooks.RunningHook, hooks.DoneHook, hooks.ConfigureHook,
                hooks.UpdateHook, load_hook):
        payload = ['marker']
        event = cls() if cls in (hooks.RunningHook, hooks.DoneHook) else cls(payload)
        results[cls.__name__] = {
            'name': event.name, 'args': event.args(),
            'same_payload': bool(event.args()) and event.args()[0] is payload,
        }
    for label in ('CustomEventHook', 'XMLParserHook', 'HTTP2RequestHook',
                  'FooBARBazHook', 'Already_hook', 'Hook'):
        cls = dataclass(type(label, (hooks.Hook,), {'__annotations__': {'value': object}}))
        event = cls('value')
        results[label + '/custom'] = {'name': event.name, 'args': event.args()}
    try:
        hooks.Hook()
    except Exception as failure:
        results['base_error'] = type(failure).__name__
    return results
