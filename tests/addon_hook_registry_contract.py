"""Shared observation of the public hook registry after proxy imports."""


def collect(hooks):
    return {
        name: hook_type.__name__
        for name, hook_type in sorted(hooks.all_hooks.items())
    }
