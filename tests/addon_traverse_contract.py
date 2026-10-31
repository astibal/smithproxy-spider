"""Public addon traversal behavior shared with the reference probe."""

from types import SimpleNamespace


def collect(addonmanager):
    observations = {}

    def record(name, operation):
        try:
            observations[name] = {
                "value": [getattr(item, "name", repr(item))
                          for item in operation()],
            }
        except Exception as error:
            observations[name] = {
                "error": type(error).__name__,
                "message": str(error),
            }

    leaf = SimpleNamespace(name="leaf")
    first = SimpleNamespace(name="first", addons=[leaf])
    second = SimpleNamespace(name="second")

    record("list", lambda: addonmanager.traverse([first, second]))
    record("tuple", lambda: addonmanager.traverse((first, second)))
    record("single", lambda: addonmanager.traverse(first))
    record(
        "none_children",
        lambda: addonmanager.traverse([
            SimpleNamespace(name="none", addons=None),
        ]),
    )
    record(
        "tuple_children",
        lambda: addonmanager.traverse([
            SimpleNamespace(name="tuple", addons=(leaf,)),
        ]),
    )
    record(
        "generator",
        lambda: addonmanager.traverse(item for item in (first, second)),
    )
    record("empty", lambda: addonmanager.traverse([]))

    children = []
    root = SimpleNamespace(name="root", addons=children)
    traversal = addonmanager.traverse([root])
    first_item = next(traversal)
    children.append(leaf)
    observations["lazy_children"] = {
        "first": first_item.name,
        "remaining": [item.name for item in traversal],
    }
    return observations
