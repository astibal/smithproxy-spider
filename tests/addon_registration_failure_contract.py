"""Failure-boundary registration scenarios shared by reference and adapter tests."""


async def collect(factory, running_event):
    results = {}

    def run_case(name, build):
        master = factory()
        events = []
        objects = build(master, events)
        operation = objects.pop("operation")

        def snapshot(label, operation):
            events.clear()
            error = None
            returned = None
            try:
                returned = operation()
            except Exception as failure:
                error = {
                    "type": type(failure).__name__,
                    "message": str(failure),
                }

            names = tuple(objects)
            return {
                "operation": label,
                "error": error,
                "returned": next(
                    (object_name for object_name, value in objects.items()
                     if returned is value),
                    None,
                ),
                "events": list(events),
                "chain": [getattr(addon, "name", type(addon).__name__.lower())
                          for addon in master.addons.chain],
                "known": {
                    object_name: master.addons.get(object_name) is value
                    for object_name, value in objects.items()
                },
                "known_names": {
                    object_name: master.addons.get(object_name) is not None
                    for object_name in names
                },
            }

        observations = []
        observations.append(snapshot("register", operation))
        observations.append(snapshot("running", lambda: running_event(master)))
        observations.append(snapshot("clear", master.addons.clear))
        results[name] = observations

    class Addon:
        def __init__(self, name, events, children=(), *, fail=False,
                     side_effect=None):
            self.name = name
            self.events = events
            self.addons = list(children)
            self.fail = fail
            self.side_effect = side_effect

        def load(self, loader):
            self.events.append(["load", self.name])
            if self.side_effect is not None:
                self.side_effect()
            if self.fail:
                raise ValueError(self.name + " load failed")

        def running(self):
            self.events.append(["running", self.name])

        def done(self):
            self.events.append(["done", self.name])

    def deep_failure(master, events):
        never = Addon("never", events)
        broken = Addon("broken", events, fail=True)
        first = Addon("first", events, (broken,))
        parent = Addon("parent", events, (first, never))
        return {
            "parent": parent,
            "first": first,
            "broken": broken,
            "never": never,
            "operation": lambda: master.addons.add(parent),
        }

    def batch_failure(master, events):
        first = Addon("first", events)
        broken = Addon("broken", events, fail=True)
        never = Addon("never", events)
        return {
            "first": first,
            "broken": broken,
            "never": never,
            "operation": lambda: master.addons.add(first, broken, never),
        }

    def nested_side_effect(master, events):
        side = Addon("side", events)

        def add_side():
            master.addons.add(side)

        parent = Addon(
            "parent",
            events,
            fail=True,
            side_effect=add_side,
        )
        return {
            "parent": parent,
            "side": side,
            "operation": lambda: master.addons.add(parent),
        }

    def child_side_effect(master, events):
        side = Addon("side", events)

        def add_side():
            master.addons.add(side)

        first = Addon("first", events, side_effect=add_side)
        broken = Addon("broken", events, fail=True)
        parent = Addon("parent", events, (first, broken))
        return {
            "parent": parent,
            "first": first,
            "broken": broken,
            "side": side,
            "operation": lambda: master.addons.add(parent),
        }

    run_case("deep-child-load-failure", deep_failure)
    run_case("multi-add-partial-failure", batch_failure)
    run_case("parent-load-side-effect-before-failure", nested_side_effect)
    run_case("child-side-effect-before-sibling-failure", child_side_effect)
    return results
