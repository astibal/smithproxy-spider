"""Dynamic update-hook observations shared by reference and adapter tests."""


async def collect(factory, update_hook):
    master = factory()
    events = []
    observations = []

    class Observer:
        name = "observer"

        def load(self, loader):
            events.append(["load", self.name])

        def update(self, updated):
            events.append([
                "update",
                self.name,
                [getattr(item, "name", type(item).__name__) for item in updated],
            ])

        def done(self):
            events.append(["done", self.name])

    class Target:
        name = "target"

        def load(self, loader):
            events.append(["load", self.name])

        async def update(self, updated):
            events.append([
                "update",
                self.name,
                [getattr(item, "name", type(item).__name__) for item in updated],
            ])

        def done(self):
            events.append(["done", self.name])

    observer = Observer()
    target = Target()

    def record(label):
        observations.append({
            "label": label,
            "events": list(events),
            "chain": [addon.name for addon in master.addons.chain],
        })
        events.clear()

    master.addons.add(observer)
    record("add observer")
    master.addons.add(target)
    record("add target")
    await master.addons.handle_lifecycle(update_hook([target]))
    record("explicit update")
    master.addons.remove(target)
    record("remove target")
    await master.addons.handle_lifecycle(update_hook([target]))
    record("update after removal")
    await master.addons.handle_lifecycle(update_hook([]))
    record("empty update")
    master.addons.remove(observer)
    record("remove observer")

    return observations
