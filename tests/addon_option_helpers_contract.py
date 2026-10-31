"""Independent public behavior probes for option convenience operations."""

from typing import Sequence


def collect(factory):
    results = {}

    def setup():
        options = factory()
        options.add_option("flag", bool, False, "Flag")
        options.add_option("count", int, 1, "Count")
        options.add_option("names", Sequence[str], ["original"], "Names")
        return options

    def observe(name, operation):
        options = setup()
        notifications = []

        def changed(updated):
            notifications.append(sorted(updated))

        options.changed.connect(changed)
        error = None
        try:
            operation(options)
        except Exception as failure:
            error = type(failure).__name__
        results[name] = {
            "error": error,
            "flag": options.flag,
            "count": options.count,
            "names": list(options.names),
            "notifications": notifications,
        }

    changes = [
        {}, {"count": None}, {"names": ["second"]}, {"names": ("second",)},
        {"names": []}, {"count": [2]}, {"missing": None}, {"missing": 1},
        {"flag": True, "count": 2}, {"count": 2, "missing": 1},
        {"count": 2, "names": ("second",)}, {"count": 2, "flag": "invalid"},
        {"names": ["second"], "flag": True},
    ]
    for index, values in enumerate(changes):
        observe("merge/" + str(index), lambda options, values=values: options.merge(values))

    for attr in ("flag", "count", "names", "missing"):
        observe("setter/create/" + attr, lambda options, attr=attr: options.setter(attr))
        observe("setter/call/" + attr, lambda options, attr=attr: options.setter(attr)(True))
        observe("toggler/create/" + attr, lambda options, attr=attr: options.toggler(attr))
        observe("toggler/call/" + attr, lambda options, attr=attr: options.toggler(attr)())

    def late_toggle(options):
        toggle = options.toggler("flag")
        toggle()
        options.flag = False
        toggle()

    observe("toggler/current_value", late_toggle)
    return results
