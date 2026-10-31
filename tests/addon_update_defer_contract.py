"""Typed deferred-option behavior shared by reference and adapter tests."""


def collect(manager_type):
    observations = []

    def deferred_state(options):
        result = {}
        for name, value in options.deferred.items():
            if hasattr(value, "val"):
                result[name] = {"unconverted": list(value.val)}
            else:
                result[name] = value
        return result

    options = manager_type()
    events = []

    def changed(updated):
        events.append(sorted(updated))

    options.changed.connect(changed)
    options.add_option("known", int, 1, "Known value")
    events.clear()
    result = options.update_defer(known=2, later=3)
    observations.append({
        "label": "known and deferred",
        "returned_none": result is None,
        "known": options.known,
        "deferred": deferred_state(options),
        "events": list(events),
    })

    events.clear()
    options.add_option("later", int, 0, "Later value")
    observations.append({
        "label": "registration is inert",
        "later": options.later,
        "deferred": deferred_state(options),
        "events": list(events),
    })
    events.clear()
    options.process_deferred()
    observations.append({
        "label": "process typed value",
        "later": options.later,
        "deferred": deferred_state(options),
        "events": list(events),
    })

    replacement = manager_type()
    replacement.update_defer(value=3)
    replacement.set("value=4", defer=True)
    first = deferred_state(replacement)
    replacement.update_defer(value=5)
    second = deferred_state(replacement)
    replacement.add_option("value", int, 0, "Value")
    replacement.process_deferred()
    observations.append({
        "label": "last deferred form wins",
        "text_replaced_typed": first,
        "typed_replaced_text": second,
        "value": replacement.value,
        "deferred": deferred_state(replacement),
    })

    invalid = manager_type()
    invalid.update_defer(value="bad")
    invalid.add_option("value", int, 0, "Value")
    failures = []
    for _ in range(2):
        try:
            invalid.process_deferred()
        except Exception as error:
            failures.append([type(error).__name__, str(error)])
    observations.append({
        "label": "invalid typed value is retained",
        "failures": failures,
        "value": invalid.value,
        "deferred": deferred_state(invalid),
    })

    rejected = manager_type()
    rejected.add_option("known", int, 1, "Known value")
    error = None
    try:
        rejected.update_defer(known="bad", later=3)
    except Exception as failure:
        error = [type(failure).__name__, str(failure)]
    observations.append({
        "label": "known rejection does not publish unknown values",
        "error": error,
        "known": rejected.known,
        "deferred": deferred_state(rejected),
    })

    return observations
