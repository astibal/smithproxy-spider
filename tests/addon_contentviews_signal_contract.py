"""Content-view registry signal behavior shared with the reference probe."""


def collect(contentviews):
    class SignalEdgeA(contentviews.Contentview):
        def prettify(self, data, metadata):
            return "a"

    class SignalEdgeB(contentviews.Contentview):
        def prettify(self, data, metadata):
            return "b"

    events = []

    def listener(*args, **kwargs):
        events.append({
            "args": [getattr(argument, "name", type(argument).__name__)
                     for argument in args],
            "kwargs": {
                key: getattr(value, "name", type(value).__name__)
                for key, value in kwargs.items()
            },
            "available": [
                name
                for name in contentviews.registry.available_views()
                if name.startswith("signaledge")
            ],
        })

    observations = {"type": type(contentviews.registry.on_change).__name__}

    def record(name, operation):
        try:
            value = operation()
            observations[name] = {
                "value": None if value is None else type(value).__name__,
            }
        except Exception as error:
            observations[name] = {
                "error": type(error).__name__,
                "message": str(error),
            }

    record("connect", lambda: contentviews.registry.on_change.connect(listener))
    record("register_instance", lambda: contentviews.registry.register(SignalEdgeA()))
    record("register_class", lambda: contentviews.registry.register(SignalEdgeB))
    record("register_duplicate", lambda: contentviews.registry.register(SignalEdgeA()))
    record("disconnect", lambda: contentviews.registry.on_change.disconnect(listener))
    record("register_disconnected", lambda: contentviews.registry.register(SignalEdgeB()))
    record("disconnect_again", lambda: contentviews.registry.on_change.disconnect(listener))
    observations["events"] = events
    return observations
