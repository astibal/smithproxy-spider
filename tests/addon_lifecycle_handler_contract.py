"""Behavioral observations for the public addon lifecycle handler."""


async def collect(factory, request_hook, empty_hook, make_flow, options_error):
    observations = []

    async def run(label, behavior):
        master = factory()
        flow = make_flow()
        events = []

        class First:
            name = "first"

            def request(self, received):
                events.append(["first", received is flow])
                if behavior == "ordinary-error":
                    raise ValueError("ordinary failure")
                if behavior == "options-error":
                    raise options_error("configuration rejected")

        class Second:
            name = "second"

            async def request(self, received):
                events.append(["second", received is flow])

        master.addons.add(First(), Second())
        result = None
        error = None
        try:
            result = await master.addons.handle_lifecycle(request_hook(flow))
        except Exception as failure:
            error = [type(failure).__name__, str(failure)]
        observations.append({
            "label": label,
            "events": events,
            "returned_none": result is None,
            "error": error,
        })

    await run("success", "success")
    await run("ordinary error", "ordinary-error")
    await run("options error", "options-error")

    master = factory()
    error = None
    try:
        await master.addons.handle_lifecycle(empty_hook())
    except Exception as failure:
        error = [type(failure).__name__, str(failure)]
    observations.append({
        "label": "event without message",
        "error": error,
    })

    return observations
