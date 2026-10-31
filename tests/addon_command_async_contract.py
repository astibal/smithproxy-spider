"""Shared black-box contract for asynchronous addon commands."""

import asyncio
import inspect
import warnings


async def collect(command, factory):
    master = factory()
    calls = []

    @command.command("probe.async")
    async def asynchronous(value: int) -> int:
        calls.append(value)
        await asyncio.sleep(0)
        return value + 1

    master.commands.add("probe.async", asynchronous)
    registered = master.commands.commands["probe.async"]
    observations = {
        "manager_methods": [
            name for name in dir(master.commands)
            if not name.startswith("_")
        ],
        "decorated_is_coroutine_function": inspect.iscoroutinefunction(asynchronous),
        "registered_is_coroutine_function": inspect.iscoroutinefunction(registered.func),
    }

    direct = asynchronous(1)
    observations["direct_is_awaitable"] = inspect.isawaitable(direct)
    observations["direct_result"] = await direct

    typed = master.commands.call("probe.async", 2)
    observations["typed_is_awaitable"] = inspect.isawaitable(typed)
    observations["typed_result"] = await typed

    # Textual invocation validates the returned object immediately. In v12 it
    # therefore rejects the coroutine instead of awaiting it. Suppress only the
    # resulting unawaited-coroutine diagnostic; the public error is recorded.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        for name, invoke in (
            ("strings", lambda: master.commands.call_strings("probe.async", ["3"])),
            ("execute", lambda: master.commands.execute("probe.async 4")),
        ):
            try:
                result = invoke()
                observations[name + "_is_awaitable"] = inspect.isawaitable(result)
                if inspect.isawaitable(result):
                    observations[name + "_result"] = await result
                else:
                    observations[name + "_result"] = result
            except Exception as error:
                observations[name + "_error"] = [
                    type(error).__name__, str(error),
                ]

    observations["calls"] = calls
    return observations
