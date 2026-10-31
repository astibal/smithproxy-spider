"""Public signal observations shared with the isolated reference probe."""

import asyncio
import gc
import weakref


async def collect(signals):
    sync_events = []
    sync_signal = signals.SyncSignal(lambda value: None)

    def first(value):
        sync_events.append(["first", value])
        sync_signal.disconnect(first)

    def second(value):
        sync_events.append(["second", value])

    sync_signal.connect(first)
    sync_signal.connect(first)
    sync_signal.connect(second)
    first_send = sync_signal.send(1)
    second_send = sync_signal.send(2)
    sync_signal.disconnect(first)

    async def coroutine_receiver(value):
        return value

    try:
        sync_signal.connect(coroutine_receiver)
        coroutine_rejection = {"accepted": True}
    except Exception as error:
        coroutine_rejection = {
            "error": type(error).__name__,
            "message": str(error),
        }

    class Receiver:
        def callback(self, value):
            return value

    receiver = Receiver()
    receiver_reference = weakref.ref(receiver)
    weak_signal = signals.SyncSignal(lambda value: None)
    weak_signal.connect(receiver.callback)
    bound_reference_type = type(weak_signal.receivers[0]).__name__
    del receiver
    gc.collect()
    weak_signal.send(3)

    async_events = []
    async_signal = signals.AsyncSignal(lambda value: None)

    async def asynchronous(value):
        async_events.append(["async-start", value])
        await asyncio.sleep(0)
        async_events.append(["async-end", value])

    def synchronous(value):
        async_events.append(["sync", value])

    async_signal.connect(asynchronous)
    async_signal.connect(synchronous)
    async_send = await async_signal.send(4)

    def function_receiver(value):
        return value

    return {
        "types": {
            "sync": type(sync_signal).__name__,
            "async": type(async_signal).__name__,
            "function_reference": type(
                signals.make_weak_ref(function_receiver)
            ).__name__,
            "bound_reference": bound_reference_type,
        },
        "sync": {
            "events": sync_events,
            "first_send": first_send,
            "second_send": second_send,
            "remaining_receivers": len(sync_signal.receivers),
            "coroutine_rejection": coroutine_rejection,
        },
        "weak": {
            "receiver_collected": receiver_reference() is None,
            "remaining_receivers": len(weak_signal.receivers),
        },
        "async": {
            "events": async_events,
            "send": async_send,
            "remaining_receivers": len(async_signal.receivers),
        },
    }
