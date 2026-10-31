"""Weakly-referenced synchronous and asynchronous addon signals."""

import asyncio
import inspect
import weakref


def make_weak_ref(obj):
    """Create the appropriate weak reference for a function or bound method."""
    if getattr(obj, "__self__", None) is not None:
        return weakref.WeakMethod(obj)
    return weakref.ref(obj)


class _SignalMixin:
    def __init__(self):
        self.receivers = []

    def connect(self, receiver):
        """Register a receiver without extending its lifetime."""
        self.receivers.append(make_weak_ref(receiver))

    def disconnect(self, receiver):
        """Remove every registration for a receiver."""
        self.receivers = [
            reference
            for reference in self.receivers
            if reference() is not None and reference() != receiver
        ]

    def notify(self, *args, **kwargs):
        """Yield receiver results in registration order."""
        snapshot = tuple(self.receivers)
        dead = []
        for reference in snapshot:
            receiver = reference()
            if receiver is None:
                dead.append(reference)
                continue
            yield receiver(*args, **kwargs)

        if dead:
            self.receivers = [
                reference for reference in self.receivers
                if reference not in dead and reference() is not None
            ]


class _SyncSignal(_SignalMixin):
    def connect(self, receiver):
        assert not inspect.iscoroutinefunction(receiver)
        super().connect(receiver)

    def send(self, *args, **kwargs):
        for _result in self.notify(*args, **kwargs):
            pass


class _AsyncSignal(_SignalMixin):
    async def send(self, *args, **kwargs):
        awaitables = [
            result
            for result in self.notify(*args, **kwargs)
            if inspect.isawaitable(result)
        ]
        if awaitables:
            await asyncio.gather(*awaitables)


def SyncSignal(receiver_spec):
    """Create a synchronous weak-reference signal."""
    del receiver_spec
    return _SyncSignal()


def AsyncSignal(receiver_spec):
    """Create a signal accepting synchronous and asynchronous receivers."""
    del receiver_spec
    return _AsyncSignal()
