"""Small public helpers used by mitmproxy-style addon scripts.

The concurrent decorator deliberately remains limited to lifecycle callbacks.
Traffic callbacks must stay serialized with Spider's native flow state, just as
they do in the reference API.  The callback runs in a thread owned by the same
worker process, so module and addon state remain attached to one script worker.
"""

import asyncio
import concurrent.futures as concurrent_futures
import contextvars
import inspect
import os
import queue
import threading


_CONCURRENT_HOOKS = frozenset(("done", "running", "update"))
_runner = None
_fallback_executor = concurrent_futures.ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="spider-addon-fallback",
)


class ConcurrentRunner:
    """Own one pre-created event loop in a sandbox-inheriting worker thread.

    Worker code creates the loop and its descriptors before installing seccomp,
    then starts this thread afterwards.  This permits both regular and coroutine
    lifecycle callbacks without granting scripts process creation or arbitrary
    network descriptors.
    """

    _STOP = object()

    def __init__(self, loop):
        if not isinstance(loop, asyncio.AbstractEventLoop):
            raise TypeError("Concurrent runner requires an asyncio event loop")
        if loop.is_running() or loop.is_closed():
            raise ValueError("Concurrent runner requires a fresh event loop")
        self.loop = loop
        self._pending = queue.SimpleQueue()
        self._read_fd, self._write_fd = os.pipe2(
            os.O_NONBLOCK | os.O_CLOEXEC
        )
        self.loop.add_reader(self._read_fd, self._drain_pending)
        self._started = threading.Event()
        self._thread = None
        self._tasks = set()
        self._closing = False
        self._state_lock = threading.Lock()
        # ThreadPoolExecutor workers keep their thread context between regular
        # callback invocations.  Coroutine callbacks inherit that context, but
        # asyncio.run() contains their later changes in its temporary task.
        # Preserve the same observable boundary while retaining one prepared
        # event loop and one sandboxed worker thread.
        self._callback_context = contextvars.Context()

    def start(self):
        with self._state_lock:
            if self._thread is not None:
                raise RuntimeError("Concurrent runner has already started")
            if self._closing:
                raise RuntimeError("Concurrent runner has already closed")

            def serve():
                asyncio.set_event_loop(self.loop)
                self._started.set()
                self.loop.run_forever()

            self._thread = threading.Thread(
                target=serve,
                name="spider-addon-concurrent",
                daemon=True,
            )
            self._thread.start()
        if not self._started.wait(timeout=1):
            raise RuntimeError("Concurrent runner did not start")

    def _begin(self, function, args, result):
        if not result.set_running_or_notify_cancel():
            return

        if not inspect.iscoroutinefunction(function):
            try:
                value = self._callback_context.run(function, *args)
            except BaseException as error:
                result.set_exception(error)
            else:
                result.set_result(value)
            return

        coroutine = self._callback_context.run(function, *args)
        task = self.loop.create_task(
            coroutine,
            context=self._callback_context.copy(),
        )
        self._tasks.add(task)

        def finish(completed):
            try:
                value = completed.result()
            except BaseException as error:
                result.set_exception(error)
            else:
                result.set_result(value)
            finally:
                self._tasks.discard(completed)
                if self._closing and not self._tasks:
                    self.loop.stop()

        task.add_done_callback(finish)

    def submit(self, function, args):
        with self._state_lock:
            if (self._closing or self._thread is None or
                    not self._thread.is_alive()):
                raise RuntimeError("Concurrent runner is not active")
            result = concurrent_futures.Future()
            # The publishing thread's context must not enter the executor. The
            # runner applies its own persistent worker context in _begin().
            self._enqueue(
                (
                    self._begin,
                    (function, args, result),
                    contextvars.Context(),
                )
            )
        return result

    def _enqueue(self, entry):
        """Publish one operation and wake the selector with an ordinary pipe."""
        self._pending.put(entry)
        try:
            os.write(self._write_fd, b"\0")
        except BlockingIOError:
            # A full pipe is already readable, so the loop will drain the
            # complete operation queue without requiring another byte.
            pass

    def _drain_pending(self):
        """Run queued operations on the runner thread in publication order."""
        while True:
            try:
                chunk = os.read(self._read_fd, 4096)
            except BlockingIOError:
                break
            if not chunk or len(chunk) < 4096:
                break

        while True:
            try:
                entry = self._pending.get_nowait()
            except queue.Empty:
                return

            if entry is self._STOP:
                if not self._tasks:
                    self.loop.stop()
                continue

            callback, args, context = entry
            context.run(callback, *args)

    def _close_descriptors(self):
        read_fd = self._read_fd
        write_fd = self._write_fd
        self._read_fd = -1
        self._write_fd = -1
        if read_fd >= 0:
            self.loop.remove_reader(read_fd)
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)

    def close(self):
        with self._state_lock:
            thread = self._thread
            self._closing = True
            if thread is not None:
                self._enqueue(self._STOP)
        if thread is None:
            self._close_descriptors()
            if not self.loop.is_closed():
                self.loop.close()
            return
        thread.join(timeout=1)
        if thread.is_alive():
            raise RuntimeError("Concurrent runner did not stop")
        self._thread = None
        self._close_descriptors()
        if not self.loop.is_closed():
            self.loop.close()


def configure_concurrent_runner(runner):
    """Install worker-owned execution infrastructure before loading an addon."""
    global _runner
    if runner is not None and not isinstance(runner, ConcurrentRunner):
        raise TypeError("Invalid concurrent runner")
    _runner = runner


async def _await_concurrent_result(result):
    """Await a worker result without relying on another loop's socket wakeup.

    The addon sandbox deliberately denies arbitrary socket operations.  Polling
    the in-memory future keeps completion deterministic even when CPython's
    private cross-thread selector socket is unavailable.  The short yield also
    preserves cancellation of the awaiting lifecycle hook without cancelling a
    callback that is already running in the dedicated runner.
    """
    while not result.done():
        await asyncio.sleep(0.001)
    return result.result()


def concurrent(function):
    """Run a supported lifecycle callback in the worker's thread executor.

    The public wrapper accepts positional arguments only.  A coroutine callback
    gets its own event loop in the executor thread; a regular callback executes
    directly there.  Callback return values are intentionally discarded, while
    exceptions pass back to the normal addon failure reporting path.
    """
    name = function.__name__
    if name not in _CONCURRENT_HOOKS:
        raise NotImplementedError(
            f"Concurrent decorator not supported for '{name}' method."
        )

    async def _concurrent(*args):
        runner = _runner
        if runner is not None:
            await _await_concurrent_result(runner.submit(function, args))
            return

        def invoke():
            if inspect.iscoroutinefunction(function):
                return asyncio.run(function(*args))
            return function(*args)

        # Do not use asyncio's default executor here.  Its completion callback
        # wakes the event loop through asyncio's private selector socket, which
        # is intentionally unavailable in a restricted Spider worker.  Polling
        # an ordinary concurrent Future is descriptor-free and also keeps all
        # callbacks from one script on the same fallback thread.
        result = _fallback_executor.submit(invoke)
        await _await_concurrent_result(result)

    # Addons sometimes inspect their callbacks.  Expose the public compatibility
    # module rather than Spider's private implementation module.
    _concurrent.__module__ = "mitmproxy.script.concurrent"
    return _concurrent


concurrent.__module__ = "mitmproxy.script.concurrent"
