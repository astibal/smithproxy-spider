"""Concurrent decorator behavior against the mitmproxy 12 corpus."""

import asyncio
import contextvars
import fcntl
import importlib
import json
from pathlib import Path
import sys
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from addon_concurrent_contract import collect
from addon_loader import compatibility_imports
from addon_modules import compatibility_modules
from addon_script import ConcurrentRunner, configure_concurrent_runner, concurrent


class ConcurrentTests(unittest.TestCase):
    def test_public_contract_matches_reference(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_concurrent_v12.json").read_text()
        )
        modules = compatibility_modules()
        loop = asyncio.new_event_loop()
        runner = ConcurrentRunner(loop)
        runner.start()
        configure_concurrent_runner(runner)
        try:
            with compatibility_imports(modules):
                script_module = importlib.import_module("mitmproxy.script")
                implementation_module = importlib.import_module(
                    "mitmproxy.script.concurrent"
                )
                actual = collect(script_module, implementation_module)
        finally:
            configure_concurrent_runner(None)
            runner.close()

        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, {
            "surface": corpus["surface"],
            "execution": corpus["execution"],
        })

    def test_runner_rejects_invalid_or_active_loops(self):
        with self.assertRaisesRegex(TypeError, "asyncio event loop"):
            ConcurrentRunner(object())

        loop = asyncio.new_event_loop()
        loop.close()
        with self.assertRaisesRegex(ValueError, "fresh event loop"):
            ConcurrentRunner(loop)

    def test_inactive_runner_rejects_submission_and_closes_cleanly(self):
        loop = asyncio.new_event_loop()
        runner = ConcurrentRunner(loop)
        with self.assertRaisesRegex(RuntimeError, "not active"):
            runner.submit(lambda: None, ())
        runner.close()
        self.assertTrue(loop.is_closed())
        with self.assertRaisesRegex(RuntimeError, "already closed"):
            runner.start()

    def test_invalid_runner_configuration_is_rejected(self):
        with self.assertRaisesRegex(TypeError, "Invalid concurrent runner"):
            configure_concurrent_runner(object())


class ConcurrentRunnerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runner_loop = asyncio.new_event_loop()
        self.runner = ConcurrentRunner(self.runner_loop)
        self.runner.start()
        configure_concurrent_runner(self.runner)

    async def asyncTearDown(self):
        configure_concurrent_runner(None)
        self.runner.close()

    async def test_runner_serializes_regular_and_coroutine_callbacks_on_one_thread(self):
        caller_thread = threading.get_ident()
        marker = contextvars.ContextVar("runner_test", default="missing")
        marker.set("caller")
        observations = []

        @concurrent
        def running(value):
            observations.append(
                ("sync", value, threading.get_ident(), marker.get())
            )
            return "ignored"

        @concurrent
        async def done(value):
            await asyncio.sleep(0)
            observations.append(
                ("async", value, threading.get_ident(), marker.get())
            )
            return "ignored"

        self.assertIsNone(await running("one"))
        self.assertIsNone(await done("two"))
        self.assertEqual([item[:2] for item in observations], [
            ("sync", "one"),
            ("async", "two"),
        ])
        callback_threads = {item[2] for item in observations}
        self.assertEqual(len(callback_threads), 1)
        self.assertNotIn(caller_thread, callback_threads)
        self.assertEqual([item[3] for item in observations], ["missing", "missing"])

    async def test_pipe_wakeup_does_not_depend_on_asyncio_private_socket(self):
        configure_concurrent_runner(None)
        self.runner.close()

        loop = asyncio.new_event_loop()
        original_wakeup = loop._write_to_self
        loop._write_to_self = lambda: None
        runner = ConcurrentRunner(loop)
        try:
            runner.start()
            result = runner.submit(lambda: "awake", ())
            self.assertEqual(await asyncio.wrap_future(result), "awake")
        finally:
            runner.close()
            loop._write_to_self = original_wakeup

    async def test_full_wakeup_pipe_does_not_drop_queued_callbacks(self):
        entered = threading.Event()
        release = threading.Event()
        observed = []

        def block_runner():
            entered.set()
            release.wait(timeout=5)

        first = self.runner.submit(block_runner, ())
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.001)

        pipe_size = fcntl.fcntl(
            self.runner._write_fd,
            fcntl.F_SETPIPE_SZ,
            4096,
        )
        callback_count = pipe_size + 64

        def record(index):
            observed.append(index)

        queued = [
            self.runner.submit(record, (index,))
            for index in range(callback_count)
        ]
        release.set()

        async with asyncio.timeout(5):
            while not all(result.done() for result in queued):
                await asyncio.sleep(0.001)

        self.assertIsNone(first.result())
        self.assertTrue(all(result.result() is None for result in queued))
        self.assertEqual(observed, list(range(callback_count)))

    async def test_runner_propagates_callback_failure(self):
        @concurrent
        def update(_flows):
            raise LookupError("runner failure")

        with self.assertRaisesRegex(LookupError, "runner failure"):
            await update(())

    async def test_coroutine_failure_does_not_poison_later_callbacks(self):
        @concurrent
        async def update(_flows):
            await asyncio.sleep(0)
            raise LookupError("coroutine failure")

        @concurrent
        def running():
            return "ignored"

        with self.assertRaisesRegex(LookupError, "coroutine failure"):
            await update(())
        self.assertIsNone(await running())

    async def test_coroutine_callbacks_can_overlap_on_the_runner_loop(self):
        entered = []
        completed = []

        @concurrent
        async def update(value):
            entered.append(value)
            while len(entered) < 2:
                await asyncio.sleep(0)
            completed.append(value)

        first = asyncio.create_task(update("first"))
        second = asyncio.create_task(update("second"))
        await asyncio.gather(first, second)

        self.assertEqual(entered, ["first", "second"])
        self.assertCountEqual(completed, ["first", "second"])

    async def test_standard_executor_fallback_handles_sync_async_and_failure(self):
        configure_concurrent_runner(None)
        caller_thread = threading.get_ident()
        observations = []

        @concurrent
        def running(value):
            observations.append(("sync", value, threading.get_ident()))

        @concurrent
        async def done(value):
            await asyncio.sleep(0)
            observations.append(("async", value, threading.get_ident()))

        @concurrent
        def update(_flows):
            raise LookupError("fallback failure")

        self.assertIsNone(await running("one"))
        self.assertIsNone(await done("two"))
        with self.assertRaisesRegex(LookupError, "fallback failure"):
            await update(())

        self.assertEqual([item[:2] for item in observations], [
            ("sync", "one"),
            ("async", "two"),
        ])
        self.assertTrue(all(item[2] != caller_thread for item in observations))

    async def test_cancelling_wrapper_does_not_interrupt_running_callback(self):
        completed = threading.Event()

        @concurrent
        def running():
            time.sleep(0.02)
            completed.set()

        task = asyncio.create_task(running())
        await asyncio.sleep(0.005)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        await asyncio.sleep(0.04)
        self.assertTrue(completed.is_set())

    async def test_close_waits_for_a_callback_after_its_await_is_cancelled(self):
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()

        @concurrent
        def running():
            entered.set()
            release.wait(timeout=1)
            completed.set()

        task = asyncio.create_task(running())
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.001)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        timer = threading.Timer(0.02, release.set)
        timer.start()
        try:
            self.runner.close()
        finally:
            timer.cancel()

        self.assertTrue(completed.is_set())
        self.assertTrue(self.runner_loop.is_closed())
        with self.assertRaisesRegex(RuntimeError, "not active"):
            self.runner.submit(lambda: None, ())

    async def test_runner_cannot_start_twice(self):
        with self.assertRaisesRegex(RuntimeError, "already started"):
            self.runner.start()

    async def test_cancelled_queued_submission_never_runs(self):
        entered = threading.Event()
        release = threading.Event()
        called = []

        def blocking():
            entered.set()
            release.wait(timeout=1)

        first = self.runner.submit(blocking, ())
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.001)
        second = self.runner.submit(lambda: called.append("unexpected"), ())
        self.assertTrue(second.cancel())
        release.set()
        await asyncio.wrap_future(first)
        await asyncio.sleep(0.01)
        self.assertEqual(called, [])

    async def test_close_rejects_new_work_and_drains_accepted_coroutine(self):
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()

        async def callback():
            entered.set()
            while not release.is_set():
                await asyncio.sleep(0)
            completed.set()

        accepted = self.runner.submit(callback, ())
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.001)

        close_thread = threading.Thread(target=self.runner.close)
        close_thread.start()
        async with asyncio.timeout(1):
            while True:
                with self.runner._state_lock:
                    if self.runner._closing:
                        break
                await asyncio.sleep(0.001)

        with self.assertRaisesRegex(RuntimeError, "not active"):
            self.runner.submit(lambda: None, ())

        release.set()
        close_thread.join(timeout=1)
        self.assertFalse(close_thread.is_alive())
        self.assertTrue(completed.is_set())
        self.assertEqual(accepted.result(), None)
        self.assertTrue(self.runner_loop.is_closed())


if __name__ == "__main__":
    unittest.main()
