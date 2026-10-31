"""Observe targeted invocation when a regular callback returns an awaitable."""

import json
import os
from pathlib import Path
import warnings

from mitmproxy import ctx, hooks, version


events = []


async def _late_callback():
    events.append("awaited")


class Target:
    def running(self):
        events.append("called")
        return _late_callback()


class CustomAwaitable:
    def __await__(self):
        events.append("awaited custom")
        if False:
            yield None


class CustomTarget:
    def running(self):
        events.append("called custom")
        return CustomAwaitable()


class Probe:
    async def running(self):
        result = {
            "reference": version.MITMPROXY,
            "sync": {"error": None, "returned_none": False},
            "async": {"error": None, "returned_none": False},
            "sync_custom": {"error": None, "returned_none": False},
            "async_custom": {"error": None, "returned_none": False},
        }
        target = Target()
        with warnings.catch_warnings(record=True) as observed_warnings:
            warnings.simplefilter("always")
            try:
                value = ctx.master.addons.invoke_addon_sync(
                    target,
                    hooks.RunningHook(),
                )
                result["sync"]["returned_none"] = value is None
            except Exception as error:
                result["sync"]["error"] = type(error).__name__
        result["sync"]["warnings"] = [
            type(item.message).__name__ + ": " + str(item.message)
            for item in observed_warnings
        ]
        result["sync"]["events"] = list(events)

        events.clear()
        try:
            value = await ctx.master.addons.invoke_addon(
                target,
                hooks.RunningHook(),
            )
            result["async"]["returned_none"] = value is None
        except Exception as error:
            result["async"]["error"] = type(error).__name__
        result["async"]["events"] = list(events)

        events.clear()
        target = CustomTarget()
        try:
            value = ctx.master.addons.invoke_addon_sync(
                target,
                hooks.RunningHook(),
            )
            result["sync_custom"]["returned_none"] = value is None
        except Exception as error:
            result["sync_custom"]["error"] = type(error).__name__
        result["sync_custom"]["events"] = list(events)

        events.clear()
        try:
            value = await ctx.master.addons.invoke_addon(
                target,
                hooks.RunningHook(),
            )
            result["async_custom"]["returned_none"] = value is None
        except Exception as error:
            result["async_custom"]["error"] = type(error).__name__
        result["async_custom"]["events"] = list(events)

        Path(os.environ["SPIDER_INVOCATION_AWAITABLE_OUTPUT"]).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        ctx.master.shutdown()


addons = [Probe()]
