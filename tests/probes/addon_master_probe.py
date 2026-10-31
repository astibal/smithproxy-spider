"""Record the public live Master boundary from an independent reference run.

Load this file with a separately installed mitmdump and set
MITM_MASTER_PROBE_OUTPUT to a disposable output path.  The probe observes only
public runtime objects; it does not import or inspect implementation sources.
"""

import asyncio
import inspect
import json
import os
from pathlib import Path

from mitmproxy import ctx, version


class Probe:
    def running(self):
        master = ctx.master
        public = sorted(name for name in dir(master) if not name.startswith("_"))
        signatures = {}
        for name in public:
            value = getattr(master, name)
            if not callable(value):
                continue
            try:
                signatures[name] = str(inspect.signature(value))
            except (TypeError, ValueError):
                signatures[name] = None

        result = {
            "reference": version.MITMPROXY,
            "public": public,
            "signatures": signatures,
            "observations": {
                "event_loop_is_running": master.event_loop.is_running(),
                "event_loop_is_asyncio": isinstance(
                    master.event_loop,
                    asyncio.AbstractEventLoop,
                ),
                "log_is_ctx_log": master.log is ctx.log,
                "ctx_log_master_is_master": ctx.log.master is master,
                "running_type": type(master.running).__name__,
                "should_exit_type": type(master.should_exit).__name__,
                "should_exit_is_set": master.should_exit.is_set(),
            },
        }
        shutdown_result = master.shutdown()
        result["observations"].update({
            "shutdown_result": shutdown_result,
            "shutdown_result_type": type(shutdown_result).__name__,
            "should_exit_after_shutdown": master.should_exit.is_set(),
        })
        Path(os.environ["MITM_MASTER_PROBE_OUTPUT"]).write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


addons = [Probe()]
