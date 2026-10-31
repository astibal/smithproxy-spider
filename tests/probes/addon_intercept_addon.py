"""Reference-only addon for the intercept/resume lifecycle probe."""

import asyncio
import json


def report(name, flow):
    print("PROBE " + json.dumps({
        "hook": name,
        "path": flow.request.path,
        "live": flow.live,
        "intercepted": flow.intercepted,
        "error": None if flow.error is None else flow.error.msg,
    }), flush=True)


async def resume_later(flow):
    await asyncio.sleep(.05)
    report("before-resume", flow)
    flow.resume()
    report("after-resume", flow)


def requestheaders(flow):
    report("requestheaders", flow)


def request(flow):
    report("request", flow)
    flow.intercept()
    report("after-intercept", flow)
    asyncio.create_task(resume_later(flow))


def responseheaders(flow):
    report("responseheaders", flow)


def response(flow):
    report("response", flow)


def error(flow):
    report("error", flow)

