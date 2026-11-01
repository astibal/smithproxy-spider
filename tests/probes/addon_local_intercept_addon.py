"""Own black-box addon: pause a generated response at either response hook."""

import asyncio
import json

from mitmproxy import http


def report(hook, flow):
    print('PROBE ' + json.dumps({
        'hook': hook,
        'path': flow.request.path,
        'body': flow.response.raw_content.decode('ascii'),
        'error': None if flow.error is None else flow.error.msg,
    }), flush=True)


async def release_later(flow):
    await asyncio.sleep(0.05)
    if flow.request.path.endswith('/resume-kill'):
        flow.resume()
        flow.kill()
    elif flow.request.path.endswith('/kill-resume'):
        flow.kill()
        flow.resume()
    elif flow.request.path.endswith('/kill'):
        flow.kill()
    else:
        flow.response.content = b'edited while held'
        flow.resume()
    report('released', flow)


def request(flow):
    flow.response = http.Response.make(200, b'local original')
    report('request', flow)


def responseheaders(flow):
    report('responseheaders', flow)
    if flow.request.path.startswith('/headers/'):
        flow.intercept()
        asyncio.create_task(release_later(flow))


def response(flow):
    report('response', flow)
    if flow.request.path.startswith('/response/'):
        flow.intercept()
        asyncio.create_task(release_later(flow))


def error(flow):
    report('error', flow)
