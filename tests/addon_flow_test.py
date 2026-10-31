"""Flow control and state identity tests for the clean-room addon runtime."""

import asyncio
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_flow import ControlException, Error, HTTPFlow
from addon_http_message import Request, Response
from addon_loader import LoadedAddon, compatibility_imports
from addon_modules import compatibility_modules
import addon_flow
from addon_flow_contract import collect, collect_transport


def new_flow():
    flow = HTTPFlow(SimpleNamespace(peername=("127.0.0.1", 1234)),
                    SimpleNamespace(address=("example.org", 443)), live=True)
    flow.request = Request.make("GET", "https://example.org/")
    return flow


class FlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_deprecated_http_mode_matches_reference_default_and_storage(self):
        flow = new_flow()
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter('always')
            self.assertEqual(flow.mode, 'regular')
            flow.mode = 'transparent'
            self.assertEqual(flow.mode, 'transparent')
        self.assertEqual(
            [(item.category, str(item.message)) for item in captured],
            [(DeprecationWarning, 'HTTPFlow.mode is deprecated.')] * 3,
        )
    async def test_tcp_udp_reference_contracts(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_transport_v12.json').read_text())

        def peers():
            return SimpleNamespace(timestamp_start=12), SimpleNamespace()

        for name in ('tcp', 'udp'):
            with self.subTest(protocol=name):
                observed = collect_transport(getattr(addon_flow, name.upper() + 'Message'),
                                             getattr(addon_flow, name.upper() + 'Flow'), peers)
                self.assertEqual(observed, corpus['cases'][name])

    async def test_transport_facade_and_message_lists_are_independent(self):
        with compatibility_imports(compatibility_modules()):
            from mitmproxy import tcp, udp
            from mitmproxy.flow import Flow
            first = tcp.TCPFlow(None, None)
            second = tcp.TCPFlow(None, None)
            datagrams = udp.UDPFlow(None, None)
            first.messages.append(tcp.TCPMessage(True, b'chunk', 1))
            datagrams.messages.append(udp.UDPMessage(True, b'', 2))
            datagrams.messages.append(udp.UDPMessage(False, b'packet', 3))
            self.assertIsInstance(first, Flow)
            self.assertIsInstance(new_flow(), Flow)
            self.assertEqual(second.messages, [])
            self.assertEqual([item.content for item in datagrams.messages], [b'', b'packet'])
            self.assertFalse(hasattr(datagrams, 'request'))
            self.assertFalse(hasattr(datagrams, 'response'))

    async def test_import_facade_is_generation_local_and_has_no_disk_fallback(self):
        first = compatibility_modules()
        second = compatibility_modules()
        first["mitmproxy.http"].generation_marker = "first"
        self.assertFalse(hasattr(second["mitmproxy.http"], "generation_marker"))
        with compatibility_imports(first):
            from mitmproxy import http
            from mitmproxy.coretypes import multidict
            from mitmproxy.exceptions import ControlException as ImportedControlException
            self.assertIs(http.HTTPFlow, HTTPFlow)
            self.assertIs(ImportedControlException, ControlException)
            self.assertEqual(multidict.MultiDict([("x", "1")])["x"], "1")
            with self.assertRaises(ModuleNotFoundError):
                __import__("mitmproxy.proxy.server")
            self.assertFalse(hasattr(http, "gzip"))
            self.assertFalse(hasattr(http, "_endpoint"))
        self.assertNotIn("mitmproxy", sys.modules)

    async def test_public_lifecycle_contract(self):
        http = SimpleNamespace(HTTPFlow=HTTPFlow, Request=Request)
        corpus = json.loads((ROOT / 'tests/corpus/addon_flow_v12.json').read_text())
        actual = collect(http, addon_flow, lambda: (SimpleNamespace(), SimpleNamespace()))
        self.assertEqual(actual, corpus['cases'])

    async def test_request_and_response_share_flow_and_addon_state(self):
        addon = LoadedAddon('''from mitmproxy import http
class Recorder:
    def __init__(self):
        self.requests = {}
        self.completed = 0

    def request(self, flow: http.HTTPFlow):
        self.requests[flow.id] = flow
        flow.metadata["request_seen"] = True

    async def response(self, flow: http.HTTPFlow):
        assert self.requests.pop(flow.id) is flow
        assert flow.metadata["request_seen"]
        self.completed += 1
        flow.response.headers["x-completed"] = str(self.completed)

addons = [Recorder()]
''', compatibility_modules(), {"request", "response"})
        first = new_flow()
        second = new_flow()
        for flow in (first, second):
            self.assertEqual(await addon.dispatch("request", flow), ())
        # Responses may arrive in the opposite order on multiplexed streams.
        for index, flow in enumerate((second, first), 1):
            flow.response = Response.make(content=b"response")
            self.assertEqual(await addon.dispatch("response", flow), ())
            self.assertEqual(flow.response.headers["x-completed"], str(index))
        self.assertNotIn("mitmproxy", sys.modules)

    async def test_intercept_can_resume_multiple_waiters(self):
        flow = new_flow()
        await flow.wait_for_resume()
        flow.intercept()
        waiting = [asyncio.create_task(flow.wait_for_resume()) for _ in range(2)]
        await asyncio.sleep(0)
        self.assertTrue(all(not task.done() for task in waiting))
        flow.resume()
        await asyncio.wait_for(asyncio.gather(*waiting), timeout=1)
        self.assertFalse(flow.intercepted)
        self.assertTrue(flow.live)
        flow.intercept()
        task = asyncio.create_task(flow.wait_for_resume())
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        flow.kill()
        await asyncio.wait_for(task, timeout=1)
        self.assertFalse(flow.live)
        self.assertFalse(flow.intercepted)
        self.assertFalse(flow.killable)
        self.assertEqual(flow.error.msg, "Connection killed.")
        with self.assertRaises(ControlException):
            flow.kill()

    async def test_detached_copy_does_not_share_pending_waiters(self):
        flow = new_flow()
        flow.metadata["nested"] = [1]
        flow.intercept()
        task = asyncio.create_task(flow.wait_for_resume())
        await asyncio.sleep(0)
        copied = flow.copy()
        copied.resume()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertNotEqual(copied.id, flow.id)
        self.assertFalse(copied.live)
        copied.request.path = "/other"
        copied.metadata["nested"].append(2)
        self.assertEqual(flow.request.path, "/")
        self.assertEqual(flow.metadata["nested"], [1])
        flow.resume()
        await asyncio.wait_for(task, timeout=1)

    async def test_error_does_not_prevent_explicit_kill(self):
        flow = new_flow()
        flow.error = Error("upstream failed", 123)
        self.assertTrue(flow.killable)
        self.assertEqual(flow.error.get_state(), {"msg": "upstream failed", "timestamp": 123.0})
        self.assertEqual(str(flow.error), "upstream failed")
        flow.kill()
        self.assertFalse(flow.killable)


if __name__ == "__main__":
    unittest.main()
