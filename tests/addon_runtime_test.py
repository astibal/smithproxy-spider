"""Deployment generation lifecycle and state retention, without proxy sockets."""

import asyncio
from dataclasses import dataclass
import inspect
import json
from pathlib import Path
import sys
import textwrap
from types import SimpleNamespace
import unittest
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_runtime import AddonGeneration, AddonMaster, AddonRuntimeError
from addon_loader import AddonLoadError
from addon_manager import AddonManager, AddonManagerError
from addon_modules import compatibility_modules
from addon_options import OptManager, OptionsError
from addon_registration_contract import collect as collect_registration
from addon_registration_failure_contract import collect as collect_registration_failures
from addon_hooks_contract import collect as collect_hooks
from addon_invocation_contract import collect as collect_invocation
from addon_lifecycle_handler_contract import collect as collect_lifecycle_handler
from addon_update_contract import collect as collect_update
from addon_connection import Client, Server
from addon_flow import Error, HTTPFlow, TCPFlow, TCPMessage, UDPFlow, UDPMessage
from addon_http_message import Request, Response
from addon_load_flow_contract import collect as collect_load_flow
import addon_hooks
import addon_dns
import addon_websocket


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_master_load_flow_reference_contract(self):
        hooks = {
            'load', 'requestheaders', 'request', 'responseheaders', 'response',
            'error', 'tcp_start', 'tcp_message', 'tcp_end', 'tcp_error',
            'udp_start', 'udp_message', 'udp_end', 'udp_error',
            'dns_request', 'dns_response', 'dns_error',
            'websocket_start', 'websocket_message', 'websocket_end',
        }
        options = OptManager()
        manager = AddonManager(options, hooks)
        master = AddonMaster(options, manager)
        self.assertTrue(inspect.iscoroutinefunction(master.load_flow))
        self.assertEqual(str(inspect.signature(master.load_flow)), '(f)')
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_load_flow_v12.json').read_text()
        )
        actual = await collect_load_flow(
            master,
            SimpleNamespace(HTTPFlow=HTTPFlow, Request=Request, Response=Response),
            SimpleNamespace(TCPFlow=TCPFlow, TCPMessage=TCPMessage),
            SimpleNamespace(UDPFlow=UDPFlow, UDPMessage=UDPMessage),
            addon_dns,
            addon_websocket,
            SimpleNamespace(Client=Client, Server=Server),
            SimpleNamespace(Error=Error),
        )
        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(actual, corpus['cases'])

    async def test_master_load_flow_uses_the_generation_import_scope(self):
        generation = AddonGeneration('''from mitmproxy import connection, ctx, http

events = []

def requestheaders(flow):
    events.append(("headers", flow.request.path))

def request(flow):
    events.append(("request", flow.request.path))

async def running():
    client = connection.Client(peername=("127.0.0.1", 41000),
                               sockname=("127.0.0.1", 8080))
    server = connection.Server(address=("example.test", 443))
    flow = http.HTTPFlow(client, server)
    flow.request = http.Request.make("GET", "https://example.test/replayed")
    await ctx.master.load_flow(flow)
''', {'requestheaders', 'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(generation.addon.module.events, [
                ('headers', '/replayed'),
                ('request', '/replayed'),
            ])
        finally:
            await generation.close()

    async def test_master_load_flow_reports_failure_and_continues_delivery(self):
        generation = AddonGeneration('''from mitmproxy import connection, ctx, http

events = []

class Broken:
    name = "broken"
    def request(self, flow):
        events.append("broken")
        raise ValueError("detached replay failed")

class Following:
    name = "following"
    def request(self, flow):
        events.append("following")

async def running():
    ctx.master.addons.add(Broken(), Following())
    client = connection.Client(peername=("127.0.0.1", 41000),
                               sockname=("127.0.0.1", 8080))
    server = connection.Server(address=("example.test", 443))
    flow = http.HTTPFlow(client, server)
    flow.request = http.Request.make("GET", "https://example.test/replayed")
    await ctx.master.load_flow(flow)
''', {'requestheaders', 'request'})
        try:
            failures = await generation.start()
            self.assertEqual(generation.addon.module.events, ['broken', 'following'])
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0].hook, 'request')
            self.assertEqual(failures[0].addon, 'broken')
            self.assertEqual(str(failures[0].exception), 'detached replay failed')
        finally:
            await generation.close()

    async def test_public_update_hook_reference_contract(self):
        class Master:
            def __init__(self):
                self.addons = AddonManager(
                    OptManager(),
                    {'load', 'update', 'done'},
                )

        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_update_v12.json').read_text()
        )
        actual = await collect_update(Master, addon_hooks.UpdateHook)
        self.assertEqual(actual, corpus['observations'])

    async def test_generation_accepts_and_dispatches_update_hook(self):
        generation = AddonGeneration('''events = []
async def update(flows):
    events.append(list(flows))
''', {'request'})
        marker = object()
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(await generation.update([marker]), ())
            self.assertEqual(generation.addon.module.events, [[marker]])
        finally:
            await generation.close()

    async def test_public_lifecycle_handler_reference_contract(self):
        @dataclass
        class RequestHook(addon_hooks.Hook):
            flow: object

        class Master:
            def __init__(self):
                self.addons = AddonManager(
                    OptManager(),
                    {'load', 'request'},
                )

        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_lifecycle_handler_v12.json').read_text()
        )
        actual = await collect_lifecycle_handler(
            Master,
            RequestHook,
            addon_hooks.RunningHook,
            object,
            OptionsError,
        )
        self.assertEqual(actual, corpus['observations'])

    async def test_master_exposes_reference_log_and_running_event_loop(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_master_v12.json').read_text()
        )
        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertTrue({
            'addons', 'commands', 'event_loop', 'log', 'options',
        }.issubset(corpus['public']))
        self.assertIsNone(corpus['observations']['shutdown_result'])
        self.assertEqual(
            corpus['observations']['shutdown_result_type'],
            'NoneType',
        )
        self.assertEqual(corpus['observations']['running_type'], 'method')
        self.assertEqual(corpus['observations']['should_exit_type'], 'Event')
        self.assertFalse(corpus['observations']['should_exit_after_shutdown'])

        generation = AddonGeneration('''import asyncio
from mitmproxy import ctx

observations = []

def load(loader):
    observations.append({
        "event_loop_is_current": ctx.master.event_loop is asyncio.get_running_loop(),
        "event_loop_is_running": ctx.master.event_loop.is_running(),
        "log_is_ctx_log": ctx.master.log is ctx.log,
        "ctx_log_master_is_master": ctx.log.master is ctx.master,
    })
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(generation.addon.module.observations, [{
                'event_loop_is_current': True,
                'event_loop_is_running': True,
                'log_is_ctx_log': True,
                'ctx_log_master_is_master': True,
            }])
            self.assertIs(generation.master.event_loop, asyncio.get_running_loop())
            self.assertEqual(
                sorted(
                    name for name in dir(generation.master)
                    if not name.startswith('_')
                ),
                ['addons', 'commands', 'event_loop', 'load_flow', 'log', 'options'],
            )
            self.assertFalse(hasattr(generation.master, 'shutdown'))
            self.assertTrue(callable(generation.master.load_flow))
        finally:
            await generation.close()

    async def test_deployment_option_overrides_precede_initial_configuration(self):
        generation = AddonGeneration('''from mitmproxy import ctx
events = []
def load(loader):
    events.append(("load", None))
    loader.add_option("probe_count", int, 1, "Test count")
def configure(updated):
    events.append(("configure", ctx.options.probe_count, "probe_count" in updated))
def running():
    events.append(("running", ctx.options.probe_count))
''', {'request'})
        try:
            self.assertEqual(await generation.start(
                option_specs=['probe_count=7']), ())
            self.assertEqual(generation.addon.module.events, [
                ('load', None),
                ('configure', 7, True),
                ('running', 7),
            ])
        finally:
            await generation.close()

    async def test_registered_content_views_run_in_the_persistent_generation(self):
        generation = AddonGeneration('''from mitmproxy import contentviews
class Upper(contentviews.InteractiveContentview):
    syntax_highlight = "yaml"
    calls = 0
    def prettify(self, data, metadata):
        from mitmproxy import ctx
        assert ctx.options is not None
        self.calls += 1
        return data.decode().upper() + ":" + str(self.calls)
    def render_priority(self, data, metadata):
        return 2 if metadata.content_type == "text/probe" else -1
    def reencode(self, text, metadata):
        assert metadata.original_data == b"original"
        return text.lower().encode()
contentviews.add(Upper)
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(generation.content_view('list'), {
                'views': [{
                    'key': 'upper',
                    'name': 'Upper',
                    'syntax_highlight': 'yaml',
                    'interactive': True,
                }],
            })
            self.assertEqual(generation.content_view(
                'render', data=b'hello', content_type='text/probe',
                view_name='auto'), {
                    'text': 'HELLO:1',
                    'syntax_highlight': 'yaml',
                    'view_name': 'Upper',
                    'interactive': True,
                })
            self.assertEqual(generation.content_view(
                'render', data=b'again', content_type='text/probe',
                view_name='upper')['text'], 'AGAIN:2')
            self.assertEqual(generation.content_view(
                'reencode', text='EDITED', original_data=b'original',
                content_type='text/probe', view_name='Upper'), {
                    'data': b'edited',
                })
        finally:
            await generation.close()

    async def test_content_view_failure_does_not_poison_addon_state(self):
        generation = AddonGeneration('''from mitmproxy import contentviews
class Broken(contentviews.Contentview):
    def prettify(self, data, metadata):
        raise ValueError("cannot decode")
contentviews.add(Broken)
''', {'request'})
        try:
            await generation.start()
            with self.assertRaisesRegex(ValueError, 'cannot decode'):
                generation.content_view(
                    'render', data=b'x', content_type=None, view_name='Broken')
            self.assertEqual(generation.state, 'running')
            self.assertEqual(await generation.dispatch('request', None), ())
        finally:
            await generation.close()

    async def test_manager_public_size_text_and_identity_membership(self):
        manager = AddonManager(OptManager(), {'load', 'done'})

        class Addon:
            def __init__(self, name, children=()):
                self.name = name
                self.addons = list(children)

            def __str__(self):
                return self.name

        child = Addon('child')
        parent = Addon('parent', [child])
        self.assertEqual(len(manager), 0)
        self.assertEqual(str(manager), '[]')
        self.assertNotIn(parent, manager)

        manager.add(parent)
        self.assertEqual(len(manager), 1)
        self.assertEqual(str(manager), "['parent']")
        self.assertIn(parent, manager)
        self.assertIn(child, manager)
        self.assertNotIn('parent', manager)
        self.assertNotIn(Addon('parent'), manager)

        manager.remove(parent)
        self.assertEqual(len(manager), 0)
        self.assertNotIn(child, manager)

    async def test_cancellation_keeps_earlier_failure_for_shutdown_report(self):
        generation = AddonGeneration('''import asyncio
entered = asyncio.Event()
class Broken:
    def request(self, flow):
        raise ValueError("failure before cancellation")
class Waiting:
    async def request(self, flow):
        entered.set()
        await asyncio.Future()
addons = [Broken(), Waiting()]
''', {'request'})
        await generation.start()
        task = asyncio.create_task(generation.dispatch('request', None))
        try:
            await asyncio.wait_for(generation.addon.module.entered.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(generation.state, 'failed')
            failures = await generation.close()
            self.assertEqual(len(failures), 1)
            self.assertEqual(str(failures[0].exception), 'failure before cancellation')
            self.assertEqual(await generation.close(), ())
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await generation.close()

    async def test_trigger_rejection_preserves_earlier_callback_failures(self):
        source = '''from mitmproxy import ctx, hooks, exceptions
events = []
class Broken:
    def configure(self, updated):
        if "probe" in updated:
            raise ValueError("earlier callback failed")
class Rejecting:
    def configure(self, updated):
        if "probe" in updated:
            raise exceptions.OptionsError("configuration rejected")
class Later:
    def configure(self, updated):
        if "probe" in updated:
            events.append("unexpected later callback")
addons = [Broken(), Rejecting(), Later()]
async def request(flow):
    try:
        TRIGGER
    except exceptions.OptionsError:
        events.append("rejection caught")
'''
        triggers = ('ctx.master.addons.trigger(hooks.ConfigureHook({"probe"}))',
                    'await ctx.master.addons.trigger_event(hooks.ConfigureHook({"probe"}))')
        for trigger in triggers:
            with self.subTest(trigger=trigger):
                generation = AddonGeneration(source.replace('TRIGGER', trigger), {'request'})
                try:
                    self.assertEqual(await generation.start(), ())
                    failures = await generation.dispatch('request', None)
                    self.assertEqual(len(failures), 1)
                    self.assertEqual(failures[0].hook, 'configure')
                    self.assertEqual(str(failures[0].exception), 'earlier callback failed')
                    self.assertEqual(generation.addon.module.events, ['rejection caught'])
                    self.assertEqual(generation.manager._take_failures(), ())
                finally:
                    await generation.close()

    async def test_targeted_invocation_reference_contract(self):
        def factory():
            return AddonManager(OptManager(), {'running'})

        corpus = json.loads((ROOT / 'tests/corpus/addon_invocation_v12.json').read_text())
        actual = await collect_invocation(factory, addon_hooks.RunningHook)
        self.assertEqual(actual, corpus['cases'])

    async def test_sync_targeted_invocation_rejects_a_returned_awaitable(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_invocation_awaitable_v12.json').read_text()
        )
        self.assertEqual(corpus['reference'], 'mitmproxy 12.3.1')
        self.assertEqual(
            corpus['sync']['warnings'],
            ["RuntimeWarning: coroutine '_late_callback' was never awaited"],
        )

        events = []

        async def late_callback():
            events.append('awaited')

        class Target:
            def running(self):
                events.append('called')
                return late_callback()

        manager = AddonManager(OptManager(), {'running'})
        with warnings.catch_warnings(record=True) as observed_warnings:
            warnings.simplefilter('always')
            with self.assertRaisesRegex(
                    AddonManagerError,
                    'Cannot invoke an async hook synchronously'):
                manager.invoke_addon_sync(Target(), addon_hooks.RunningHook())
        self.assertEqual(events, ['called'])
        self.assertEqual(observed_warnings, [])

        events.clear()
        self.assertIsNone(await manager.invoke_addon(
            Target(), addon_hooks.RunningHook()))
        self.assertEqual(events, ['called', 'awaited'])

        class CustomAwaitable:
            def __await__(self):
                events.append('awaited custom')
                if False:
                    yield None

        class CustomTarget:
            def running(self):
                events.append('called custom')
                return CustomAwaitable()

        self.assertEqual(
            corpus['sync_custom']['events'],
            ['called custom'],
        )
        events.clear()
        with self.assertRaisesRegex(
                AddonManagerError,
                'Cannot invoke an async hook synchronously'):
            manager.invoke_addon_sync(
                CustomTarget(), addon_hooks.RunningHook())
        self.assertEqual(events, ['called custom'])

        events.clear()
        self.assertIsNone(await manager.invoke_addon(
            CustomTarget(), addon_hooks.RunningHook()))
        self.assertEqual(events, ['called custom', 'awaited custom'])

    async def test_targeted_invocation_from_a_deployed_hook(self):
        generation = AddonGeneration('''from mitmproxy import ctx, hooks
events = []
class Target:
    async def running(self):
        from mitmproxy import http
        events.append(http.Request.make("GET", "https://example.test/").host)
class Broken:
    def running(self):
        raise ValueError("target failed")
async def request(flow):
    assert await ctx.master.addons.invoke_addon(Target(), hooks.RunningHook()) is None
    try:
        ctx.master.addons.invoke_addon_sync(Broken(), hooks.RunningHook())
    except ValueError:
        events.append("caught")
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(await generation.dispatch('request', None), ())
            self.assertEqual(generation.addon.module.events, ['example.test', 'caught'])
            self.assertIsNone(generation.manager.get('target'))
        finally:
            await generation.close()

    async def test_public_triggers_propagate_options_rejection(self):
        generation = AddonGeneration('''from mitmproxy import ctx, hooks, exceptions
events = []
def configure(updated):
    if "sync" in updated or "async" in updated:
        raise exceptions.OptionsError("rejected")
async def request(flow):
    try:
        ctx.master.addons.trigger(hooks.ConfigureHook({"sync"}))
    except exceptions.OptionsError:
        events.append("sync rejected")
    try:
        await ctx.master.addons.trigger_event(hooks.ConfigureHook({"async"}))
    except exceptions.OptionsError:
        events.append("async rejected")
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(await generation.dispatch('request', None), ())
            self.assertEqual(generation.addon.module.events, ['sync rejected', 'async rejected'])
        finally:
            await generation.close()

    async def test_public_hook_value_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_hooks_v12.json').read_text())
        self.assertEqual(collect_hooks(addon_hooks, addon_hooks.LoadHook), corpus['cases'])

    async def test_public_trigger_methods_dispatch_with_scoped_imports(self):
        generation = AddonGeneration('''from mitmproxy import ctx, hooks
events = []
def configure(updated):
    events.append(sorted(updated))
async def request(flow):
    assert ctx.master.addons.trigger(hooks.ConfigureHook({"sync"})) is None
    assert await ctx.master.addons.trigger_event(hooks.ConfigureHook({"async"})) is None
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(await generation.dispatch('request', None), ())
            self.assertEqual(generation.addon.module.events, [
                sorted(generation.options.keys()), ['sync'], ['async']
            ])
        finally:
            await generation.close()

    async def test_failed_module_retains_scope_for_one_cleanup(self):
        generation = AddonGeneration('''from mitmproxy import ctx
events = []
class Dynamic:
    name = "dynamic"
    def load(self, loader):
        events.append("load")
    def done(self):
        import __spider_addon__ as own_module
        from mitmproxy import ctx
        assert own_module.events is events
        assert ctx.master.addons.get(self.name) is self
        events.append("done")
ctx.master.addons.add(Dynamic())
raise RuntimeError("module startup failed")
''', set())
        with self.assertRaisesRegex(RuntimeError, 'module startup failed'):
            await generation.start()
        self.assertEqual(generation.state, 'failed')
        self.assertEqual(await generation.close(), ())
        self.assertEqual(await generation.close(), ())
        self.assertEqual(generation.addon.module.events, ['load', 'done'])
        self.assertIsNone(generation.manager.get('dynamic'))
        self.assertNotIn('__spider_addon__', sys.modules)
        self.assertNotIn('mitmproxy', sys.modules)

    async def test_dynamic_addon_preserves_state_and_import_scope(self):
        generation = AddonGeneration('''from mitmproxy import ctx
events = []
class Dynamic:
    name = "dynamic"
    def __init__(self):
        self.calls = 0
    def load(self, loader):
        from mitmproxy import http
        assert http.Request.make("GET", "https://example.test/").host == "example.test"
        events.append("loaded")
    def request(self, flow):
        from mitmproxy import ctx
        assert ctx.master.addons.get(self.name) is self
        self.calls += 1
        events.append(self.calls)
    def done(self):
        events.append("done")
def request(flow):
    if ctx.master.addons.get("dynamic") is None:
        ctx.master.addons.add(Dynamic())
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            for index in range(2):
                self.assertEqual(await generation.dispatch('request', None), ())
            self.assertEqual(generation.addon.module.events, ['loaded', 1, 2])
        finally:
            await generation.close()
        self.assertEqual(generation.addon.module.events, ['loaded', 1, 2, 'done'])
        self.assertIsNone(generation.manager.get('dynamic'))
        self.assertNotIn('mitmproxy', sys.modules)

    async def test_uncaught_registration_failure_is_reported_by_its_calling_hook(self):
        generation = AddonGeneration('''from mitmproxy import ctx
class Broken:
    name = "broken"
    def load(self, loader):
        raise ValueError("dynamic load failure")
def request(flow):
    if ctx.master.addons.get("broken") is None:
        ctx.master.addons.add(Broken())
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            failures = await generation.dispatch('request', None)
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0].hook, 'request')
            self.assertEqual(str(failures[0].exception), 'dynamic load failure')
            self.assertIsNone(generation.manager.get('broken'))
            self.assertEqual(generation.manager._take_failures(), ())
            failures = await generation.dispatch('request', None)
            self.assertEqual(len(failures), 1)
        finally:
            await generation.close()

    async def test_script_can_catch_failed_registration_without_partial_publication(self):
        generation = AddonGeneration('''from mitmproxy import ctx
events = []
class Child:
    def load(self, loader):
        events.append("child load")
        raise ValueError("load rejected")
class Parent:
    addons = [Child()]
    def load(self, loader):
        events.append("parent load")
    def done(self):
        events.append("unexpected cleanup")
def request(flow):
    try:
        ctx.master.addons.add(Parent())
    except ValueError as error:
        events.append(str(error))
''', {'request'})
        try:
            await generation.start()
            self.assertEqual(await generation.dispatch('request', None), ())
            self.assertIsNone(generation.manager.get('parent'))
            self.assertIsNone(generation.manager.get('child'))
            self.assertEqual(await generation.close(), ())
            self.assertEqual(generation.addon.module.events,
                             ['parent load', 'child load', 'load rejected'])
        finally:
            await generation.close()

    async def test_manager_registration_reference_contract(self):
        class Context:
            def __init__(self):
                self.options = OptManager()
                self.addons = AddonManager(self.options, {'load', 'configure', 'running', 'done'})

            async def running(self):
                await self.addons._dispatch('running')

        def running_event(context):
            context.addons._dispatch_sync('running')

        corpus = json.loads((ROOT / 'tests/corpus/addon_registration_v12.json').read_text())
        actual = await collect_registration(Context, running_event)
        self.assertEqual(actual.keys(), corpus['cases'].keys())
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    async def test_manager_registration_failure_boundaries_match_reference(self):
        class Context:
            def __init__(self):
                self.options = OptManager()
                self.addons = AddonManager(
                    self.options,
                    {"load", "running", "done"},
                )

        def running_event(context):
            context.addons._dispatch_sync("running")

        corpus = json.loads(
            (ROOT / "tests/corpus/addon_registration_failure_v12.json").read_text()
        )
        actual = await collect_registration_failures(Context, running_event)
        self.assertEqual(corpus["reference"], "mitmproxy 12.3.1")
        self.assertEqual(actual, corpus["cases"])

    async def test_load_replacement_keeps_parent_child_and_sibling_order(self):
        generation = AddonGeneration('''events = []
class Leaf:
    def __init__(self, name):
        self.name = name
    def load(self, loader):
        events.append(self.name + ".load")
    def request(self, flow):
        events.append(self.name + ".request")
class Parent(Leaf):
    addons = [Leaf("discarded")]
    def load(self, loader):
        super().load(loader)
        self.addons = [Leaf("created")]
addons = [Parent("parent"), Leaf("sibling")]
''', {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(await generation.dispatch('request', None), ())
            self.assertEqual(generation.addon.module.events,
                             ['parent.load', 'created.load', 'sibling.load',
                              'parent.request', 'created.request', 'sibling.request'])
        finally:
            await generation.close()

    async def test_load_created_trees_retain_registration_guards(self):
        cases = (
            ('self.addons = [self]', AddonManagerError, 'Cyclic'),
            ('child = Child()\nself.addons = [child, child]', AddonManagerError, 'already registered'),
            ('self.addons = []\nfor index in range(256):\n    child = Child()\n    child.name = str(index)\n    self.addons.append(child)', AddonManagerError, 'exceeds 256'),
            ('self.addons = object()', AddonLoadError, 'list or tuple'),
        )
        for mutation, exception_type, error in cases:
            with self.subTest(mutation=mutation):
                source = ('class Child:\n    pass\n'
                          'class Parent:\n    def load(self, loader):\n' + textwrap.indent(mutation, '        ') +
                          '\naddons = [Parent()]\n')
                generation = AddonGeneration(source, {'request'})
                try:
                    with self.assertRaisesRegex(exception_type, error):
                        await generation.start()
                    self.assertEqual(generation.state, 'failed')
                    with self.assertRaises(AddonRuntimeError):
                        await generation.dispatch('request', None)
                    # Failed discovery never replaces the preflight registry.
                    self.assertEqual(len(generation.addon.registry.addons), 2)
                finally:
                    await generation.close()

    async def test_children_created_during_load_receive_the_lifecycle(self):
        # Reference registration discovers children after their parent's load
        # callback; recognizing only the initial addon list misses this case.
        generation = AddonGeneration('''events = []
class Child:
    def load(self, loader):
        events.append("child.load")
    def running(self):
        events.append("child.running")
    def done(self):
        events.append("child.done")
class Parent:
    def load(self, loader):
        events.append("parent.load")
        self.addons = [Child()]
    def running(self):
        events.append("parent.running")
    def done(self):
        events.append("parent.done")
addons = [Parent()]
''', set())
        try:
            self.assertEqual(await generation.start(), ())
        finally:
            await generation.close()
        self.assertEqual(generation.addon.module.events,
                         ['parent.load', 'child.load', 'parent.running',
                          'child.running', 'parent.done', 'child.done'])

    async def test_legacy_logging_uses_standard_python_records(self):
        generation = AddonGeneration('''
from mitmproxy import ctx

def request(flow):
    ctx.log.debug("debug")
    ctx.log.info("info")
    ctx.log.warn("warn")
    ctx.log.error("error")
    ctx.log.alert("alert")
    ctx.log({"value": 1}, "warning")
''', {"request"})
        await generation.start()
        with warnings.catch_warnings(record=True) as deprecated:
            warnings.simplefilter("always", DeprecationWarning)
            with self.assertLogs(level="DEBUG") as captured:
                failures = await generation.dispatch("request", None)
        self.assertEqual(failures, ())
        self.assertEqual([record.levelno for record in captured.records],
                         [10, 20, 30, 40, 21, 30])
        self.assertEqual(captured.records[-1].msg, {"value": 1})
        self.assertEqual(len(deprecated), 5)
        self.assertTrue(all(isinstance(item.message, DeprecationWarning)
                            for item in deprecated))
        await generation.close()

    async def test_cookie_attributes_public_import_in_response_hook(self):
        from addon_http_message import Response

        generation = AddonGeneration('''
from mitmproxy.net.http.cookies import CookieAttrs

def response(flow):
    attrs = CookieAttrs([("Path", "/"), ("HttpOnly", None)])
    flow.response.cookies["session"] = ("new", attrs)
    assert isinstance(flow.response.cookies["session"][1], CookieAttrs)
''', {"response"})
        self.assertEqual(await generation.start(), ())
        flow = generation.create_flow("one", 1, None, None)
        flow.response = Response.make()
        self.assertEqual(await generation.dispatch("response", flow), ())
        self.assertEqual(flow.response.headers.get_all("set-cookie"),
                         ["session=new; Path=/; HttpOnly"])
        await generation.close()
        for name in ("mitmproxy.net", "mitmproxy.net.http", "mitmproxy.net.http.cookies"):
            self.assertNotIn(name, sys.modules)

    async def test_unimplemented_network_module_does_not_fall_back_to_disk(self):
        generation = AddonGeneration("import mitmproxy.net.tcp", set())
        with self.assertRaises(ModuleNotFoundError):
            await generation.start()
        self.assertEqual(generation.state, "failed")
        self.assertNotIn("mitmproxy.net", sys.modules)
        await generation.close()

    async def test_multiple_connections_share_addon_but_not_flow_identity(self):
        generation = AddonGeneration('''
count = 0
def request(flow):
    global count
    count += 1
    flow.metadata["sequence"] = count
''', {"request"})
        await generation.start(None)
        first = generation.create_flow("connection-a", 1, None, None)
        second = generation.create_flow("connection-b", 1, None, None)
        third = generation.create_flow("connection-a", 3, None, None)
        self.assertIsInstance(first.client_conn, Client)
        self.assertIsInstance(first.server_conn, Server)
        self.assertIsNone(first.client_conn.peername)
        self.assertIsNone(first.client_conn.sockname)
        self.assertIsNone(first.server_conn.address)
        for index, flow in enumerate((first, second, third), 1):
            await generation.dispatch("request", flow)
            self.assertEqual(flow.metadata["sequence"], index)
        self.assertIs(generation.get_flow("connection-a", 1), first)
        self.assertIs(generation.get_flow("connection-b", 1), second)
        self.assertEqual(len({first.id, second.id, third.id}), 3)
        self.assertEqual(generation.active_flows, 3)
        self.assertEqual(generation.release_connection("connection-a"), (first, third))
        self.assertFalse(first.live)
        self.assertFalse(third.live)
        self.assertTrue(second.live)
        self.assertEqual(generation.active_flows, 1)
        await generation.close()
        self.assertFalse(second.live)
        self.assertEqual(generation.active_flows, 0)

    async def test_flow_limit_never_evicts_existing_state(self):
        generation = AddonGeneration("", set(), max_flows=1)
        await generation.start(None)
        first = generation.create_flow("a", 1, None, None)
        first.metadata["retained"] = True
        with self.assertRaisesRegex(AddonRuntimeError, "already"):
            generation.create_flow("a", 1, None, None)
        with self.assertRaisesRegex(AddonRuntimeError, "limit"):
            generation.create_flow("b", 1, None, None)
        self.assertIs(generation.get_flow("a", 1), first)
        self.assertTrue(first.metadata["retained"])
        self.assertIs(generation.release_flow("a", 1), first)
        self.assertIsNone(generation.release_flow("a", 1))
        replacement = generation.create_flow("b", 1, None, None)
        self.assertNotEqual(replacement.id, first.id)
        await generation.close()

    async def test_full_flow_capacity_is_reusable_without_losing_addon_state(self):
        generation = AddonGeneration('''
count = 0
flow_ids = []

def request(flow):
    global count
    count += 1
    flow.metadata["sequence"] = count
    flow_ids.append(flow.id)
''', {"request"}, max_flows=128)
        await generation.start(None)

        flows = {}
        for connection in range(8):
            connection_id = f"connection-{connection}"
            for stream in range(1, 32, 2):
                flow = generation.create_flow(
                    connection_id,
                    stream,
                    None,
                    None,
                )
                await generation.dispatch("request", flow)
                flows[(connection_id, stream)] = flow

        self.assertEqual(generation.active_flows, 128)
        self.assertEqual(generation.addon.module.count, 128)
        self.assertEqual(len(set(generation.addon.module.flow_ids)), 128)
        with self.assertRaisesRegex(AddonRuntimeError, "limit"):
            generation.create_flow("overflow", 1, None, None)

        released = generation.release_connection("connection-3")
        expected = tuple(
            flows[("connection-3", stream)]
            for stream in range(1, 32, 2)
        )
        self.assertEqual(released, expected)
        self.assertTrue(all(not flow.live for flow in released))
        self.assertEqual(generation.active_flows, 112)

        for stream in range(1, 32, 2):
            replacement = generation.create_flow(
                "replacement",
                stream,
                None,
                None,
            )
            await generation.dispatch("request", replacement)
            self.assertEqual(replacement.metadata["sequence"], 128 + (stream + 1) // 2)

        self.assertEqual(generation.active_flows, 128)
        self.assertEqual(generation.addon.module.count, 144)
        self.assertEqual(len(set(generation.addon.module.flow_ids)), 144)
        for key, flow in flows.items():
            if key[0] != "connection-3":
                self.assertIs(generation.get_flow(*key), flow)
                self.assertTrue(flow.live)

        await generation.close()
        self.assertEqual(generation.active_flows, 0)

    async def test_generation_close_wakes_intercepted_flows_even_when_done_fails(self):
        generation = AddonGeneration('def done(): raise ValueError("cleanup failed")', set())
        await generation.start(None)
        flow = generation.create_flow("a", 1, None, None)
        flow.intercept()
        waiter = asyncio.create_task(flow.wait_for_resume())
        await asyncio.sleep(0)
        self.assertFalse(waiter.done())
        self.assertEqual(len(await generation.close()), 1)
        await asyncio.wait_for(waiter, timeout=1)
        self.assertFalse(flow.live)
        self.assertEqual(generation.active_flows, 0)

    async def test_mass_retirement_wakes_every_intercepted_flow_after_done_failure(self):
        generation = AddonGeneration(
            'def done(): raise ValueError("cleanup failed")',
            set(),
            max_flows=128,
        )
        await generation.start(None)

        flows = []
        waiters = []
        for connection in range(8):
            for stream in range(1, 32, 2):
                flow = generation.create_flow(
                    f"connection-{connection}",
                    stream,
                    None,
                    None,
                )
                flow.intercept()
                flows.append(flow)
                waiters.append(asyncio.create_task(flow.wait_for_resume()))

        await asyncio.sleep(0)
        self.assertEqual(generation.active_flows, 128)
        self.assertTrue(all(not waiter.done() for waiter in waiters))

        failures = await generation.close()
        self.assertEqual(len(failures), 1)
        self.assertEqual(str(failures[0].exception), "cleanup failed")
        async with asyncio.timeout(1):
            await asyncio.gather(*waiters)

        self.assertEqual(generation.active_flows, 0)
        self.assertTrue(all(not flow.live for flow in flows))
        self.assertTrue(all(not flow.intercepted for flow in flows))
        self.assertEqual(await generation.close(), ())

    async def test_flow_keys_and_limits_are_validated_before_allocation(self):
        for limit in (0, 1025, True, 1.5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    AddonGeneration("", set(), max_flows=limit)
        generation = AddonGeneration("", set())
        await generation.start(None)
        for connection, exchange in (("", 1), (None, 1), ("a", 0), ("a", True)):
            with self.subTest(connection=connection, exchange=exchange):
                with self.assertRaises(ValueError):
                    generation.create_flow(connection, exchange, None, None)
        self.assertEqual(generation.active_flows, 0)
        await generation.close()

    async def test_construction_does_not_execute_administrator_code(self):
        generation = AddonGeneration('raise RuntimeError("module executed")', set())
        self.assertIsNone(generation.addon)
        await generation.close()
        self.assertEqual(generation.state, "closed")

    async def test_import_failure_cannot_be_retried_on_the_same_generation(self):
        generation = AddonGeneration('raise RuntimeError("module executed")', set())
        with self.assertRaisesRegex(RuntimeError, "module executed"):
            await generation.start(None)
        self.assertEqual(generation.state, "failed")
        self.assertNotIn("mitmproxy", sys.modules)
        with self.assertRaises(AddonRuntimeError):
            await generation.start(None)
        await generation.close()

    async def test_lifecycle_runs_once_and_globals_survive_events(self):
        generation = AddonGeneration('''
events = []
counter = 0

def load(loader):
    events.append(("load", loader))

def configure(updated):
    events.append(("configure", sorted(updated)))

def running():
    events.append(("running",))

def request(flow):
    global counter
    counter += 1
    events.append(("request", counter))

def done():
    events.append(("done",))
''', {"request"})
        with self.assertRaises(AddonRuntimeError):
            await generation.dispatch("request", None)
        self.assertEqual(await generation.start("loader", {"first"}), ())
        for _ in range(3):
            self.assertEqual(await generation.dispatch("request", None), ())
        self.assertEqual(await generation.configure({"second"}), ())
        self.assertEqual(await generation.close(), ())
        self.assertEqual(await generation.close(), ())
        self.assertEqual(generation.addon.module.events, [
            ("load", "loader"), ("configure", ["first"]), ("running",),
            ("request", 1), ("request", 2), ("request", 3),
            ("configure", ["second"]), ("done",),
        ])
        with self.assertRaises(AddonRuntimeError):
            await generation.start("loader")
        with self.assertRaises(AddonRuntimeError):
            await generation.dispatch("request", None)

    async def test_ordinary_hook_failure_is_reported_without_losing_state(self):
        generation = AddonGeneration('''
count = 0
def request(flow):
    global count
    count += 1
    if count == 1:
        raise ValueError("first call failed")
''', {"request"})
        await generation.start(None)
        failures = await generation.dispatch("request", None)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0].exception, ValueError)
        self.assertEqual(await generation.dispatch("request", None), ())
        self.assertEqual(generation.addon.module.count, 2)
        await generation.close()

    async def test_cancelled_dispatch_poisoned_until_generation_is_closed(self):
        generation = AddonGeneration('''
async def request(flow):
    await flow.wait()
''', {"request"})
        await generation.start(None)
        task = asyncio.create_task(generation.dispatch("request", asyncio.Event()))
        await asyncio.sleep(0)
        with self.assertRaisesRegex(AddonRuntimeError, "serialized"):
            await generation.dispatch("request", None)
        with self.assertRaisesRegex(AddonRuntimeError, "during dispatch"):
            await generation.close()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(generation.state, "failed")
        self.assertNotIn("mitmproxy", sys.modules)
        with self.assertRaises(AddonRuntimeError):
            await generation.dispatch("request", None)
        await generation.close()
        self.assertEqual(generation.state, "closed")

    async def test_done_failure_still_closes_exactly_once(self):
        generation = AddonGeneration('''
count = 0
def done():
    global count
    count += 1
    raise ValueError("cleanup failed")
''', set())
        await generation.start(None)
        self.assertEqual(len(await generation.close()), 1)
        self.assertEqual(await generation.close(), ())
        self.assertEqual(generation.addon.module.count, 1)

    async def test_lifecycle_events_cannot_be_injected_as_transport_events(self):
        generation = AddonGeneration("", set())
        await generation.start(None)
        for name in generation.LIFECYCLE_HOOKS:
            with self.subTest(hook=name):
                with self.assertRaises(AddonRuntimeError):
                    await generation.dispatch(name)
        await generation.close()

    async def test_optional_hook_observation_tracks_the_active_addon_tree(self):
        generation = AddonGeneration('', {'client_connected'})
        with self.assertRaisesRegex(AddonRuntimeError, 'not running'):
            generation.observes('client_connected')

        await generation.start(None)
        self.assertFalse(generation.observes('client_connected'))
        self.assertFalse(generation.observes('unsupported_event'))

        class Child:
            def client_connected(self, _client):
                pass

        class Parent:
            def __init__(self):
                self.addons = [Child()]

        parent = Parent()
        generation.manager.add(parent)
        self.assertTrue(generation.observes('client_connected'))

        generation.manager.remove(parent)
        self.assertFalse(generation.observes('client_connected'))
        await generation.close()
        with self.assertRaisesRegex(AddonRuntimeError, 'not running'):
            generation.observes('client_connected')

    async def test_post_registration_tree_mutations_keep_runtime_guards(self):
        class Addon:
            addons = ()

            def running(self):
                pass

        manager = AddonManager(OptManager(), {'load', 'running', 'done'})
        root = Addon()
        manager.add(root)

        root.addons = [root]
        with self.assertRaisesRegex(AddonManagerError, 'Repeated addon'):
            await manager._dispatch('running')

        root.addons = [Addon() for _ in range(256)]
        with self.assertRaisesRegex(AddonManagerError, 'exceeds 256 objects'):
            await manager._dispatch('running')

        root.addons = []
        manager.clear()

    async def test_generation_guards_before_start_and_after_close(self):
        generation = AddonGeneration(
            "",
            set(),
            modules=compatibility_modules(),
        )
        with self.assertRaisesRegex(AddonRuntimeError, "between callbacks"):
            generation.create_flow("connection", 1, None, None)
        with self.assertRaisesRegex(AddonRuntimeError, "not running"):
            await generation.configure(set())
        with self.assertRaisesRegex(AddonRuntimeError, "not running"):
            generation.content_view("list")

        generation.invalidate()
        self.assertEqual(generation.state, "failed")
        await generation.close()
        generation.invalidate()
        self.assertEqual(generation.state, "closed")

    async def test_busy_dispatch_blocks_flow_release_and_content_views(self):
        generation = AddonGeneration('''import asyncio
entered = asyncio.Event()
release = asyncio.Event()
async def request(flow):
    entered.set()
    await release.wait()
''', {"request"})
        await generation.start()
        flow = generation.create_flow("connection", 1, None, None)
        task = asyncio.create_task(generation.dispatch("request", flow))
        try:
            await asyncio.wait_for(generation.addon.module.entered.wait(), timeout=1)
            with self.assertRaisesRegex(AddonRuntimeError, "during dispatch"):
                generation.release_flow("connection", 1)
            with self.assertRaisesRegex(AddonRuntimeError, "during dispatch"):
                generation.release_connection("connection")
            with self.assertRaisesRegex(AddonRuntimeError, "serialized"):
                generation.content_view("list")
        finally:
            generation.addon.module.release.set()
            await task
            await generation.close()

    async def test_unknown_content_view_and_direct_option_rejection(self):
        generation = AddonGeneration('''from mitmproxy import exceptions
def configure(updated):
    if "reject" in updated:
        raise exceptions.OptionsError("rejected")
''', set())
        await generation.start(updated_options=set())
        try:
            with self.assertRaisesRegex(ValueError, "Unknown content view action"):
                generation.content_view("unknown")
            with self.assertRaisesRegex(OptionsError, "rejected"):
                await generation.configure({"reject"})
            self.assertEqual(generation.state, "running")
        finally:
            await generation.close()

    async def test_callback_option_changes_configure_inline_and_roll_back(self):
        generation = AddonGeneration('''from mitmproxy import ctx, exceptions
events = []
def load(loader):
    loader.add_option("probe", int, 1, "Runtime probe")
def configure(updated):
    if "probe" in updated:
        events.append(("configure", ctx.options.probe))
        if ctx.options.probe == 3:
            raise exceptions.OptionsError("probe rejected")
def request(flow):
    ctx.options.probe = 2
    events.append(("request", ctx.options.probe))
    try:
        ctx.options.probe = 3
    except exceptions.OptionsError:
        events.append(("rejected", ctx.options.probe))
''', {"request"})
        await generation.start()
        try:
            flow = generation.create_flow("connection", 1, None, None)
            self.assertEqual(await generation.dispatch("request", flow), ())
            self.assertEqual(generation.options.probe, 2)
            self.assertEqual(generation.addon.module.events, [
                ("configure", 1),
                ("configure", 2),
                ("request", 2),
                ("configure", 3),
                ("configure", 2),
                ("rejected", 2),
            ])
        finally:
            await generation.close()

    async def test_abort_from_nested_configure_invalidates_generation(self):
        generation = AddonGeneration('''from mitmproxy import ctx
events = []
def load(loader):
    loader.add_option("probe", int, 1, "Runtime probe")
def configure(updated):
    events.append(("configure", ctx.options.probe))
    if ctx.options.probe == 2:
        raise SystemExit("configuration aborted")
def request(flow):
    ctx.options.probe = 2
def done():
    events.append(("done", ctx.options.probe))
''', {"request"})
        await generation.start()
        flow = generation.create_flow("connection", 1, None, None)

        with self.assertRaisesRegex(SystemExit, "configuration aborted"):
            await generation.dispatch("request", flow)

        self.assertEqual(generation.state, "failed")
        with self.assertRaisesRegex(AddonRuntimeError, "not running"):
            await generation.dispatch("request", flow)
        self.assertEqual(await generation.close(), ())
        self.assertEqual(generation.addon.module.events, [
            ("configure", 1),
            ("configure", 2),
            ("done", 2),
        ])

    async def test_explicit_connections_and_connection_flow_lookup(self):
        generation = AddonGeneration("", set())
        await generation.start()
        try:
            client = Client(peername=("127.0.0.1", 1234), sockname=None)
            server = Server(address=("example.test", 443))
            flow = generation.create_flow("connection", 1, client, server)
            self.assertIs(flow.client_conn, client)
            self.assertIs(flow.server_conn, server)
            self.assertEqual(generation.connection_flows("connection"), (flow,))
            self.assertEqual(generation.connection_flows("other"), ())
        finally:
            await generation.close()


if __name__ == "__main__":
    unittest.main()
