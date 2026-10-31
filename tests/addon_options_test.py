"""Reference option contract and real addon load/configure integration."""

import json
import gc
from pathlib import Path
import sys
import unittest
import weakref

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from addon_options import Loader, OptManager, Options, OptionsError
from addon_options_contract import collect, collect_notifications
from addon_option_helpers_contract import collect as collect_helpers
from addon_option_strings_contract import collect as collect_strings
from addon_deferred_options_contract import collect as collect_deferred
from addon_update_defer_contract import collect as collect_update_defer
from addon_option_parser_contract import collect as collect_option_parser
from addon_runtime import AddonGeneration


class OptionsTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_argument_parser_matches_reference(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_option_parser_v12.json').read_text()
        )
        self.assertEqual(
            collect_option_parser(OptManager),
            corpus['observations'],
        )

    async def test_typed_deferred_updates_match_reference(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_update_defer_v12.json').read_text()
        )
        self.assertEqual(
            collect_update_defer(OptManager),
            corpus['observations'],
        )

    async def test_typed_deferred_update_precedes_initial_configure(self):
        source = '''from mitmproxy import ctx
ctx.options.update_defer(late_count=7)
events = []
def load(loader):
    loader.add_option("late_count", int, 1, "Late count")
def configure(updated):
    events.append([ctx.options.late_count, "late_count" in updated])
def request(flow):
    assert ctx.options.late_count == 7
'''
        generation = AddonGeneration(source, {'request'})
        try:
            self.assertEqual(await generation.start(), ())
            self.assertEqual(await generation.dispatch('request', None), ())
            self.assertEqual(generation.addon.module.events, [[7, True]])
            self.assertEqual(generation.options.deferred, {})
        finally:
            await generation.close()

    async def test_builtin_inventory_matches_reference(self):
        corpus = json.loads(
            (ROOT / 'tests/corpus/addon_builtin_options_v12.json').read_text()
        )
        options = Options()
        inventory = {}
        for name, option in sorted(options.items()):
            inventory[name] = {
                'typespec': str(option.typespec),
                'default': options.default(name),
                'value': getattr(options, name),
                'choices': option.choices,
                'changed': options.has_changed(name),
            }
        self.assertEqual(inventory, corpus['inventory'])
        self.assertEqual(sorted(OptManager().keys()),
                         corpus['empty_optmanager_keys'])

        configured = Options(listen_port=9000, http2=False, mode=['socks5'])
        self.assertEqual({
            'listen_port': configured.listen_port,
            'http2': configured.http2,
            'mode': configured.mode,
            'changed': {
                name: configured.has_changed(name)
                for name in ('listen_port', 'http2', 'mode', 'server')
            },
        }, corpus['configured'])

    async def test_startup_registration_processes_deferred_values_before_configure(self):
        source = '''from mitmproxy import ctx
events = []
def load(loader):
    loader.add_option("late_count", int, 1, "Late count")
def configure(updated):
    events.append(["configure", ctx.options.late_count])
def running():
    events.append(["before", ctx.options.late_count])
    ctx.options.process_deferred()
    events.append(["after", ctx.options.late_count])
def request(flow):
    assert ctx.options.late_count == 3
    ctx.options.process_deferred()
'''
        addon = AddonGeneration(source, {'request'})
        addon.options.set('late_count=3', defer=True)
        try:
            self.assertEqual(await addon.start(), ())
            self.assertEqual(await addon.dispatch('request', None), ())
            self.assertEqual(addon.addon.module.events,
                             [['configure', 3], ['before', 3], ['after', 3]])
        finally:
            await addon.close()

    async def test_reference_deferred_configuration_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_deferred_options_v12.json').read_text())
        actual = collect_deferred(OptManager, OptionsError)
        self.assertEqual(actual.keys(), corpus['cases'].keys())
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    async def test_reference_string_configuration_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_option_strings_v12.json').read_text())
        actual = collect_strings(OptManager)
        self.assertEqual(actual.keys(), corpus['cases'].keys())
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name, specs=expected['specs']):
                self.assertEqual(actual[name], expected)

    async def test_helpers_dispatch_configure_and_restore_rejected_values(self):
        source = '''from mitmproxy import ctx, exceptions
events = []
def load(loader):
    loader.add_option("flag", bool, False, "Flag")
    loader.add_option("count", int, 1, "Count")
def configure(updated):
    events.append([ctx.options.flag, ctx.options.count])
    if ctx.options.flag or ctx.options.count == 4:
        raise exceptions.OptionsError("Rejected option change")
def request(flow):
    operations = [ctx.options.toggler("flag"),
                  lambda: ctx.options.setter("count")(4),
                  lambda: ctx.options.merge({"count": 4}),
                  lambda: ctx.options.set("count=4", "flag=false")]
    for operation in operations:
        try:
            operation()
        except exceptions.OptionsError:
            assert ctx.options.flag is False
            assert ctx.options.count == 1
        else:
            raise AssertionError("Option rejection did not propagate")
'''
        addon = AddonGeneration(source, {'request'})
        try:
            self.assertEqual(await addon.start(), ())
            self.assertEqual(await addon.dispatch('request', None), ())
            self.assertEqual(addon.addon.module.events,
                             [[False, 1], [True, 1], [False, 1],
                              [False, 4], [False, 1], [False, 4], [False, 1],
                              [False, 4], [False, 1]])
        finally:
            await addon.close()

    async def test_reference_helper_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_option_helpers_v12.json').read_text())
        actual = collect_helpers(OptManager)
        self.assertEqual(actual.keys(), corpus['cases'].keys())
        for name, expected in corpus['cases'].items():
            with self.subTest(case=name):
                self.assertEqual(actual[name], expected)

    async def test_reference_notification_contract(self):
        path = ROOT / 'tests/corpus/addon_option_notifications_v12.json'
        corpus = json.loads(path.read_text())
        self.assertEqual(collect_notifications(OptManager, OptionsError), corpus['cases'])

    async def test_bound_subscribers_do_not_keep_addon_instances_alive(self):
        options = OptManager()
        options.add_option('count', int, 1, 'Counter')
        events = []

        class Observer:
            def changed(self, updated):
                events.append(sorted(updated))

            def subscribed(self, manager, updated):
                events.append(manager.count)

        observer = Observer()
        reference = weakref.ref(observer)
        options.changed.connect(observer.changed)
        options.subscribe(observer.subscribed, ['count'])
        options.count = 2
        self.assertEqual(events, [2, ['count']])
        del observer
        gc.collect()
        self.assertIsNone(reference())
        options.count = 3
        self.assertEqual(events, [2, ['count']])

    async def test_rejection_restores_changes_made_by_observers(self):
        options = OptManager()
        options.add_option('count', int, 1, 'Counter')
        options.add_option('label', str, 'original', 'Label')

        def reject(updated):
            if updated == {'count'} and options.count == 4:
                options.label = 'changed inside observer'
                raise OptionsError('Rejected count')

        options.changed.connect(reject)
        with self.assertRaisesRegex(OptionsError, 'Rejected count'):
            options.count = 4
        self.assertEqual(options.count, 1)
        self.assertEqual(options.label, 'original')

    async def test_reference_contract(self):
        corpus = json.loads((ROOT / 'tests/corpus/addon_options_v12.json').read_text())
        self.assertEqual(collect(OptManager), corpus['cases'])

    async def test_load_registers_options_before_initial_configure(self):
        source = '''from mitmproxy import ctx
events = []
def load(loader):
    loader.add_option("label", str, "default", "Label for requests")
def configure(updated):
    events.append((sorted(updated), ctx.options.label))
def request(flow):
    events.append(ctx.options.label)
'''
        first = AddonGeneration(source, {'request'})
        second = AddonGeneration(source, {'request'})
        self.assertEqual(await first.start(), ())
        self.assertEqual(await second.start(), ())
        first.options.label = 'changed'
        await first.dispatch('request', None)
        await second.dispatch('request', None)
        initial = sorted(first.options.keys())
        self.assertEqual(first.addon.module.events,
                         [(initial, 'default'), (['label'], 'changed'), 'changed'])
        self.assertEqual(second.addon.module.events, [(initial, 'default'), 'default'])
        await first.close()
        await second.close()

    async def test_assignment_configures_immediately_and_rejection_is_catchable(self):
        source = '''from mitmproxy import ctx, exceptions
events = []
def load(loader):
    loader.add_option("count", int, 1, "Counter")
def configure(updated):
    events.append(["configure", ctx.options.count])
    if ctx.options.count == 4:
        raise exceptions.OptionsError("Rejected four")
def request(flow):
    events.append(["before", ctx.options.count])
    ctx.options.count = 3
    events.append(["after", ctx.options.count])
    try:
        ctx.options.count = 4
    except exceptions.OptionsError:
        events.append(["caught", ctx.options.count])
'''
        generation = AddonGeneration(source, {'request'})
        await generation.start()
        generation.addon.module.events.clear()
        self.assertEqual(await generation.dispatch('request', None), ())
        self.assertEqual(generation.addon.module.events, [
            ['before', 1], ['configure', 3], ['after', 3],
            ['configure', 4], ['configure', 3], ['caught', 3],
        ])
        self.assertEqual(generation.state, 'running')
        with self.assertRaises(OptionsError):
            generation.options.count = 4
        self.assertEqual(generation.options.count, 3)
        self.assertEqual(generation.state, 'running')
        await generation.close()
        before = list(generation.addon.module.events)
        generation.options.count = 2
        self.assertEqual(generation.addon.module.events, before)

    async def test_configure_errors_do_not_skip_other_addons(self):
        source = '''from mitmproxy import ctx
events = []
def load(loader):
    loader.add_option("count", int, 1, "Counter")
def configure(updated):
    if ctx.options.count == 2:
        raise ValueError("ordinary error")
class Observer:
    def configure(self, updated):
        events.append(ctx.options.count)
addons = [Observer()]
def request(flow):
    ctx.options.count = 2
'''
        generation = AddonGeneration(source, {'request'})
        await generation.start()
        failures = await generation.dispatch('request', None)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].hook, 'configure')
        self.assertIsInstance(failures[0].exception, ValueError)
        self.assertEqual(generation.addon.module.events, [1, 2])
        self.assertEqual(generation.options.count, 2)
        self.assertEqual(generation.take_option_failures(), ())
        await generation.close()

    async def test_async_configure_is_not_deferred_or_executed(self):
        source = '''events = []
def load(loader):
    loader.add_option("count", int, 1, "Counter")
async def configure(updated):
    events.append("must not execute")
'''
        generation = AddonGeneration(source, set())
        failures = await generation.start()
        self.assertEqual(len(failures), 1)
        generation.options.count = 2
        self.assertEqual(len(generation.take_option_failures()), 1)
        self.assertEqual(generation.addon.module.events, [])
        await generation.close()

    async def test_initial_rejection_prevents_running_hook(self):
        source = '''from mitmproxy import exceptions
events = []
def configure(updated):
    raise exceptions.OptionsError("Invalid initial configuration")
def running():
    events.append("must not run")
'''
        generation = AddonGeneration(source, set())
        with self.assertRaisesRegex(OptionsError, 'Invalid initial configuration'):
            await generation.start()
        self.assertEqual(generation.state, 'failed')
        self.assertEqual(generation.addon.module.events, [])
        await generation.close()

    async def test_configure_can_update_a_related_option_synchronously(self):
        source = '''from mitmproxy import ctx
events = []
def load(loader):
    loader.add_option("count", int, 1, "Counter")
    loader.add_option("label", str, "initial", "Derived label")
def configure(updated):
    events.append(["enter", sorted(updated)])
    if updated == {"count"}:
        ctx.options.label = str(ctx.options.count)
        events.append(["derived", ctx.options.label])
    events.append(["leave", sorted(updated)])
'''
        generation = AddonGeneration(source, set())
        await generation.start()
        generation.addon.module.events.clear()
        generation.options.count = 2
        self.assertEqual(generation.addon.module.events, [
            ['enter', ['count']], ['enter', ['label']],
            ['leave', ['label']], ['derived', '2'], ['leave', ['count']],
        ])
        self.assertFalse(generation._busy)
        self.assertEqual(generation.state, 'running')
        await generation.close()

    async def test_identical_registration_preserves_current_value(self):
        options = OptManager()
        loader = Loader(options)
        loader.add_option('count', int, 1, 'Counter')
        options.count = 5
        loader.add_option('count', int, 1, 'Counter')
        self.assertEqual(options.count, 5)
        with self.assertLogs(level='WARNING'):
            loader.add_option('count', int, 2, 'Counter')
        self.assertEqual(options.count, 2)


if __name__ == '__main__':
    unittest.main()
