"""Behavioral contracts for script selection and unchanged addon loading."""

import asyncio
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from addon_loader import (
    AddonLoadError,
    HOOK_ARGUMENTS,
    HookRegistry,
    LoadedAddon,
    UnsupportedAddonHook,
    compatibility_imports,
    compile_script,
    select_script_api,
)
from addon_h1_events import H1AddonEvents
from addon_h2_events import H2AddonEvents
from addon_runtime import AddonGeneration
from addon_modules import compatibility_modules
from addon_traverse_contract import collect as collect_traverse


def modules(label="test"):
    package = ModuleType("mitmproxy")
    package.__path__ = []
    context = ModuleType("mitmproxy.ctx")
    context.label = label
    package.ctx = context
    return {"mitmproxy": package, "mitmproxy.ctx": context}


class SelectionTests(unittest.TestCase):
    def test_shebang_overrides_explicit_choice(self):
        for source in ("#!mitmproxy", "#!mitmproxy\r\ndef request(flow): pass",
                       "\ufeff#!mitmproxy\ndef request(flow): pass"):
            for choice in ("spider", "mitmproxy"):
                with self.subTest(source=source, choice=choice):
                    result = select_script_api(source, choice)
                    self.assertEqual(result.api, "mitmproxy")
                    self.assertEqual(result.source, "shebang")

    def test_directive_has_priority_even_over_an_obsolete_ui_value(self):
        result = select_script_api("#!mitmproxy\n", "auto")
        self.assertEqual(result.api, "mitmproxy")

    def test_no_heuristics_from_imports_names_or_embedded_text(self):
        sources = (
            "from mitmproxy import http\n",
            "def request(flow): pass\n",
            "addons = []\n",
            "\n#!mitmproxy\n",
            " #!mitmproxy\n",
            "#!mitmproxy-extra\n",
            'description = "#!mitmproxy"\n',
            "#!/usr/bin/env python3\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(select_script_api(source).api, "spider")
                self.assertEqual(select_script_api(source, "mitmproxy").api, "mitmproxy")

    def test_invalid_choice_and_non_text_source_are_rejected(self):
        for choice in ("auto", "python", "", None, 7):
            with self.subTest(choice=choice), self.assertRaises(ValueError):
                select_script_api("pass", choice)
        with self.assertRaises(TypeError):
            select_script_api(b"#!mitmproxy")

    def test_limit_counts_utf8_bytes(self):
        select_script_api("#" + "x" * 65535)
        with self.assertRaises(ValueError):
            select_script_api("#" + "x" * 65536)
        with self.assertRaises(ValueError):
            select_script_api("#" + "\u00e9" * 32768)

    def test_native_return_and_module_syntax_are_distinct(self):
        selection, native = compile_script("return api.answer")
        namespace = {}
        exec(native, namespace)
        self.assertEqual(selection.api, "spider")
        self.assertEqual(namespace["__spider_script"](SimpleNamespace(answer=42)), 42)
        with self.assertRaises(SyntaxError):
            compile_script("return 42", "mitmproxy")

    def test_compile_does_not_execute_user_code(self):
        selection, compiled = compile_script("raise RuntimeError('must not execute')", "mitmproxy")
        self.assertEqual(selection.api, "mitmproxy")
        with self.assertRaisesRegex(RuntimeError, "must not execute"):
            exec(compiled, {})


class LoadingTests(unittest.IsolatedAsyncioTestCase):
    async def test_minimal_unmodified_script_without_imports(self):
        addon = LoadedAddon(
            'def request(flow):\n    flow.request.headers["X-Experiment"] = "saslik"',
            modules(), {"request"},
        )
        flow = SimpleNamespace(request=SimpleNamespace(headers={}))
        self.assertEqual(await addon.dispatch("request", flow), ())
        self.assertEqual(flow.request.headers, {"X-Experiment": "saslik"})

    async def test_object_state_and_module_globals_survive_calls(self):
        addon = LoadedAddon('''
total = 0

def request(flow):
    global total
    total += 1
    flow.observed.append(total)

class Counter:
    def __init__(self):
        self.count = 100

    def request(self, flow):
        self.count += 1
        flow.observed.append(self.count)

addons = [Counter()]
''', modules(), {"request"})
        flow = SimpleNamespace(observed=[])
        for _ in range(3):
            self.assertEqual(await addon.dispatch("request", flow), ())
        self.assertEqual(flow.observed, [1, 101, 2, 102, 3, 103])

    async def test_nested_addons_preserve_registration_order(self):
        def node(label, children=()):
            return SimpleNamespace(
                request=lambda flow: flow.append(label), addons=list(children)
            )
        registry = HookRegistry({"request"})
        registry.add(node("parent", [node("first", [node("leaf")]), node("last")]))
        observed = []
        await registry.dispatch("request", observed)
        self.assertEqual(observed, ["parent", "first", "leaf", "last"])

    async def test_async_hooks_finish_before_next_addon(self):
        observed = []

        async def first(flow):
            observed.append("started")
            await asyncio.sleep(0)
            flow.append("first")
            observed.append("finished")

        def second(flow):
            self.assertEqual(observed, ["started", "finished"])
            flow.append("second")

        registry = HookRegistry({"response"})
        registry.add(SimpleNamespace(response=first))
        registry.add(SimpleNamespace(response=second))
        flow = []
        self.assertEqual(await registry.dispatch("response", flow), ())
        self.assertEqual(flow, ["first", "second"])

    async def test_hook_error_is_reported_and_next_addon_runs(self):
        def failed(flow):
            raise ValueError("broken addon")

        registry = HookRegistry({"request"})
        registry.add(SimpleNamespace(name="broken", request=failed))
        registry.add(SimpleNamespace(request=lambda flow: flow.append("survived")))
        observed = []
        failures = await registry.dispatch("request", observed)
        self.assertEqual(observed, ["survived"])
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].addon, "broken")
        self.assertIsInstance(failures[0].exception, ValueError)

    async def test_cancellation_is_not_swallowed_as_an_addon_error(self):
        async def cancelled(flow):
            raise asyncio.CancelledError()

        registry = HookRegistry({"request"})
        registry.add(SimpleNamespace(request=cancelled))
        with self.assertRaises(asyncio.CancelledError):
            await registry.dispatch("request", None)

    async def test_registration_during_dispatch_applies_to_next_event(self):
        registry = HookRegistry({"request"})
        added = False

        def register(flow):
            nonlocal added
            flow.append("first")
            if not added:
                registry.add(SimpleNamespace(request=lambda value: value.append("new")))
                added = True

        registry.add(SimpleNamespace(request=register))
        observed = []
        await registry.dispatch("request", observed)
        self.assertEqual(observed, ["first"])
        await registry.dispatch("request", observed)
        self.assertEqual(observed, ["first", "first", "new"])

    async def test_runtime_imports_and_context_are_generation_local(self):
        source = '''
from mitmproxy import ctx

def request(flow):
    from mitmproxy.ctx import label
    flow.append((ctx.label, label))
'''
        first = LoadedAddon(source, modules("first"), {"request"})
        second = LoadedAddon(source, modules("second"), {"request"})
        observed = []
        for addon in (first, second, first):
            await addon.dispatch("request", observed)
        self.assertEqual(observed, [("first", "first"), ("second", "second"), ("first", "first")])

    async def test_dataclass_addon_can_resolve_its_own_module(self):
        addon = LoadedAddon('''
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Counter:
    count: int = 0

    def request(self, flow):
        self.count += 1
        flow.append(self.count)

addons = [Counter()]
''', modules(), {"request"})
        result = []
        await addon.dispatch("request", result)
        self.assertEqual(result, [1])


class RegistrationTests(unittest.TestCase):
    def test_reference_public_traverse_contract(self):
        corpus = json.loads(
            (ROOT / "tests/corpus/addon_traverse_v12.json").read_text()
        )
        module = compatibility_modules()["mitmproxy.addonmanager"]
        self.assertEqual(collect_traverse(module), corpus["observations"])

    def test_registry_rejects_unknown_adapter_hooks(self):
        with self.assertRaisesRegex(ValueError, "Unknown adapter hooks: invented"):
            HookRegistry({"request", "invented"})

    def test_children_must_be_a_concrete_sequence(self):
        for children in (None, {"child"}, iter(())):
            with self.subTest(children=children):
                registry = HookRegistry({"request"})
                owner = SimpleNamespace(addons=children)
                with self.assertRaisesRegex(AddonLoadError, "list or tuple"):
                    registry.add(owner)
                self.assertEqual(registry.addons, ())

    def test_registration_can_deliberately_exclude_child_tree(self):
        child = SimpleNamespace(request=lambda flow: flow.append("child"))
        parent = SimpleNamespace(
            request=lambda flow: flow.append("parent"),
            addons=[child],
        )
        registry = HookRegistry({"request"})
        registry.add(parent, include_children=False)

        self.assertEqual(registry.addons, (parent,))
        self.assertEqual(
            tuple(hook.owner for hook in registry.callbacks("request")),
            (parent,),
        )

    def test_dispatch_validates_hook_name_and_argument_count(self):
        registry = HookRegistry({"request"})
        with self.assertRaisesRegex(UnsupportedAddonHook, "cannot dispatch response"):
            registry.dispatch_sync("response", object())
        with self.assertRaisesRegex(TypeError, "request requires 1 arguments"):
            registry.dispatch_sync("request")

    def test_sync_dispatch_rejects_async_results_without_leaking_coroutines(self):
        async def declared_async(flow):
            flow.append("unreachable")

        def returned_coroutine(flow):
            return declared_async(flow)

        for callback in (declared_async, returned_coroutine):
            with self.subTest(callback=callback):
                registry = HookRegistry({"configure"})
                registry.add(SimpleNamespace(configure=callback))
                failures = registry.dispatch_sync("configure", set())
                self.assertEqual(len(failures), 1)
                self.assertIsInstance(failures[0].exception, AddonLoadError)
                self.assertIn("sync context", str(failures[0].exception))

    def test_sync_dispatch_propagates_only_the_selected_exception_type(self):
        class RejectedUpdate(Exception):
            pass

        registry = HookRegistry({"configure"})
        registry.add(SimpleNamespace(configure=lambda updated: 1 / 0))
        ordinary = registry.dispatch_sync(
            "configure", {"ordinary"}, propagate=(RejectedUpdate,)
        )
        self.assertEqual(len(ordinary), 1)
        self.assertIsInstance(ordinary[0].exception, ZeroDivisionError)

        def reject(updated):
            raise RejectedUpdate("rollback")

        registry = HookRegistry({"configure"})
        registry.add(SimpleNamespace(configure=reject))
        with self.assertRaisesRegex(RejectedUpdate, "rollback"):
            registry.dispatch_sync(
                "configure", {"rejected"}, propagate=(RejectedUpdate,)
            )

    def test_unsupported_hook_fails_before_partial_registration(self):
        registry = HookRegistry({"request"})
        child = SimpleNamespace(dns_request=lambda flow: None)
        parent = SimpleNamespace(request=lambda flow: None, addons=[child])
        with self.assertRaisesRegex(UnsupportedAddonHook, "dns_request"):
            registry.add(parent)
        self.assertEqual(registry.addons, ())
        self.assertEqual(registry.callbacks("request"), ())

    def test_every_public_hook_has_an_explicit_transport_capability(self):
        """Never let a recognized hook silently become a capability claim."""
        for protocol, transport_hooks in (
            ("http1", H1AddonEvents.HOOKS),
            ("http2", H2AddonEvents.HOOKS),
        ):
            supported = transport_hooks | AddonGeneration.LIFECYCLE_HOOKS
            self.assertEqual(
                supported,
                {
                    "load", "configure", "running", "update", "done",
                    "requestheaders", "request",
                    "responseheaders", "response", "error",
                },
                protocol,
            )

            for name in HOOK_ARGUMENTS:
                callback = lambda *arguments: None
                addon = SimpleNamespace(**{name: callback})
                registry = HookRegistry(supported)

                with self.subTest(protocol=protocol, hook=name):
                    if name in supported:
                        registry.add(addon)
                        self.assertEqual(len(registry.callbacks(name)), 1)
                    else:
                        with self.assertRaisesRegex(
                            UnsupportedAddonHook,
                            rf"hook {name} is not supported",
                        ):
                            registry.add(addon)
                        self.assertEqual(registry.addons, ())

    def test_cycles_duplicates_and_registration_limit(self):
        registry = HookRegistry({"request"})
        root = SimpleNamespace(addons=[])
        root.addons.append(root)
        with self.assertRaisesRegex(AddonLoadError, "Cyclic"):
            registry.add(root)
        root.addons.clear()
        registry.add(root)
        with self.assertRaisesRegex(AddonLoadError, "already registered"):
            registry.add(root)
        large = SimpleNamespace(addons=[SimpleNamespace() for _ in range(256)])
        with self.assertRaisesRegex(AddonLoadError, "exceeds"):
            registry.add(large)
        self.assertEqual(registry.addons, (root,))

    def test_invalid_hook_signatures_are_load_errors(self):
        for callback in (42, lambda: None, lambda first, second: None):
            with self.subTest(callback=callback), self.assertRaises(AddonLoadError):
                HookRegistry({"request"}).add(SimpleNamespace(request=callback))

    def test_explicit_import_surface_does_not_fall_back_to_installed_reference(self):
        leaked = ModuleType("mitmproxy.private_reference_module")
        original = sys.modules.get(leaked.__name__)
        sys.modules[leaked.__name__] = leaked
        try:
            with compatibility_imports(modules()):
                with self.assertRaises(ModuleNotFoundError):
                    __import__(leaked.__name__)
            self.assertIs(sys.modules[leaked.__name__], leaked)
        finally:
            if original is None:
                sys.modules.pop(leaked.__name__, None)
            else:
                sys.modules[leaked.__name__] = original

    def test_import_table_restored_after_failure(self):
        previous = {name: value for name, value in sys.modules.items()
                    if name == "mitmproxy" or name.startswith("mitmproxy.")}
        with self.assertRaisesRegex(RuntimeError, "load failed"):
            LoadedAddon('raise RuntimeError("load failed")', modules(), {"request"})
        current = {name: value for name, value in sys.modules.items()
                   if name == "mitmproxy" or name.startswith("mitmproxy.")}
        self.assertEqual(current, previous)

    def test_import_scope_rejects_unsafe_or_incomplete_module_tables(self):
        with self.assertRaisesRegex(ValueError, "under mitmproxy"):
            with compatibility_imports({"mitmproxy": ModuleType("mitmproxy"),
                                        "foreign": ModuleType("foreign")}):
                pass
        with self.assertRaisesRegex(ValueError, "include the package root"):
            with compatibility_imports({"mitmproxy.ctx": ModuleType("mitmproxy.ctx")}):
                pass


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_load_tree_discovers_children_created_by_load(self):
        observed = []

        class Parent:
            addons = []

            def load(self, loader):
                observed.append(("parent-load", loader))
                self.addons = [SimpleNamespace(
                    load=lambda child_loader: observed.append(
                        ("child-load", child_loader)
                    ),
                    request=lambda flow: flow.append("child"),
                )]

            def request(self, flow):
                flow.append("parent")

        registry = HookRegistry({"load", "request"})
        loader = object()
        self.assertEqual(await registry.load_tree(Parent(), loader), ())
        self.assertEqual(observed, [("parent-load", loader), ("child-load", loader)])

        requests = []
        self.assertEqual(await registry.dispatch("request", requests), ())
        self.assertEqual(requests, ["parent", "child"])

    async def test_load_tree_reports_callback_failure_and_keeps_discovering(self):
        observed = []

        def fail(loader):
            observed.append("failed")
            raise RuntimeError("load failed")

        child = SimpleNamespace(
            name="broken child",
            load=fail,
            request=lambda flow: flow.append("child"),
        )
        root = SimpleNamespace(
            load=lambda loader: observed.append("root"),
            request=lambda flow: flow.append("root"),
            addons=[child],
        )
        registry = HookRegistry({"load", "request"})
        failures = await registry.load_tree(root, object())

        self.assertEqual(observed, ["root", "failed"])
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].addon, "broken child")
        self.assertIsInstance(failures[0].exception, RuntimeError)

        requests = []
        await registry.dispatch("request", requests)
        self.assertEqual(requests, ["root", "child"])

    async def test_failed_discovery_does_not_publish_a_partial_tree(self):
        original = SimpleNamespace(request=lambda flow: flow.append("original"))
        registry = HookRegistry({"load", "request"})
        registry.add(original)

        root = SimpleNamespace(request=lambda flow: flow.append("replacement"), addons=[])
        root.addons.append(root)
        with self.assertRaisesRegex(AddonLoadError, "Cyclic"):
            await registry.load_tree(root, object())

        self.assertEqual(registry.addons, (original,))
        requests = []
        await registry.dispatch("request", requests)
        self.assertEqual(requests, ["original"])

    async def test_loaded_addon_without_manager_uses_discovered_tree(self):
        addon = LoadedAddon('''
events = []

class Child:
    def load(self, loader):
        events.append("child-load")

    def request(self, flow):
        flow.append("child")

def load(loader):
    global addons
    events.append("module-load")
    addons = [Child()]

def request(flow):
    flow.append("module")
''', modules(), {"load", "request"})

        self.assertEqual(await addon.dispatch("load", object()), ())
        self.assertEqual(addon.module.events, ["module-load", "child-load"])
        requests = []
        self.assertEqual(await addon.dispatch("request", requests), ())
        self.assertEqual(requests, ["module", "child"])

    async def test_manual_execution_is_single_shot(self):
        addon = LoadedAddon("value = 42", modules(), set(), execute=False)
        self.assertFalse(hasattr(addon.module, "value"))
        addon.execute()
        self.assertEqual(addon.module.value, 42)
        with self.assertRaisesRegex(AddonLoadError, "already started"):
            addon.execute()


if __name__ == "__main__":
    unittest.main()
