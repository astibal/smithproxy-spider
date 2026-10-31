"""Spider-owned loading and hook registration for mitmproxy addon scripts.

This module is a clean-room implementation of the documented addon conventions.
It does not import the reference implementation. The transport adapter supplies
the compatibility modules and the hooks it can actually deliver.

Loading executes administrator code and must happen inside the script sandbox.
Compilation and API selection do not execute the submitted source.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import inspect
import sys
from types import ModuleType


TARGET_API_MAJOR = 12
REFERENCE_RELEASE = "12.3.1"
REFERENCE_CHECKED = "2026-10-31"

# Names identify events, not a promise that every Spider transport can emit them.
# Availability is checked against the adapter's explicit capability set.
HOOK_ARGUMENTS = {
    "load": 1,
    "running": 0,
    "configure": 1,
    "done": 0,
    "client_connected": 1,
    "client_disconnected": 1,
    "server_connect": 1,
    "server_connected": 1,
    "server_disconnected": 1,
    "server_connect_error": 1,
    "requestheaders": 1,
    "request": 1,
    "responseheaders": 1,
    "response": 1,
    "error": 1,
    "http_connect": 1,
    "http_connect_upstream": 1,
    "http_connected": 1,
    "http_connect_error": 1,
    "tcp_start": 1,
    "tcp_message": 1,
    "tcp_end": 1,
    "tcp_error": 1,
    "udp_start": 1,
    "udp_message": 1,
    "udp_end": 1,
    "udp_error": 1,
    "dns_request": 1,
    "dns_response": 1,
    "dns_error": 1,
    "websocket_start": 1,
    "websocket_message": 1,
    "websocket_end": 1,
    "tls_clienthello": 1,
    "tls_start_client": 1,
    "tls_start_server": 1,
    "tls_established_client": 1,
    "tls_established_server": 1,
    "tls_failed_client": 1,
    "tls_failed_server": 1,
    "quic_start_client": 1,
    "quic_start_server": 1,
    "next_layer": 1,
    "update": 1,
    "add_log": 1,
}


class AddonLoadError(ValueError):
    """Source or registration cannot run under the selected adapter contract."""


class UnsupportedAddonHook(AddonLoadError):
    """A valid addon requires an event the adapter cannot deliver."""


@dataclass(frozen=True)
class ScriptSelection:
    api: str
    source: str


def select_script_api(source, selected="spider"):
    """Resolve an exact first-line directive before consulting the UI selection.

    A UTF-8 BOM and CRLF are accepted. Imports and function names deliberately
    have no effect. Unknown Python shebangs are ordinary comments.
    """
    if not isinstance(source, str):
        raise TypeError("Script source must be text")
    if len(source.encode("utf-8")) > 65536:
        raise ValueError("Script source exceeds 64 KiB")

    first_line = source.removeprefix("\ufeff").split("\n", 1)[0].rstrip("\r")
    if first_line == "#!mitmproxy":
        return ScriptSelection("mitmproxy", "shebang")

    if selected not in ("spider", "mitmproxy"):
        raise ValueError("Script API must be spider or mitmproxy")
    return ScriptSelection(selected, "selection")


def compile_script(source, selected="spider"):
    """Compile the selected entry-point convention without importing the addon."""
    import textwrap

    selection = select_script_api(source, selected)
    normalized = source.removeprefix("\ufeff")
    if selection.api == "spider":
        normalized = "def __spider_script(api):\n" + textwrap.indent(
            normalized or "pass", "    "
        )
    return selection, compile(normalized, "<inspection>", "exec")


@dataclass(frozen=True)
class Hook:
    owner: object
    name: str
    callback: object


@dataclass(frozen=True)
class HookFailure:
    hook: str
    addon: str
    exception: Exception


class HookRegistry:
    """Ordered, bounded registration shared by module and object addons.

    A dispatch snapshots its callbacks. Changes made during a hook apply to the
    next event, rather than skipping or double-invoking callbacks in this event.
    Async hooks are awaited in registration order.
    """

    MAX_ADDONS = 256

    def __init__(self, supported_hooks):
        unknown = set(supported_hooks) - HOOK_ARGUMENTS.keys()
        if unknown:
            raise ValueError("Unknown adapter hooks: " + ", ".join(sorted(unknown)))
        self.supported_hooks = frozenset(supported_hooks)
        self._owners = []
        self._hooks = {}

    @property
    def addons(self):
        return tuple(self._owners)

    def callbacks(self, name):
        return tuple(self._hooks.get(name, ()))

    def _owner_hooks(self, owner):
        hooks = []
        for name, count in HOOK_ARGUMENTS.items():
            callback = getattr(owner, name, None)
            if callback is None:
                continue
            if not callable(callback):
                raise AddonLoadError(f"Hook {name} must be callable")
            if name not in self.supported_hooks:
                raise UnsupportedAddonHook(
                    f"mitmproxy {TARGET_API_MAJOR} hook {name} is not supported "
                    "by this Spider adapter"
                )
            try:
                inspect.signature(callback).bind(*([None] * count))
            except (TypeError, ValueError) as error:
                raise AddonLoadError(f"Invalid signature for {name}: {error}") from error
            hooks.append(Hook(owner, name, callback))
        return hooks

    @staticmethod
    def _children(owner):
        children = getattr(owner, 'addons', ())
        if not isinstance(children, (list, tuple)):
            raise AddonLoadError('addons must be a list or tuple of instances')
        return tuple(children)

    def add(self, addon, *, include_children=True):
        """Validate the entire addon tree before publishing any registration."""
        pending = []
        hooks = []
        seen = {id(owner) for owner in self._owners}

        def collect(owner, ancestors):
            identity = id(owner)
            if identity in ancestors:
                raise AddonLoadError("Cyclic addons registration")
            if identity in seen:
                raise AddonLoadError("Addon instance is already registered")
            if len(seen) >= self.MAX_ADDONS:
                raise AddonLoadError("Addon registration exceeds 256 objects")

            seen.add(identity)
            pending.append(owner)
            hooks.extend(self._owner_hooks(owner))
            path = ancestors | {identity}
            if include_children:
                for child in self._children(owner):
                    collect(child, path)

        collect(addon, set())
        self._owners.extend(pending)
        for hook in hooks:
            self._hooks.setdefault(hook.name, []).append(hook)

    async def load_tree(self, root, loader):
        """Discover children after load, then publish the completed hook table.

        A load callback can construct or replace its children. Validating the
        initial tree remains useful, but it cannot determine the final event
        recipients. Failed discovery never installs a partially rebuilt table.
        """
        self._validate_dispatch('load', (loader,))
        pending = []
        hooks = []
        seen = set()
        failures = []

        async def visit(owner, ancestors):
            identity = id(owner)
            if identity in ancestors:
                raise AddonLoadError('Cyclic addons registration')
            if identity in seen:
                raise AddonLoadError('Addon instance is already registered')
            if len(seen) >= self.MAX_ADDONS:
                raise AddonLoadError('Addon registration exceeds 256 objects')
            seen.add(identity)
            pending.append(owner)
            owner_hooks = self._owner_hooks(owner)
            load_hooks = tuple(hook for hook in owner_hooks if hook.name == 'load')
            failures.extend(await self._dispatch_hooks('load', (loader,), load_hooks))
            # Revalidate callbacks too: load may have installed handlers.
            hooks.extend(self._owner_hooks(owner))
            for child in self._children(owner):
                await visit(child, ancestors | {identity})

        await visit(root, set())
        rebuilt = {}
        for hook in hooks:
            rebuilt.setdefault(hook.name, []).append(hook)
        self._owners = pending
        self._hooks = rebuilt
        return tuple(failures)

    def _validate_dispatch(self, name, arguments):
        if name not in self.supported_hooks:
            raise UnsupportedAddonHook(f"Adapter cannot dispatch {name}")
        if len(arguments) != HOOK_ARGUMENTS[name]:
            raise TypeError(f"Hook {name} requires {HOOK_ARGUMENTS[name]} arguments")

    def dispatch_sync(self, name, *arguments, propagate=()):
        """Deliver immediate events without scheduling delayed side effects.

        Option notification must finish before the assignment returns, including
        rejection and rollback. An asynchronous handler cannot meet that contract.
        """
        self._validate_dispatch(name, arguments)
        failures = []
        for hook in self.callbacks(name):
            try:
                if inspect.iscoroutinefunction(hook.callback):
                    raise AddonLoadError(f"Async handler {name} cannot be called from sync context")
                result = hook.callback(*arguments)
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):
                        result.close()
                    raise AddonLoadError(f"Async handler {name} cannot be called from sync context")
            except propagate:
                raise
            except Exception as error:
                label = getattr(hook.owner, "name", type(hook.owner).__name__)
                failures.append(HookFailure(name, str(label), error))
        return tuple(failures)

    async def dispatch(self, name, *arguments, propagate=()):
        self._validate_dispatch(name, arguments)
        return await self._dispatch_hooks(name, arguments, self.callbacks(name), propagate=propagate)

    @staticmethod
    async def _dispatch_hooks(name, arguments, hooks, *, propagate=()):
        failures = []
        for hook in hooks:
            try:
                result = hook.callback(*arguments)
                if inspect.isawaitable(result):
                    await result
            except propagate:
                raise
            except Exception as error:
                # Addon exceptions belong in the invocation log. They do not
                # prevent unrelated registered addons from seeing the event.
                owner = hook.owner
                label = getattr(owner, "name", type(owner).__name__)
                failures.append(HookFailure(name, str(label), error))
        return tuple(failures)


@contextmanager
def compatibility_imports(modules):
    """Expose only Spider's supplied modules while loading or calling an addon.

    A worker serializes execution. This is not a thread-safe global import API.
    Restore the previous module table even when administrator code raises.
    """
    if any(name != "mitmproxy" and not name.startswith("mitmproxy.") for name in modules):
        raise ValueError("Compatibility module names must be under mitmproxy")
    if "mitmproxy" not in modules:
        raise ValueError("Compatibility modules must include the package root")

    previous = {
        name: module for name, module in sys.modules.items()
        if name == "mitmproxy" or name.startswith("mitmproxy.")
    }
    for name in previous:
        del sys.modules[name]
    sys.modules.update(modules)
    try:
        yield
    finally:
        current = [
            name for name in sys.modules
            if name == "mitmproxy" or name.startswith("mitmproxy.")
        ]
        for name in current:
            del sys.modules[name]
        sys.modules.update(previous)


class LoadedAddon:
    """A loaded addon generation; its Python state survives successive hooks."""

    def __init__(self, source, modules, supported_hooks, *, manager=None, execute=True):
        selection, compiled = compile_script(source, "mitmproxy")
        self.selection = selection
        self.modules = dict(modules)
        self.module = ModuleType("__spider_addon__")
        self.module.__file__ = "<inspection>"
        self.registry = HookRegistry(supported_hooks)
        self.manager = manager
        self._compiled = compiled
        self._execution_started = False
        if execute:
            self.execute()

    def execute(self):
        """Run the module once, keeping its scope available after a failure.

        The generation can retain this object before execution begins, allowing
        registered addons to receive cleanup even if later module code raises.
        """
        if self._execution_started:
            raise AddonLoadError('Addon module execution has already started')
        self._execution_started = True
        with self._scope():
            exec(self._compiled, self.module.__dict__)
            self.registry.add(self.module)

    @contextmanager
    def _scope(self):
        # Dataclasses and deferred annotations resolve types through the owning
        # module. Keep it discoverable for this generation only while executing.
        name = self.module.__name__
        previous = sys.modules.get(name)
        with compatibility_imports(self.modules):
            sys.modules[name] = self.module
            try:
                yield
            finally:
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

    async def dispatch(self, hook, *arguments):
        with self._scope():
            if self.manager is not None:
                self.registry._validate_dispatch(hook, arguments)
                if hook == 'load':
                    self.manager.register(self.module, loader=arguments[0])
                    self.manager.chain.append(self.module)
                    return self.manager._take_failures()
                if hook == 'done':
                    return await self.manager._shutdown()
                failures = await self.manager._dispatch(hook, *arguments)
                return failures + self.manager._take_failures()
            if hook == 'load':
                self.registry._validate_dispatch(hook, arguments)
                return await self.registry.load_tree(self.module, arguments[0])
            return await self.registry.dispatch(hook, *arguments)

    def dispatch_sync(self, hook, *arguments, propagate=()):
        with self._scope():
            if self.manager is not None:
                failures = self.manager._dispatch_sync(
                    hook,
                    *arguments,
                    propagate=propagate,
                )
                return failures + self.manager._take_failures()
            return self.registry.dispatch_sync(hook, *arguments, propagate=propagate)
