"""Registration and active addon roots, independent of any proxy master.

The generation owns import scope and transport capabilities. This manager uses
the same hook validation and dispatch machinery as static script loading.
"""

import inspect

from addon_exceptions import MitmproxyException
from addon_loader import AddonLoadError, HookRegistry, UnsupportedAddonHook
from addon_options import Loader, OptionsError


class AddonManagerError(MitmproxyException):
    """A registration operation cannot be applied to the current addon tree."""


def traverse(chain):
    """Lazily traverse an addon chain in parent-before-children order."""
    for addon in chain:
        yield addon
        yield from traverse(getattr(addon, "addons", ()))


class AddonManager:
    def __init__(self, options, supported_hooks):
        self.options = options
        self.supported_hooks = frozenset(supported_hooks)
        self.chain = []
        self.commands = None
        self._lookup = {}
        self._failures = []

    @staticmethod
    def _name(addon):
        return getattr(addon, 'name', type(addon).__name__.lower())

    def get(self, name):
        return self._lookup.get(name)

    def __len__(self):
        return len(self.chain)

    def __str__(self):
        return str([str(addon) for addon in self.chain])

    def __contains__(self, addon):
        if isinstance(addon, str):
            return False
        return any(candidate is addon for candidate in self._event_owners())

    def _snapshot(self, roots, *, include_children=True):
        registry = HookRegistry(self.supported_hooks)
        for root in roots:
            registry.add(root, include_children=include_children)
        return registry

    def _take_failures(self):
        failures = tuple(self._failures)
        self._failures.clear()
        return failures

    def register(self, addon, *, loader=None):
        pending = {}
        owners = []
        identities = {id(owner) for owner in self._lookup.values()}
        if loader is None:
            loader = Loader(self.options, self.commands)

        def visit(owner, ancestors):
            name = self._name(owner)
            identity = id(owner)
            if identity in ancestors:
                raise AddonManagerError('Cyclic addon registration')
            if name in self._lookup or identity in identities:
                raise AddonManagerError('Addon is already registered: ' + str(name))
            if len(identities) >= HookRegistry.MAX_ADDONS:
                raise AddonManagerError('Addon registration exceeds 256 objects')
            identities.add(identity)
            pending[name] = owner
            owners.append(owner)
            registry = self._snapshot((owner,), include_children=False)
            # Registration is a direct call: load failures belong to its caller,
            # unlike ordinary broadcast failures collected for worker reporting.
            registry.dispatch_sync('load', loader, propagate=(Exception,))
            # Lookup publication follows the whole load traversal, so a child
            # does not observe its parent as registered during its load hook.
            for child in HookRegistry._children(owner):
                visit(child, ancestors | {identity})

        visit(addon, set())
        # Distinct children may share a name within this registration. Both
        # receive events, while lookup resolves to the last visited object.
        self._lookup.update(pending)
        if self.commands is not None:
            for owner in owners:
                self.commands.collect_commands(owner)
        self.options.process_deferred()
        return addon

    def add(self, *addons):
        for addon in addons:
            self.register(addon)
            self.chain.append(addon)

    def remove(self, addon):
        # Removing a child does not rewrite the parent's public addons list.
        # Lookup membership and event-tree membership are distinct contracts.
        self.chain = [root for root in self.chain if root is not addon]
        registry = self._snapshot((addon,))
        for owner in registry.addons:
            name = self._name(owner)
            if name not in self._lookup:
                raise AddonManagerError('No such addon: ' + str(name))
            del self._lookup[name]
        self._failures.extend(registry.dispatch_sync('done'))

    def clear(self):
        # Unlike remove(), bulk shutdown delivers done while names are still
        # visible, then clears both the event chain and registration lookup.
        self._failures.extend(self._dispatch_sync('done'))
        self.chain = []
        self._lookup.clear()

    def _dispatch_sync(self, name, *arguments, propagate=()):
        failures = []
        try:
            for owner in self._event_owners():
                registry = self._snapshot((owner,), include_children=False)
                failures.extend(registry.dispatch_sync(name, *arguments, propagate=propagate))
        except BaseException:
            # A later deliberate rejection or cancellation must not erase
            # diagnostics already collected from earlier event recipients.
            self._failures.extend(failures)
            raise
        return tuple(failures)

    def trigger(self, event):
        failures = self._dispatch_sync(event.name, *event.args(), propagate=(OptionsError,))
        self._failures.extend(failures)

    async def trigger_event(self, event):
        failures = await self._dispatch(event.name, *event.args(), propagate=(OptionsError,))
        self._failures.extend(failures)

    async def handle_lifecycle(self, event):
        """Dispatch one message lifecycle event through the active addon tree.

        The reference helper requires an event carrying at least one argument.
        Reading the first argument here preserves that public boundary instead
        of silently accepting empty lifecycle hooks through the wrong API.
        Ordinary callback failures remain collected by ``trigger_event``;
        option rejections keep their existing synchronous-abort semantics.
        """
        event.args()[0]
        await self.trigger_event(event)

    def _target_callback(self, owner, name):
        if name not in self.supported_hooks:
            raise UnsupportedAddonHook('Adapter cannot dispatch ' + str(name))
        callback = getattr(owner, name, None)
        if callback is not None and not callable(callback):
            raise AddonManagerError('Hook is not callable: ' + str(name))
        return callback

    def _observes(self, name):
        """Return whether the current addon tree observes an optional event."""
        for owner in self._event_owners():
            if self._target_callback(owner, name) is not None:
                return True
        return False

    def invoke_addon_sync(self, addon, event):
        # Targeted invocation propagates callback exceptions. It is not a
        # broadcast with errors collected for later worker reporting.
        arguments = event.args()
        for owner in self._event_owners((addon,)):
            callback = self._target_callback(owner, event.name)
            if callback is None:
                continue
            if inspect.iscoroutinefunction(callback):
                raise AddonManagerError('Cannot invoke an async hook synchronously')
            result = callback(*arguments)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise AddonManagerError('Cannot invoke an async hook synchronously')

    async def invoke_addon(self, addon, event):
        arguments = event.args()
        for owner in self._event_owners((addon,)):
            callback = self._target_callback(owner, event.name)
            if callback is None:
                continue
            result = callback(*arguments)
            if inspect.isawaitable(result):
                await result

    async def _dispatch(self, name, *arguments, propagate=()):
        failures = []
        try:
            for owner in self._event_owners():
                registry = self._snapshot((owner,), include_children=False)
                failures.extend(await registry.dispatch(name, *arguments, propagate=propagate))
        except BaseException:
            self._failures.extend(failures)
            raise
        return tuple(failures)

    async def _shutdown(self):
        try:
            failures = await self._dispatch('done')
            return failures + self._take_failures()
        finally:
            self.chain = []
            self._lookup.clear()

    def _event_owners(self, roots=None):
        # Appends can participate in the current event. Removal replaces the
        # active root list, so an event already iterating the old list still
        # reaches its remaining roots. Children are discovered after the parent
        # callback, matching mutations of the public addons list.
        seen = set()

        def visit(owner):
            identity = id(owner)
            if identity in seen:
                raise AddonManagerError('Repeated addon in the active event tree')
            if len(seen) >= HookRegistry.MAX_ADDONS:
                raise AddonManagerError('Addon event tree exceeds 256 objects')
            seen.add(identity)
            yield owner
            for child in HookRegistry._children(owner):
                yield from visit(child)

        if roots is None:
            roots = self.chain
        for root in roots:
            yield from visit(root)
