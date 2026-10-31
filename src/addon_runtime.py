"""One serialized addon generation owned by a deployment worker.

Transport events and the public loader/options services are supplied by the
adapter. This object never reconstructs addon state from JSON or replays hooks
to recover a lost worker: Python state belongs to this generation's lifetime.
"""

import asyncio

from addon_loader import LoadedAddon, compile_script
from addon_manager import AddonManager
from addon_commands import CommandManager
from addon_modules import compatibility_modules
from addon_flow import HTTPFlow, TCPFlow, UDPFlow
from addon_connection import Client, Server
from addon_options import Loader, Options, OptionsError
from addon_contentviews import (
    describe_registered,
    reencode_registered,
    render_registered,
)
from addon_log import Log


class AddonRuntimeError(RuntimeError):
    """A generation was used outside its valid lifecycle."""


class AddonMaster:
    """Generation-local public services that Spider can implement faithfully.

    Proxy-wide operations such as shutdown and network replay are not exposed
    until the worker has a host control contract for them. Detached
    ``load_flow()`` lifecycle replay is safe because it invokes addon hooks only
    and never publishes the resulting object to Smithproxy. Keeping supported
    services on a real object makes this boundary explicit and avoids growing
    an unstructured namespace as compatibility support expands.
    """

    def __init__(self, options, addons):
        self.options = options
        self.addons = addons
        self.commands = CommandManager(self)
        self.log = Log(self)
        self.event_loop = None

    class _FlowLifecycleEvent:
        """One private event value consumed by the public addon manager."""

        def __init__(self, name, flow):
            self.name = name
            self.flow = flow

        def args(self):
            return [self.flow]

    async def _load_event(self, name, flow):
        await self.addons.trigger_event(self._FlowLifecycleEvent(name, flow))

    async def _load_messages(self, prefix, flow, container, terminal):
        messages = tuple(container.messages)
        container.messages = []
        await self._load_event(prefix + "_start", flow)
        for message in messages:
            container.messages.append(message)
            await self._load_event(prefix + "_message", flow)
        await self._load_event(prefix + "_" + terminal, flow)

    async def load_flow(self, f):
        """Replay a detached flow through the active addon lifecycle.

        This is an addon event operation, not network replay. In particular it
        never publishes the possibly mutated object to Smithproxy. Transport
        message lists are rebuilt incrementally so each callback observes the
        same history boundary as mitmproxy's public Master API.
        """
        flow = f
        if isinstance(flow, HTTPFlow):
            if flow.request is not None:
                await self._load_event("requestheaders", flow)
                await self._load_event("request", flow)
            if flow.response is not None:
                await self._load_event("responseheaders", flow)
                await self._load_event("response", flow)
            if flow.websocket is not None:
                await self._load_messages(
                    "websocket",
                    flow,
                    flow.websocket,
                    "end",
                )
            if flow.error is not None:
                await self._load_event("error", flow)
            return

        # Keep the DNS import lazy, matching Flow.from_state and avoiding a
        # circular import while addon_dns builds DNSFlow on this base module.
        from addon_dns import DNSFlow

        if isinstance(flow, DNSFlow):
            if flow.request is not None:
                await self._load_event("dns_request", flow)
            if flow.response is not None:
                await self._load_event("dns_response", flow)
            if flow.error is not None:
                await self._load_event("dns_error", flow)
            return

        if isinstance(flow, TCPFlow):
            prefix = "tcp"
        elif isinstance(flow, UDPFlow):
            prefix = "udp"
        else:
            raise TypeError("Unknown flow type: " + type(flow).__name__)

        terminal = "error" if flow.error is not None else "end"
        await self._load_messages(
            prefix,
            flow,
            flow,
            terminal,
        )


class AddonGeneration:
    LIFECYCLE_HOOKS = frozenset({"load", "configure", "running", "update", "done"})

    def __init__(self, source, transport_hooks, *, modules=None, max_flows=128):
        if type(max_flows) is not int or not 1 <= max_flows <= 1024:
            raise ValueError("max_flows must be an integer between 1 and 1024")
        self.options = Options()
        self._hooks = set(transport_hooks) | self.LIFECYCLE_HOOKS
        self.manager = AddonManager(self.options, self._hooks)
        self.master = AddonMaster(self.options, self.manager)
        self.manager.commands = self.master.commands
        if modules is None:
            modules = compatibility_modules(options=self.options, master=self.master)
        compile_script(source, "mitmproxy")
        self._source = source
        self._modules = modules
        self.addon = None
        self.state = "created"
        self._busy = False
        self._flows = {}
        self._option_failures = []
        self.max_flows = max_flows

    @staticmethod
    def _flow_key(connection_id, exchange_id):
        if not isinstance(connection_id, str) or not connection_id or len(connection_id) > 1024:
            raise ValueError("A bounded, non-empty connection identity is required")
        if type(exchange_id) is not int or exchange_id < 1:
            raise ValueError("A positive exchange identity is required")
        return connection_id, exchange_id

    @property
    def active_flows(self):
        return len(self._flows)

    def create_flow(self, connection_id, exchange_id, client_conn, server_conn):
        """Allocate an exchange without conflating stream IDs across connections.

        For HTTP/2, exchange_id is the stream ID. An HTTP/1 adapter supplies its
        own request sequence. This table owns no sockets and starts no workers.
        """
        if self.state != "running" or self._busy:
            raise AddonRuntimeError("Create flows between callbacks of a running generation")
        key = self._flow_key(connection_id, exchange_id)
        if key in self._flows:
            raise AddonRuntimeError("The exchange already has an addon flow")
        if len(self._flows) >= self.max_flows:
            raise AddonRuntimeError("Addon active-flow limit reached")
        # The native envelope does not yet carry observed endpoint metadata.
        # Still provide the public descriptor objects expected by addons and
        # saved-flow tools, with every unknown field left explicitly empty.
        # Never infer endpoints from display labels or connection identities.
        if client_conn is None:
            client_conn = Client(peername=None, sockname=None)
        if server_conn is None:
            server_conn = Server(address=None)
        flow = HTTPFlow(client_conn, server_conn, live=True)
        self._flows[key] = flow
        return flow

    def create_transport_flow(self, connection_id, kind, client_conn, server_conn):
        """Allocate one raw TCP or UDP flow for a native connection."""
        if kind not in ('tcp', 'udp'):
            raise ValueError('Raw transport kind must be tcp or udp')
        if self.state != 'running' or self._busy:
            raise AddonRuntimeError(
                'Create flows between callbacks of a running generation')
        key = self._flow_key(connection_id, 1)
        if key in self._flows:
            raise AddonRuntimeError('The connection already has an addon flow')
        if len(self._flows) >= self.max_flows:
            raise AddonRuntimeError('Addon active-flow limit reached')

        flow_type = TCPFlow if kind == 'tcp' else UDPFlow
        flow = flow_type(client_conn, server_conn, live=True)
        self._flows[key] = flow
        return flow

    def get_flow(self, connection_id, exchange_id):
        return self._flows.get(self._flow_key(connection_id, exchange_id))

    def connection_flows(self, connection_id):
        self._flow_key(connection_id, 1)
        return tuple(flow for key, flow in self._flows.items() if key[0] == connection_id)

    def release_flow(self, connection_id, exchange_id):
        """Release after the terminal event and publication, never before hooks."""
        if self._busy:
            raise AddonRuntimeError("Cannot release a flow during dispatch")
        flow = self._flows.pop(self._flow_key(connection_id, exchange_id), None)
        if flow is not None:
            flow.live = False
            flow.resume()
        return flow

    def release_connection(self, connection_id):
        """Release all exchanges after the adapter delivers connection teardown."""
        self._flow_key(connection_id, 1)
        if self._busy:
            raise AddonRuntimeError("Cannot release a connection during dispatch")
        keys = [key for key in self._flows if key[0] == connection_id]
        return tuple(self.release_flow(*key) for key in keys)

    def _release_all_flows(self):
        for flow in self._flows.values():
            flow.live = False
            flow.resume()
        self._flows.clear()

    def invalidate(self):
        """Retire state after an adapter transaction cannot be published.

        Arbitrary addon globals cannot be rolled back with native Parts. The
        owning worker must reject further traffic until explicit redeployment.
        """
        if self.state != 'closed':
            self.state = 'failed'

    async def start(self, loader=None, updated_options=None, option_specs=()):
        if self.state != "created":
            raise AddonRuntimeError("Addon generation can only start once")
        self.state = "starting"
        self.master.event_loop = asyncio.get_running_loop()
        self._busy = True
        failures = []
        try:
            # Construction is inert. Execute administrator code only when the
            # worker starts the generation inside its established sandbox.
            self.addon = LoadedAddon(self._source, self._modules, self._hooks,
                                     manager=self.manager, execute=False)
            self.addon.execute()
            if loader is None:
                loader = Loader(self.options, self.master.commands)
            failures.extend(await self.addon.dispatch("load", loader))
            # Text overrides belong between declaration and the initial
            # configure event. Earlier application would reject addon-defined
            # names; later application would expose defaults to running().
            self.options.set(*option_specs)
            self.options.changed.connect(self._options_changed)
            if updated_options is None:
                updated_options = self.options.keys()
            failures.extend(self._configure_now(set(updated_options)))
            failures.extend(await self.addon.dispatch("running"))
            failures.extend(self.take_option_failures())
        except BaseException:
            self.state = "failed"
            raise
        finally:
            self._busy = False
        self.state = "running"
        return tuple(failures)

    async def dispatch(self, hook, *arguments):
        if hook in self.LIFECYCLE_HOOKS:
            raise AddonRuntimeError("Use the generation lifecycle methods for " + hook)
        if self.state != "running":
            raise AddonRuntimeError("Addon generation is not running")
        return await self._invoke(hook, *arguments)

    def observes(self, hook):
        """Check an optional transport hook without scheduling an empty task."""
        if self.state != "running":
            raise AddonRuntimeError("Addon generation is not running")
        if hook not in self._hooks:
            return False
        return self.manager._observes(hook)

    async def configure(self, updated_options):
        if self.state != "running":
            raise AddonRuntimeError("Addon generation is not running")
        return await self._invoke("configure", set(updated_options))

    async def update(self, flows):
        if self.state != "running":
            raise AddonRuntimeError("Addon generation is not running")
        return await self._invoke("update", flows)

    def content_view(self, action, **arguments):
        """Invoke a registered custom view inside this addon's import scope."""
        if self.state != "running":
            raise AddonRuntimeError("Addon generation is not running")
        if self._busy:
            raise AddonRuntimeError("Addon dispatch must be serialized")

        module = self._modules["mitmproxy.contentviews"]
        self._busy = True
        try:
            with self.addon._scope():
                if action == "list":
                    return {"views": describe_registered(module.registry)}
                if action == "render":
                    return render_registered(module.registry, **arguments)
                if action == "reencode":
                    return {
                        "data": reencode_registered(module.registry, **arguments)
                    }
                raise ValueError("Unknown content view action: " + str(action))
        finally:
            self._busy = False

    def _configure_now(self, updated_options):
        return self.addon.dispatch_sync("configure", updated_options,
                                        propagate=(OptionsError,))

    def _options_changed(self, updated):
        if self.state not in {"starting", "running", "closing"}:
            return
        # This is intentionally nested when an addon assigns ctx.options inside
        # another hook. Deferral would move rejection past the user's try/except
        # and change both the observable order and the rollback boundary.
        was_busy = self._busy
        self._busy = True
        try:
            self._option_failures.extend(self._configure_now(updated))
        except OptionsError:
            raise
        except BaseException:
            self.state = "failed"
            raise
        finally:
            self._busy = was_busy

    def take_option_failures(self):
        failures = tuple(self._option_failures)
        self._option_failures.clear()
        return failures

    async def _invoke(self, hook, *arguments):
        # Import scoping and mutable addon globals are generation-local, but
        # not reentrant. Reject accidental overlap rather than corrupting state.
        if self._busy:
            raise AddonRuntimeError("Addon dispatch must be serialized")
        self._busy = True
        try:
            if hook == "configure":
                failures = self._configure_now(*arguments)
            else:
                failures = await self.addon.dispatch(hook, *arguments)
            return failures + self.take_option_failures()
        except OptionsError:
            raise
        except BaseException:
            # Cancellation may interrupt an addon halfway through a mutation.
            # Do not pretend its Python state is safe for another transaction.
            self.state = "failed"
            raise
        finally:
            self._busy = False

    async def close(self):
        if self._busy:
            raise AddonRuntimeError("Cannot close an addon during dispatch")
        if self.state == "closed":
            return ()
        if self.addon is None:
            self._release_all_flows()
            self.state = "closed"
            return ()
        self.state = "closing"
        self._busy = True
        try:
            failures = await self.addon.dispatch("done")
            return failures + self.take_option_failures()
        finally:
            self.options.changed.disconnect(self._options_changed)
            self._busy = False
            self.state = "closed"
            self._release_all_flows()
