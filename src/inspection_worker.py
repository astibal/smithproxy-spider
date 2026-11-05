import base64
import contextlib
import json
import resource
import sys
import textwrap
import traceback

# Resource limits complement the mandatory kernel policy installed below.
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
cpu_supervised = sys.argv[1:] == ['--persistent', '--cpu-supervised']
persistent_worker = cpu_supervised or sys.argv[1:] == ['--persistent']
if not cpu_supervised:
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
sys.dont_write_bytecode = True
request = json.loads(sys.stdin.readline(64 * 1024 * 1024 + 1))
if 'language_action' in request:
    try:
        json.dump(language_query(request), sys.stdout)
    except Exception as error:
        json.dump({'ok': False, 'error': str(error)[:1000]}, sys.stdout)
    sys.exit(0)

class Output:
    def __init__(self):
        self.text = ''
    def write(self, value):
        self.text = (self.text + str(value))[:50000]
        return len(value)
    def flush(self):
        pass

class Api:
    def __init__(self, request):
        event = request.get('event', {})
        info = event.get('details', {}).get('info', {})
        self.event = event
        self.info = info
        self.phase = 'setup' if event.get('action') == 'connection-start' else 'content'
        self.bytes = base64.b64decode(info.get('content', ''), validate=True)
        self.text = self.bytes.decode('utf-8', errors='replace')
        self.side = info.get('side', '')
        self.session_id = event.get('id', '')
        self.session_label = info.get('session', '')
        self.annotations = info.get('content_annotations', [])
        self.enrichments = request.get('enrichments', [])
        for item in self.enrichments:
            item['bytes'] = base64.b64decode(item.get('content', ''), validate=True)
        views = make_views(event, self.bytes, self.enrichments)
        self.message = None if self.phase == 'setup' else views.message
        if request.get('held_parts') and not request.get('translate_active'):
            resume_message(self.message, request['held_parts'], info, self.enrichments)
        if self.message is not None:
            _prepare_translation(self.message, request)
            _prepare_h1_responses(self.message, request)
        self.metadata = views.metadata
        self.http1 = views.http1
        self.http2 = views.http2
        self.state = request.get('instance_state', {})
        self.network_enabled = network_enabled
        self.storage = SharedStorage(request.get('storage_directory'))
        identity = request.get('instance', {})
        self.instance = InstanceContext(identity.get('mode', 'message'), identity.get('key', ''),
                                        identity.get('deployment_id', ''), identity.get('version', 0))
        self.connection = Connection(self.message, request.get('translate_active', False),
                                     self.instance.mode, self.phase)
        self._protocol_owner = None
        protocol_checkpoint = request.get('protocol_state')

        # Observe native Parts after reassembly and Translate enrichment, but
        # before the script can edit drafts. No state lives in worker globals.
        if protocol_checkpoint is not None:
            if self.instance.mode != 'flow':
                raise CommitException('Protocol tracking requires a flow deployment')

            owner = ProtocolStateOwner(self.session_id, protocol_checkpoint)
            if self.phase == 'content':
                owner.observe(self.side, self.message.parts)

            self._protocol_owner = owner
            self.http1 = replace(self.http1, state=owner.h1.snapshot())
            self.http2 = replace(self.http2, state=owner.h2.snapshot())

        starts, ends = info.get('L7_payload_start', []), info.get('L7_payload_end', [])
        self.l7_state = 'unavailable'
        self.l7_ranges = []
        self.l7_encodings = []
        if starts and len(starts) == len(ends):
            if -1 in starts or -1 in ends:
                self.l7_state = 'unknown'
            elif starts == [0] and ends == [0]:
                self.l7_state = 'none'
            elif all(type(a) is int and type(b) is int and 0 <= a <= b <= len(self.bytes)
                     for a, b in zip(starts, ends)):
                self.l7_state = 'body'
                self.l7_ranges = list(zip(starts, ends))
                encodings = info.get('L7_encoding', [])
                self.l7_encodings = [encodings[i] if i < len(encodings) else '' for i in range(len(starts))]
            else:
                self.l7_state = 'invalid'
        self.l7_bytes = b''.join(self.bytes[a:b] for a, b in self.l7_ranges)
    def print(self, *values):
        print(*values)
    def hexdump(self, limit=256, width=16):
        width = max(1, min(256, int(width)))
        data = self.bytes[:max(0, min(65536, int(limit)))]
        rows = []
        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hexa = ' '.join(f'{v:02x}' for v in chunk)
            text = ''.join(chr(v) if 32 <= v < 127 else '.' for v in chunk)
            rows.append(f'{offset:08x}  {hexa:<{width * 3 - 1}}  |{text}|')
        return '\n'.join(rows)

def script_error():
    response = {'ok': False, 'replacement': None, 'logs': []}
    if isinstance(sys.exc_info()[1], SandboxUnavailable):
        response['error_kind'] = 'sandbox_unavailable'
    if isinstance(sys.exc_info()[1], StorageBusy):
        response['error_kind'] = 'storage_busy'
    if isinstance(sys.exc_info()[1], ScriptApiUnavailable):
        response['error_kind'] = 'unsupported_script_api'
    response['error'] = traceback.format_exc(limit=8)[-12000:]
    return response


class ScriptApiUnavailable(RuntimeError):
    """The requested execution path cannot preserve addon lifecycle semantics."""


def report_addon_failures(failures):
    for failure in failures:
        print(f'Addon {failure.addon} {failure.hook}: '
              f'{type(failure.exception).__name__}: {failure.exception}')


class AddonWorkerRuntime:
    """Own every process-local resource of one addon generation.

    A deployment worker has exactly one addon generation. Keeping its event
    loop, adapter, concurrent runner and startup diagnostics together makes the
    shutdown boundary explicit and prevents partially cleaned global state.
    """

    def __init__(self):
        self.loop = None
        self.adapter = None
        self.concurrent_runner = None
        self.startup_output = Output()
        self.closed = False

    def drain_startup_output(self, output):
        if self.startup_output.text:
            output.write(self.startup_output.text)
            self.startup_output.text = ''

    def run(self, awaitable):
        if self.loop is None or self.loop.is_closed():
            raise ScriptApiUnavailable('The addon event loop is unavailable')
        return self.loop.run_until_complete(awaitable)

    def close(self, report=False):
        """Retire the generation and all of its prepared worker resources."""
        if self.closed:
            return {'ok': True, 'logs': []}
        self.closed = True

        shutdown_output = Output()
        response = {'ok': True}
        try:
            if self.adapter is not None:
                with (
                    contextlib.redirect_stdout(shutdown_output),
                    contextlib.redirect_stderr(shutdown_output),
                ):
                    failures = self.run(self.adapter.close())
                    report_addon_failures(failures)
                    if failures:
                        response = {'ok': False, 'error': 'Addon cleanup hook failed'}
        except BaseException:
            response = {'ok': False, 'error': 'Addon cleanup aborted'}
            shutdown_output.write(traceback.format_exc(limit=8)[-12000:])
        finally:
            if self.concurrent_runner is not None:
                configure_concurrent_runner(None)
                try:
                    self.concurrent_runner.close()
                except BaseException:
                    response = {
                        'ok': False,
                        'error': 'Concurrent runner cleanup aborted',
                    }
                    shutdown_output.write(traceback.format_exc(limit=8)[-12000:])
            if self.loop is not None and not self.loop.is_closed():
                self.loop.close()

        response['logs'] = shutdown_output.text.splitlines()
        if authentication_worker or connect_worker:
            response['logs'] = []
            shutdown_output.text = ''
        if shutdown_output.text and not report:
            sys.stderr.write(shutdown_output.text)
        return response


addon_worker = AddonWorkerRuntime()


def invoke_content_view(current):
    """Serve one bounded UI request from the persistent addon generation."""
    output = Output()
    addon_worker.drain_startup_output(output)
    try:
        if addon_worker.adapter is None:
            raise ScriptApiUnavailable(
                'Custom content views require a deployed addon generation')
        action = current.get('content_view_action')
        if action not in ('list', 'render', 'reencode'):
            raise ValueError('Unknown content view action')

        arguments = {}
        if action in ('render', 'reencode'):
            encoded = current.get('data', '')
            if not isinstance(encoded, str):
                raise TypeError('Content view data must be base64 text')
            data = base64.b64decode(encoded, validate=True)
            if len(data) > 1024 * 1024:
                raise ValueError('Content view input exceeds 1 MiB')

            content_type = current.get('content_type')
            if (content_type is not None and
                    (not isinstance(content_type, str) or len(content_type) > 1024)):
                raise ValueError('Content type must be text up to 1024 characters')
            view_name = current.get('view_name', 'auto')
            if not isinstance(view_name, str) or not 1 <= len(view_name) <= 256:
                raise ValueError('Content view name must be 1 to 256 characters')

            if action == 'render':
                arguments = {
                    'data': data,
                    'content_type': content_type,
                    'view_name': view_name,
                }
            else:
                text = current.get('text')
                if not isinstance(text, str):
                    raise TypeError('Edited content view text must be text')
                if len(text.encode('utf-8')) > 1024 * 1024:
                    raise ValueError('Edited content view text exceeds 1 MiB')
                arguments = {
                    'text': text,
                    'original_data': data,
                    'content_type': content_type,
                    'view_name': view_name,
                }

        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = addon_worker.adapter.generation.content_view(action, **arguments)
        if action == 'render' and len(result['text'].encode('utf-8')) > 1024 * 1024:
            raise ValueError('Rendered content view text exceeds 1 MiB')
        if action == 'reencode':
            if len(result['data']) > 1024 * 1024:
                raise ValueError('Reencoded content view data exceeds 1 MiB')
            result['data'] = base64.b64encode(result['data']).decode('ascii')
        response = {'ok': True, 'replacement': None, **result}
        if len(json.dumps(response).encode('utf-8')) > 1900 * 1024:
            raise ValueError('Content view response exceeds worker budget')
    except BaseException:
        response = script_error()
    response['logs'] = output.text.splitlines()
    return response


def protocol_checkpoint(api, current, response, known_publication):
    """Prepare the state checkpoint only after the callback result is valid."""
    owner = api._protocol_owner

    if api.phase == 'setup' and api.connection._protocol_tracking_requested:
        owner = ProtocolStateOwner(api.session_id)

    if owner is None:
        return None

    if api.phase == 'setup':
        return owner.checkpoint()

    # Native hold checkpoints are the authority for retained Parts. Include
    # the opposite lane even when this callback did not change that hold.
    peer = 'R' if api.side == 'L' else 'L'
    checkpoints = {
        api.side: response.get('held_parts'),
        peer: response.get('peer_held_parts', current.get('peer_held_parts')),
    }
    held = {}

    for side, checkpoint in checkpoints.items():
        if checkpoint is not None:
            held[side], _ = _restore(checkpoint)

    # Logical suspension is separate from the ordinary suffix hold. Its
    # buffers also retain younger stream openings blocked behind an older one.
    control = response.get('translate_control') or {}
    suspension = control.get('suspension') or {}
    paused = set()

    for side in ('L', 'R'):
        direction = suspension.get(side, {})

        for stream in direction.get('paused', {}):
            paused.add((side, int(stream)))

        buffers = direction.get('buffers')
        if buffers is not None:
            store = _PartHoldBuffers.from_checkpoint(buffers)

            for stream in store.stream_ids:
                paused.add((side, stream))

    owner.finish(held, paused, known_publication=known_publication)
    return owner.checkpoint()


class LifecycleApi:
    """Deployment context with no connection, message or publish capability."""

    def __init__(self, phase):
        self.phase = phase
        self.storage = SharedStorage(request.get('storage_directory'))
        self.network_enabled = network_enabled

    def print(self, *values, **options):
        print(*values, **options)


class AuthenticationApi(LifecycleApi):
    """A pre-target policy callback, with no payload or connection controls."""

    def __init__(self, observation):
        super().__init__('authentication')
        from types import SimpleNamespace
        self.auth = SimpleNamespace(**observation)
        self.auth.groups = tuple(observation['groups'])
        self.auth.allowed = observation['status'] == 'accepted'


def invoke_authentication(observation, compiled):
    global authentication_worker
    authentication_worker = True
    native_output.text = ''
    output = Output()
    namespace = {}
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            if selected_api == 'mitmproxy':
                allowed = addon_worker.run(addon_worker.adapter.authenticate(observation))
                return {'ok': True, 'replacement': None, 'logs': [],
                        'auth_allowed': observation['status'] == 'accepted' and allowed}

            api = AuthenticationApi(observation)
            if native_lifecycle:
                result = native_namespace['main'](api, native_state)
            else:
                exec(compiled, namespace)
                result = namespace['__spider_script'](api)
            if result is not None or type(api.auth.allowed) is not bool:
                raise ValueError('Authentication returns None and sets api.auth.allowed')
            allowed = observation['status'] == 'accepted' and api.auth.allowed
        return {'ok': True, 'replacement': None, 'logs': [], 'auth_allowed': allowed}
    except BaseException:
        # Tracebacks and prints can contain credentials; never publish them.
        return {'ok': False, 'replacement': None, 'logs': [], 'auth_allowed': False,
                'error': 'Authentication callback failed'}
    finally:
        namespace.clear()


def invoke_http_connect(observation):
    global connect_worker
    connect_worker = True
    output = Output()

    # Discard callback output: even rejected requests may carry credentials.
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            decision = addon_worker.run(
                addon_worker.adapter.http_connect(observation)
            )

        return {
            'ok': True,
            'replacement': None,
            'decision': decision,
            'logs': [],
        }
    except BaseException:
        # A traceback can expose the same credentials as explicit script output.
        return {
            'ok': False,
            'replacement': None,
            'logs': [],
            'error': 'CONNECT callback failed',
        }


def invoke_lifecycle(observation, *, tls=False, quic=False):
    output = Output()
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            adapter = addon_worker.adapter
            if quic:
                callback = adapter.quic_lifecycle
            else:
                callback = adapter.tls_lifecycle if tls else adapter.server_lifecycle
            decision = addon_worker.run(callback(observation))

        return {
            'ok': True,
            'replacement': None,
            'decision': decision,
            'logs': [],
        }
    except BaseException:
        return {
            'ok': False,
            'replacement': None,
            'logs': [],
            'error': 'TLS lifecycle callback failed' if tls else 'Server lifecycle callback failed',
        }


def compile_native(source):
    """Detect module-style hooks without executing administrator code."""
    import ast

    normalized = source.removeprefix('\ufeff')
    wrapped = 'def __spider_script(api):\n' + textwrap.indent(normalized or 'pass', '    ')
    try:
        tree = ast.parse(normalized or 'pass', '<inspection>')
    except SyntaxError:
        # Legacy snippets may start indented: they are function bodies, not
        # modules. Let the original wrapper validate their syntax.
        return compile(wrapped, '<inspection>', 'exec'), False
    entries = [node for node in tree.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name in ('init', 'main', 'exit')]
    lifecycle = any(node.name == 'main' for node in entries)

    # Snippets retain their historical top-level return convention. Only a
    # top-level main function opts into deployment-scoped Python objects.
    if not lifecycle:
        return compile(wrapped, '<inspection>', 'exec'), False

    names = set()
    for node in entries:
        args = node.args
        if (node.name in names or isinstance(node, ast.AsyncFunctionDef)
                or node.decorator_list or args.posonlyargs or args.kwonlyargs
                or args.vararg or args.kwarg or args.defaults
                or [argument.arg for argument in args.args] != ['api', 'state']):
            raise ValueError('Lifecycle hooks require def ' + node.name + '(api, state)')

        names.add(node.name)

    return compile(tree, '<inspection>', 'exec'), True


native_namespace = {}
native_state = None
native_initialized = False
authentication_worker = False
connect_worker = False
native_lifecycle = False
native_output = Output()
network_enabled = request.get('network_enabled', False)


def close_native():
    global native_initialized, native_state
    output = Output()
    response = {'ok': True}

    # Mark cleanup before invoking user code, so even a failing exit runs once.
    try:
        if native_initialized:
            native_initialized = False
            callback = native_namespace.get('exit')
            if callback is not None:
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    callback(LifecycleApi('exit'), native_state)
    except BaseException:
        response = script_error()
    finally:
        native_state = None
        native_namespace.clear()
        sys.modules.pop('_spider_deployment', None)
    response['logs'] = output.text.splitlines()
    if authentication_worker:
        response['logs'] = []
        if not response['ok']:
            response['error'] = 'Authentication cleanup failed'
    return response


def invoke_script(current, compiled):
    output = Output()
    output.write(native_output.text)
    native_output.text = ''
    addon_worker.drain_startup_output(output)
    response = {'ok': False, 'replacement': None,
                'script_api': selected_api, 'script_api_source': selection_source}
    namespace = {'CommitException': CommitException, 'Header': Header, 'PartType': PartType, 'Mode': Mode, 'Safety': Safety}
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            # Legacy snippets keep callback-local globals. Lifecycle scripts
            # and addons retain one namespace per deployment generation.
            if selected_api == 'spider' and not native_lifecycle:
                exec(compiled, namespace)
            stopping = (selected_api == 'mitmproxy' and
                        current.get('event', {}).get('action') == 'connection-stop')
            api = None if current.get('validate_only') or stopping else Api(current)
            input_size = len(api.bytes) if api is not None else 0
            result = None
            if stopping:
                stop_info = current.get('event', {}).get('details', {}).get('info', {})
                failures = addon_worker.run(
                    addon_worker.adapter.stop(
                        current['event'].get('id', ''), stop_info))
                report_addon_failures(failures)
            elif api is not None:
                if selected_api == 'spider':
                    if native_lifecycle:
                        result = native_namespace['main'](api, native_state)
                    else:
                        result = namespace['__spider_script'](api)
                elif api.phase == 'setup':
                    # Endpoint observations are not yet part of the worker
                    # envelope. Leave them unknown rather than infer TLS or
                    # socket addresses from human-readable session labels.
                    setup_result = addon_worker.adapter.setup(api, None, None)
                    if setup_result is not None:
                        report_addon_failures(addon_worker.run(setup_result))
                else:
                    result = addon_worker.run(addon_worker.adapter.content(api))
            translation = getattr(api.message, '_translation', None) if api is not None else None
            h1_response = getattr(api.message, '_h1_response', None) if api is not None else None
            requested = api is not None and api.connection._requested
            staged_translation = translation is not None and bool(
                translation.message_edits or translation.local_responses or
                translation.suspension is not None)
            if requested or staged_translation or (translation is not None and translation.result is not None):
                if translation is None or translation.result is None or result is not translation.result:
                    raise CommitException('Active translate requires return api.message.translate() on every callback')
                response['translate_state'] = translation.checkpoint
                response['translate_control'] = translation.control_checkpoint
                response['translated'] = True
                if translation.peer_checkpoint_changed:
                    response['peer_translate_state'] = translation.peer_checkpoint
                if translation.peer_hold_changed:
                    response['peer_held_parts'] = translation.peer_hold_result
                response['hold_credit_reservation'] = bool(translation.control_checkpoint.get('flow', {}).get('hold_reserved'))
                if translation.flow_summary is not None:
                    response['flow_control'] = translation.flow_summary
                if translation.reverse_output:
                    response['replacement_reverse'] = base64.b64encode(translation.reverse_output).decode()
            if h1_response is not None:
                if h1_response.result is not None:
                    if result is not h1_response.result:
                        raise CommitException(
                            'HTTP/1 response ordering requires return api.message.commit()')
                elif h1_response.has_local_responses():
                    raise CommitException(
                        'A staged HTTP/1 local response requires return api.message.commit()')
                elif h1_response.requires_publication():
                    if result is not None:
                        raise CommitException(
                            'Raw replacement cannot bypass a queued HTTP/1 local response')
                    result = h1_response.commit()
                else:
                    h1_response.observe_passthrough()

                response['h1_response_state'] = h1_response.checkpoint
                suspension = h1_response.suspension
                if suspension is not None and suspension.peer_hold_changed:
                    response['peer_held_parts'] = suspension.peer_hold_result
                if h1_response.termination is not None:
                    response['connection_close'] = {
                        'reason': h1_response.termination['reason'],
                    }
                if h1_response.reverse_output:
                    response['replacement_reverse'] = base64.b64encode(
                        h1_response.reverse_output).decode()
            # Capture the identity before HeldCommit is reduced to its prefix
            # and byte-like results are normalized. Arbitrary replacements do
            # not prove publication of the input's logical message identities.
            known_publication = result is None
            if api is not None and api.message is not None:
                native_results = [getattr(api.message, '_commit_result', None)]
                if translation is not None:
                    native_results.append(translation.result)
                if h1_response is not None:
                    native_results.append(h1_response.result)

                known_publication = known_publication or any(
                    value is not None and result is value for value in native_results)

                # Synthesized responses and termination deliberately suppress
                # input messages. A successful native commit is not evidence
                # that those input identities were published unchanged.
                if h1_response is not None and (h1_response.has_local_responses() or h1_response.termination):
                    known_publication = False

                if translation is not None and (
                        translation.local_responses or translation.terminations or
                        translation.reset_failures or translation.informational_suppressions):
                    known_publication = False

            held = None
            if isinstance(result, HeldCommit):
                if not current.get('hold_allowed') or api.instance.mode != 'flow' or api.side not in ('L', 'R'):
                    raise CommitException('Hold requires a live flow deployment at the end of the enabled chain and an L/R side')
                held = result.checkpoint
                response['hold'] = {'state': 'holding', 'parts': result.count}
                result = result.prefix
                response['need_more'] = not result
            elif api is not None and api.message is not None and api.message.parts._held_from is not None:
                raise CommitException('Return message.commit() to publish the requested hold')
            elif current.get('held_parts'):
                if result is None:
                    raise CommitException('Resumed Parts require an explicit result: return message.commit() or hold again')
                response['hold'] = {'state': 'released', 'parts': 0}
            if isinstance(result, str):
                result = result.encode()
            if result is not None and not isinstance(result, (bytes, bytearray, memoryview)):
                raise TypeError('script must return None, str, bytes, bytearray, or memoryview')

            # Normalize before measuring: memoryview length can count elements
            # rather than bytes, while str has already been encoded above.
            if result is not None:
                result = bytes(result)

            if result is not None and len(result) > 1024 * 1024:
                raise ValueError('replacement exceeds 1 MiB')

            if api is not None and api.phase == 'setup' and result is not None:
                raise CommitException('Setup has no payload; return None after requesting rewrite')

            # A new proxy explicitly reports the negotiated capability. Older
            # proxies and offline/manual runs do not carry this field. A plain
            # same-size replacement needs no reservation and does not activate
            # an output context. Protocol consequences belong to the script.
            control = api.info.get('webhook_control', {}) if api is not None else {}
            if control.get('rewrite') is False:
                if held is not None or current.get('held_parts') or response.get('translated'):
                    raise CommitException('Hold and Translate require rewrite reservation at connection-start')

                if result is not None and len(result) != input_size:
                    raise CommitException('Length-changing rewrite was not reserved at connection-start')

            if api is not None:
                if not isinstance(api.state, dict):
                    raise TypeError('api.state must remain a JSON object')
                encoded_state = json.dumps(api.state, allow_nan=False, ensure_ascii=False)
                if len(encoded_state.encode()) > 65536:
                    raise ValueError('api.state exceeds 64 KiB')
                response['instance_state'] = json.loads(encoded_state)
            response.update(ok=True, replacement=None if result is None else base64.b64encode(result).decode())
            if api is not None and api.phase == 'setup':
                response['rewrite_requested'] = api.connection._rewrite_requested
            response['held_parts'] = held
            if api is not None:
                tracked = protocol_checkpoint(api, current, response, known_publication)
                if tracked is not None:
                    response['protocol_state'] = tracked

            if response.get('replacement_reverse'):
                # An empty forward replacement plus reverse output is not need-more.
                response['need_more'] = False
            if len(json.dumps(response).encode()) > 1900 * 1024:
                raise CommitException('Translate output and checkpoints exceed worker response budget')
    except BaseException:
        response = script_error()
    finally:
        namespace.clear()
    response['logs'] = output.text.splitlines()
    if connect_worker and current.get('event', {}).get('action') == 'connection-stop':
        response['logs'] = []
        if not response['ok']:
            response['error'] = 'CONNECT connection cleanup failed'
    return response


try:
    source = request['script']
    if type(network_enabled) is not bool:
        raise ValueError('network_enabled must be a boolean')
    first_line = source.removeprefix('\ufeff').split('\n', 1)[0].rstrip('\r')
    executing_addon = (not request.get('validate_only') and
                       (first_line == '#!mitmproxy' or request.get('script_api') == 'mitmproxy'))
    native_compiled = None
    if not executing_addon and first_line != '#!mitmproxy' and request.get('script_api', 'spider') == 'spider':
        native_compiled, native_lifecycle = compile_native(source)
    if cpu_supervised and not executing_addon and not native_lifecycle:
        # Legacy snippets retain the cumulative kernel limit. Stateful
        # generations use renewable parent-owned CPU budgets.
        resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    if executing_addon:
        if not persistent_worker:
            raise ScriptApiUnavailable('Addon execution requires a persistent generation worker')
        # Only trusted runtime preparation precedes the sandbox. In particular,
        # no administrator module or lifecycle hook runs while sockets can be
        # created. The policy grants access only to this prepared epoll handle.
        import asyncio
        import selectors
        import logging
        from addon_runtime import AddonGeneration
        from addon_native import NativeAddonAdapter
        from addon_authentication import AuthenticationAddonAdapter
        from addon_h1_events import H1AddonEvents
        from addon_h2_events import H2AddonEvents
        from addon_script import ConcurrentRunner, configure_concurrent_runner
        addon_selector = selectors.EpollSelector()
        addon_worker.loop = asyncio.SelectorEventLoop(addon_selector)
        addon_concurrent_selector = selectors.EpollSelector()
        addon_concurrent_loop = asyncio.SelectorEventLoop(addon_concurrent_selector)
        addon_worker.concurrent_runner = ConcurrentRunner(addon_concurrent_loop)

        class AddonLogHandler(logging.Handler):
            """Resolve stderr per record, not once during generation startup.

            Each callback redirects stderr to its own bounded output buffer.
            A normal StreamHandler would retain the startup buffer forever.
            """
            def emit(self, record):
                try:
                    sys.stderr.write(self.format(record) + '\n')
                except Exception:
                    self.handleError(record)

        logging.addLevelName(21, 'ALERT')
        addon_log_handler = AddonLogHandler()
        addon_log_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logging.getLogger().addHandler(addon_log_handler)
        logging.getLogger().setLevel(logging.INFO)
    try:
        if addon_worker.loop is None:
            install_script_sandbox(request.get('storage_directory'), network_enabled=network_enabled)
        else:
            install_script_sandbox(request.get('storage_directory'), network_enabled=network_enabled,
                                   event_loop_fd=addon_selector.fileno(),
                                   additional_event_loop_fds=(
                                       addon_concurrent_selector.fileno(),
                                   ),
                                   wakeup_read_fds=(
                                       addon_worker.loop._ssock.fileno(),
                                       addon_concurrent_loop._ssock.fileno(),
                                   ),
                                   wakeup_write_fds=(
                                       addon_worker.loop._csock.fileno(),
                                       addon_concurrent_loop._csock.fileno(),
                                   ))
    except Exception as error:
        raise SandboxUnavailable('Cannot activate script sandbox: ' + str(error)) from error
    if addon_worker.concurrent_runner is not None:
        addon_worker.concurrent_runner.start()
        configure_concurrent_runner(addon_worker.concurrent_runner)
    selected_api = 'spider'
    selection_source = 'selection'
    if native_compiled is None:
        # Keep the legacy path lightweight. Addon compilation is inert: even
        # module-level imports and expressions must not run during validation.
        from addon_loader import compile_script
        selection, compiled = compile_script(source, request.get('script_api', 'spider'))
        selected_api = selection.api
        selection_source = selection.source
    else:
        compiled = native_compiled
    if selected_api == 'spider':
        compiled = native_compiled
        if native_lifecycle and not request.get('validate_only'):
            # Register a real module so dataclasses and imported helpers can
            # resolve class annotations through their defining module.
            import types
            module = types.ModuleType('_spider_deployment')
            sys.modules[module.__name__] = module
            native_namespace = module.__dict__
            native_namespace.update(CommitException=CommitException, Header=Header,
                                    PartType=PartType, Mode=Mode, Safety=Safety)
            with contextlib.redirect_stdout(native_output), contextlib.redirect_stderr(native_output):
                exec(compiled, native_namespace)
                initializer = native_namespace.get('init')
                if initializer is not None:
                    native_state = initializer(LifecycleApi('init'), None)
                native_initialized = True
    if selected_api == 'mitmproxy' and not request.get('validate_only'):
        with (
            contextlib.redirect_stdout(addon_worker.startup_output),
            contextlib.redirect_stderr(addon_worker.startup_output),
        ):
            if request.get('hook', 'content') == 'authentication':
                generation = AddonGeneration(source, AuthenticationAddonAdapter.HOOKS)
                addon_worker.adapter = AuthenticationAddonAdapter(generation)
            else:
                generation = AddonGeneration(source, NativeAddonAdapter.HOOKS)
                addon_worker.adapter = NativeAddonAdapter(
                    generation, opaque_part_factory=RewritePart)
            option_specs = request.get('addon_options', [])
            if not isinstance(option_specs, list):
                raise ValueError('Addon options must be a list')
            if len(option_specs) > 128:
                raise ValueError('Addon options exceed 128 entries')
            if any(not isinstance(spec, str) or not spec or len(spec) > 4096
                   for spec in option_specs):
                raise ValueError('Addon option entries must be bounded non-empty text')
            report_addon_failures(addon_worker.run(
                generation.start(option_specs=option_specs)))
except BaseException:
    response = script_error()
    if addon_worker.loop is not None:
        # Module execution can register live addons before a later statement
        # fails. Preserve the original startup error while retiring those
        # objects inside the same sandbox and capturing their cleanup output.
        try:
            cleanup = addon_worker.close(report=True)
            if cleanup.get('error') in (
                    'Addon cleanup aborted',
                    'Concurrent runner cleanup aborted'):
                addon_worker.startup_output.write(
                    'Addon startup cleanup aborted:\n')
            for line in cleanup['logs']:
                addon_worker.startup_output.write(line + '\n')
        except BaseException:
            addon_worker.startup_output.write('Addon startup cleanup aborted:\n')
            addon_worker.startup_output.write(traceback.format_exc(limit=8)[-12000:])
    response['logs'] = (native_output.text + addon_worker.startup_output.text).splitlines()
    json.dump(response, sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()
    sys.exit(0)

def serve_persistent():
    import time
    storage_directory = request.get('storage_directory')
    started = time.monotonic()
    ready = {'ready': True}
    if native_lifecycle:
        ready['native_lifecycle'] = True
    if selected_api == 'mitmproxy':
        ready['script_api'] = selected_api
    sys.stdout.write(json.dumps(ready) + '\n')
    sys.stdout.flush()
    calls = 0
    while native_lifecycle or addon_worker.adapter is not None or calls < 4096:
        line = sys.stdin.readline(64 * 1024 * 1024 + 1)
        if not line:
            break
        if len(line) > 64 * 1024 * 1024 or not line.endswith('\n'):
            break
        current = json.loads(line)
        if current.get('_shutdown') is True and (native_lifecycle or addon_worker.adapter is not None):
            response = close_native() if native_lifecycle else addon_worker.close(report=True)
            response['_shutdown'] = True
            json.dump(response, sys.stdout)
            sys.stdout.write('\n')
            sys.stdout.flush()
            break
        current['storage_directory'] = storage_directory
        if 'quic_lifecycle' in current:
            response = invoke_lifecycle(current['quic_lifecycle'], quic=True)
        elif 'tls_lifecycle' in current:
            response = invoke_lifecycle(current['tls_lifecycle'], tls=True)
        elif 'server_lifecycle' in current:
            response = invoke_lifecycle(current['server_lifecycle'])
        elif 'http_connect' in current:
            response = invoke_http_connect(current['http_connect'])
        elif 'authentication' in current:
            response = invoke_authentication(current['authentication'], compiled)
        elif 'content_view_action' in current:
            response = invoke_content_view(current)
        else:
            response = invoke_script(current, compiled)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # Ask the parent for rolling retirement, but keep serving until replaced.
        # Otherwise both equally-aged workers can exit while their successors
        # are still starting. Independent hard limits still bound this grace.
        cpu_seconds = usage.ru_utime + usage.ru_stime
        age_seconds = time.monotonic() - started
        rotate = calls >= 255 or cpu_seconds >= 0.5 or age_seconds >= 300
        # A structured script error is a valid IPC response. Legacy snippets
        # execute in a fresh namespace and can safely report that error without
        # destroying healthy pool capacity. Transport failure, malformed IPC
        # and hard resource exhaustion are handled by the parent and still
        # retire the process. Addon generations are different: an adapter-level
        # failure can leave unrollbackable Python state and must invalidate the
        # generation instead of silently continuing. Native lifecycle state
        # has the same ownership and failure semantics.
        recycle = (calls == 4095 or cpu_seconds >= 1.5 or age_seconds >= 600)
        if native_lifecycle:
            rotate = False
            recycle = not response['ok']
        if addon_worker.adapter is not None:
            rotate = False
            # A content view is an auxiliary renderer. Reference behavior
            # reports formatter errors without discarding addon module state.
            recycle = not response['ok'] and 'content_view_action' not in current
        response['_request_id'] = current['_request_id']
        response['_worker_rotate'] = rotate
        response['_worker_recycle'] = recycle

        # This is an internal JSON channel, not formatted diagnostic output.
        # Encode compactly and write once instead of visiting the stream for
        # every scalar. The existing response-size guard remains conservative.
        sys.stdout.write(json.dumps(response, separators=(',', ':')))
        sys.stdout.write('\n')
        sys.stdout.flush()
        if recycle:
            break
        calls += 1
        del current, response, line

try:
    if persistent_worker:
        serve_persistent()
    else:
        response = invoke_script(request, compiled)
        cleanup = close_native()
        response['logs'].extend(cleanup['logs'])
        if not cleanup['ok']:
            response['ok'] = False
            response['error'] = cleanup['error']
        json.dump(response, sys.stdout)
finally:
    close_native()
    addon_worker.close()
