import base64
import contextlib
import json
import resource
import sys
import textwrap
import traceback

# Resource limits complement the mandatory kernel policy installed below.
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
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
        self.message = views.message
        if request.get('held_parts') and not request.get('translate_active'):
            resume_message(self.message, request['held_parts'], info, self.enrichments)
        _prepare_translation(self.message, request)
        self.metadata = views.metadata
        self.http1 = views.http1
        self.http2 = views.http2
        self.state = request.get('instance_state', {})
        self.storage = SharedStorage(request.get('storage_directory'))
        identity = request.get('instance', {})
        self.instance = InstanceContext(identity.get('mode', 'message'), identity.get('key', ''),
                                        identity.get('deployment_id', ''), identity.get('version', 0))
        self.connection = Connection(self.message, request.get('translate_active', False), self.instance.mode)
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
    response['error'] = traceback.format_exc(limit=8)[-12000:]
    return response


def invoke_script(current, compiled):
    output = Output()
    response = {'ok': False, 'replacement': None}
    namespace = {'CommitException': CommitException, 'Header': Header, 'PartType': PartType, 'Mode': Mode}
    try:
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            # Fresh script globals and API objects; imports/native module caches
            # remain private to this deployment's worker, not to a flow instance.
            exec(compiled, namespace)
            api = None if current.get('validate_only') else Api(current)
            result = None if api is None else namespace['__spider_script'](api)
            translation = getattr(api.message, '_translation', None) if api is not None else None
            requested = api is not None and api.connection._requested
            if requested or (translation is not None and translation.result is not None):
                if translation is None or translation.result is None or result is not translation.result:
                    raise CommitException('Active translate requires return api.message.translate() on every callback')
                response['translate_state'] = translation.checkpoint
                response['translate_control'] = translation.control_checkpoint
                response['translated'] = True
            held = None
            if isinstance(result, HeldCommit):
                if not current.get('hold_allowed') or api.instance.mode != 'flow' or api.side not in ('L', 'R'):
                    raise CommitException('Hold requires a live flow deployment at the end of the enabled chain and an L/R side')
                held = result.checkpoint
                response['hold'] = {'state': 'holding', 'parts': result.count}
                result = result.prefix
                response['need_more'] = not result
            elif api is not None and api.message.parts._held_from is not None:
                raise CommitException('Return message.commit() to publish the requested hold')
            elif current.get('held_parts'):
                if result is None:
                    raise CommitException('Resumed Parts require an explicit result: return message.commit() or hold again')
                response['hold'] = {'state': 'released', 'parts': 0}
            if isinstance(result, str):
                result = result.encode()
            if result is not None and not isinstance(result, (bytes, bytearray, memoryview)):
                raise TypeError('script must return None, str, bytes, bytearray, or memoryview')
            if result is not None and len(result) > 1024 * 1024:
                raise ValueError('replacement exceeds 1 MiB')
            if api is not None:
                if not isinstance(api.state, dict):
                    raise TypeError('api.state must remain a JSON object')
                encoded_state = json.dumps(api.state, allow_nan=False, ensure_ascii=False)
                if len(encoded_state.encode()) > 65536:
                    raise ValueError('api.state exceeds 64 KiB')
                response['instance_state'] = json.loads(encoded_state)
            response.update(ok=True, replacement=None if result is None else base64.b64encode(result).decode())
            response['held_parts'] = held
    except BaseException:
        response = script_error()
    finally:
        namespace.clear()
    response['logs'] = output.text.splitlines()
    return response


try:
    try:
        install_script_sandbox(request.get('storage_directory'))
    except Exception as error:
        raise SandboxUnavailable('Cannot activate script sandbox: ' + str(error)) from error
    source = 'def __spider_script(api):\n' + textwrap.indent(request['script'] or 'pass', '    ')
    compiled = compile(source, '<inspection>', 'exec')
except BaseException:
    json.dump(script_error(), sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()
    sys.exit(0)

if sys.argv[1:] != ['--persistent']:
    json.dump(invoke_script(request, compiled), sys.stdout)
else:
    import time
    storage_directory = request.get('storage_directory')
    started = time.monotonic()
    sys.stdout.write('{"ready": true}\n')
    sys.stdout.flush()
    for calls in range(4096):
        line = sys.stdin.readline(64 * 1024 * 1024 + 1)
        if not line:
            break
        if len(line) > 64 * 1024 * 1024 or not line.endswith('\n'):
            break
        current = json.loads(line)
        current['storage_directory'] = storage_directory
        response = invoke_script(current, compiled)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        # Ask the parent for rolling retirement, but keep serving until replaced.
        # Otherwise both equally-aged workers can exit while their successors
        # are still starting. Independent hard limits still bound this grace.
        cpu_seconds = usage.ru_utime + usage.ru_stime
        age_seconds = time.monotonic() - started
        rotate = calls >= 255 or cpu_seconds >= 0.5 or age_seconds >= 300
        recycle = (not response['ok'] or calls == 4095 or
                   cpu_seconds >= 1.5 or age_seconds >= 600)
        response['_request_id'] = current['_request_id']
        response['_worker_rotate'] = rotate
        response['_worker_recycle'] = recycle
        json.dump(response, sys.stdout)
        sys.stdout.write('\n')
        sys.stdout.flush()
        if recycle:
            break
        del current, response, line
