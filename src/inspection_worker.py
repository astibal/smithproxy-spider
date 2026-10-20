import base64
import contextlib
import json
import resource
import sys
import textwrap
import traceback

# Trusted administrator scripts, isolated for failures, not a security sandbox.
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024,) * 2)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
request = json.load(sys.stdin)
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
        self.metadata = views.metadata
        self.http1 = views.http1
        self.http2 = views.http2
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

output = Output()
response = {'ok': False, 'replacement': None}
try:
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        source = 'def __spider_script(api):\n' + textwrap.indent(request['script'] or 'pass', '    ')
        namespace = {}
        exec(compile(source, '<inspection>', 'exec'), namespace)
        result = None if request.get('validate_only') else namespace['__spider_script'](Api(request))
        if isinstance(result, str):
            result = result.encode()
        if result is not None and not isinstance(result, (bytes, bytearray, memoryview)):
            raise TypeError('script must return None, str, bytes, bytearray, or memoryview')
        if result is not None and len(result) > 1024 * 1024:
            raise ValueError('replacement exceeds 1 MiB')
        response.update(ok=True, replacement=None if result is None else base64.b64encode(result).decode())
except BaseException:
    response['error'] = traceback.format_exc(limit=8)[-12000:]
response['logs'] = output.text.splitlines()
json.dump(response, sys.stdout)
