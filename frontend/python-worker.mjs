import {loadPyodide} from 'https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.mjs';

const pyodideReady = loadPyodide();

const harness = String.raw`
import base64, json, textwrap, traceback

logs = []

class Api:
    def __init__(self):
        self.bytes = base64.b64decode(_spider_content, validate=True)
        self.text = self.bytes.decode("utf-8", errors="replace")
        self.side = _spider_side
        self.session_id = _spider_session_id
        self.session_label = _spider_session_label
        l7 = json.loads(_spider_l7)
        self.l7_state = l7.get("state", "unavailable")
        self.l7_ranges = [tuple(value) for value in l7.get("ranges", [])]
        self.l7_encodings = list(l7.get("encodings", []))
        self.l7_bytes = bytes(l7.get("bytes", []))

    def print(self, *values):
        logs.append(" ".join(str(value) for value in values))

    def hexdump(self, limit=256, width=16):
        data = self.bytes[:max(0, int(limit))]
        rows = []
        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hexa = " ".join(f"{value:02x}" for value in chunk)
            text = "".join(chr(value) if 32 <= value < 127 else "." for value in chunk)
            rows.append(f"{offset:08x}  {hexa:<{width * 3 - 1}}  |{text}|")
        return "\n".join(rows)

try:
    api = Api()
    source = "def __spider_script(api):\n" + textwrap.indent(_spider_script, "    ")
    namespace = {"print": api.print}
    exec(compile(source, "<spider-script>", "exec"), namespace)
    result = namespace["__spider_script"](api)
    if result is None:
        replacement = None
    elif isinstance(result, str):
        replacement = base64.b64encode(result.encode()).decode()
    elif isinstance(result, (bytes, bytearray, memoryview)):
        replacement = base64.b64encode(bytes(result)).decode()
    else:
        raise TypeError("script must return None, str, bytes, bytearray, or memoryview")
    response = {"ok": True, "logs": logs, "replacement": replacement}
except BaseException as error:
    response = {"ok": False, "logs": logs,
                "error": "".join(traceback.format_exception_only(type(error), error)).strip()}

response
`;

try {
  const pyodide = await pyodideReady;
  self.postMessage({type: 'ready'});
  self.onmessage = async ({data}) => {
    const {id} = data;
    try {
      pyodide.globals.set('_spider_script', data.script);
      pyodide.globals.set('_spider_content', data.content);
      pyodide.globals.set('_spider_side', data.side);
      pyodide.globals.set('_spider_session_id', data.sessionId);
      pyodide.globals.set('_spider_session_label', data.sessionLabel);
      pyodide.globals.set('_spider_l7', JSON.stringify(data.l7 || {}));
      const proxy = await pyodide.runPythonAsync(harness);
      const result = proxy.toJs({dict_converter: Object.fromEntries});
      proxy.destroy();
      self.postMessage({id, ...result});
    } catch (error) {
      self.postMessage({id, ok: false, logs: [], error: `${error.name}: ${error.message}`});
    }
  };
} catch (error) {
  self.postMessage({type: 'init-error', error: `${error.name}: ${error.message}`});
}
