'use strict';

const bytesToBase64 = bytes => {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
};

self.onmessage = ({data}) => {
  const logs = [];
  const l7Bytes = Uint8Array.from(data.l7?.bytes || []);
  const l7 = Object.freeze({
    state: data.l7?.state || 'unavailable',
    ranges: Object.freeze((data.l7?.ranges || []).map(range => Object.freeze([...range]))),
    encodings: Object.freeze([...(data.l7?.encodings || [])]),
    bytes: l7Bytes,
    text: new TextDecoder().decode(l7Bytes),
  });
  const enrichments = Object.freeze((data.enrichments || []).map(item => {
    const bytes = Uint8Array.from(item.bytes || []);
    return Object.freeze({
      metadata: Object.freeze(item.metadata || {}),
      bytes,
      text: new TextDecoder().decode(bytes),
    });
  }));
  const api = Object.freeze({
    bytes: Uint8Array.from(data.bytes),
    text: new TextDecoder().decode(Uint8Array.from(data.bytes)),
    side: data.side,
    sessionId: data.sessionId,
    sessionLabel: data.sessionLabel,
    l7,
    enrichments,
    print: (...values) => logs.push(values.map(value =>
      typeof value === 'string' ? value : JSON.stringify(value)).join(' ')),
  });
  try {
    const result = Function('api', `"use strict";\n${data.script}\n`)(api);
    let replacement = null;
    if (typeof result === 'string') replacement = new TextEncoder().encode(result);
    else if (result instanceof Uint8Array) replacement = result;
    else if (result instanceof ArrayBuffer) replacement = new Uint8Array(result);
    else if (result !== undefined && result !== null) {
      throw new TypeError('script must return string, Uint8Array, ArrayBuffer, null, or undefined');
    }
    self.postMessage({ok: true, logs, replacement: replacement && bytesToBase64(replacement)});
  } catch (error) {
    self.postMessage({ok: false, logs, error: `${error.name}: ${error.message}`});
  }
};
