(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.SpiderSxbn = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const decoder = new TextDecoder('utf-8', {fatal: true});
  const magic = 'SXBN001:';
  const prefixSize = 25;

  function ascii(bytes, start, end) {
    let result = '';
    for (let index = start; index < end; ++index) result += String.fromCharCode(bytes[index]);
    return result;
  }

  function parseHex(bytes, start, end, label) {
    const text = ascii(bytes, start, end);
    if (!/^[0-9a-fA-F]{8}$/.test(text)) throw new Error(`invalid SXBN ${label} length`);
    return Number.parseInt(text, 16);
  }

  function decode(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (!bytes.length) throw new Error('empty SXBN chain');
    const envelopes = [];
    let offset = 0;
    while (offset < bytes.length) {
      if (bytes.length - offset < prefixSize || ascii(bytes, offset, offset + magic.length) !== magic) {
        throw new Error('missing SXBN001 envelope');
      }
      if (bytes[offset + 16] !== 0x3a) throw new Error('invalid SXBN length separator');
      const jsonLength = parseHex(bytes, offset + 8, offset + 16, 'JSON');
      const payloadLength = parseHex(bytes, offset + 17, offset + 25, 'payload');
      const jsonStart = offset + prefixSize;
      const payloadStart = jsonStart + jsonLength;
      const end = payloadStart + payloadLength;
      if (end > bytes.length) throw new Error('truncated SXBN envelope');
      let metadata;
      try {
        metadata = JSON.parse(decoder.decode(bytes.subarray(jsonStart, payloadStart)));
      } catch (_) {
        throw new Error('invalid SXBN JSON metadata');
      }
      if (!metadata || Array.isArray(metadata) || typeof metadata !== 'object') {
        throw new Error('SXBN metadata must be an object');
      }
      envelopes.push({metadata, payload: bytes.slice(payloadStart, end)});
      offset = end;
    }
    return envelopes;
  }

  return {decode};
}));
