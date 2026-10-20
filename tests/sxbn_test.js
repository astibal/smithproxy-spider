'use strict';

const assert = require('assert');
const sxbn = require('../frontend/sxbn.js');
const encoder = new TextEncoder();

function envelope(metadata, payload = new Uint8Array()) {
  const json = encoder.encode(JSON.stringify(metadata));
  const prefix = encoder.encode(`SXBN001:${json.length.toString(16).padStart(8, '0')}:` +
                                payload.length.toString(16).padStart(8, '0'));
  const result = new Uint8Array(prefix.length + json.length + payload.length);
  result.set(prefix);
  result.set(json, prefix.length);
  result.set(payload, prefix.length + json.length);
  return result;
}

function concatenate(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

const wire = concatenate(
  envelope({type: 'event', key: 'event:7', revision: 7}, new Uint8Array([0, 1, 254, 255])),
  envelope({type: 'enrichment', source: {envelope: 'event:7', annotation: 1}}),
);
const decoded = sxbn.decode(wire.buffer);
assert.strictEqual(decoded.length, 2);
assert.strictEqual(decoded[0].metadata.revision, 7);
assert.deepStrictEqual([...decoded[0].payload], [0, 1, 254, 255]);
assert.strictEqual(decoded[1].metadata.type, 'enrichment');
assert.strictEqual(decoded[1].payload.length, 0);
assert.throws(() => sxbn.decode(wire.slice(0, -1)), /missing|truncated/);
assert.throws(() => sxbn.decode(new Uint8Array()), /empty/);
assert.throws(() => sxbn.decode(encoder.encode('SXBN001:zzzzzzzz:00000000')), /JSON length/);
assert.throws(() => sxbn.decode(encoder.encode('SXBN001:00000002:00000000[]')), /object/);
assert.throws(() => sxbn.decode(encoder.encode('SXBN001:00000001:00000000{')), /JSON metadata/);
assert.throws(() => sxbn.decode(encoder.encode('SXBN001:00000002;00000000{}')), /separator/);

const emptyPayload = sxbn.decode(envelope({type: 'event', revision: 8}));
assert.strictEqual(emptyPayload.length, 1);
assert.strictEqual(emptyPayload[0].payload.length, 0);

console.log('sxbn_test: chained binary envelopes decoded');
const roundtrip = sxbn.decode(sxbn.encode({event: {id: 'replay-ž'}}, Uint8Array.of(0, 128, 255)));
assert.deepStrictEqual(roundtrip[0].metadata, {event: {id: 'replay-ž'}});
assert.deepStrictEqual(roundtrip[0].payload, Uint8Array.of(0, 128, 255));
