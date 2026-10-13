'use strict';

const assert = require('assert');
const pcapng = require('../frontend/pcapng.js');

const text = new TextEncoder();
const capture = pcapng.build([
  {sessionId: 'ipv4', sourceAddress: '192.0.2.10', sourcePort: 40194,
   destinationAddress: '198.51.100.20', destinationPort: 443, side: 'L',
   payload: text.encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'), timestampMs: 1700000000000},
  {sessionId: 'ipv4', sourceAddress: '192.0.2.10', sourcePort: 40194,
   destinationAddress: '198.51.100.20', destinationPort: 443, side: 'R',
   payload: Uint8Array.of(0, 0, 0, 4, 1, 0, 0, 0, 0), timestampMs: 1700000000001},
  {sessionId: 'ipv6', sourceAddress: '[2001:db8::10]', sourcePort: 50000,
   destinationAddress: '[2001:db8::20]', destinationPort: 80, side: 'L',
   payload: text.encode('GET / HTTP/1.1\r\n\r\n'), timestampMs: 1700000000002},
]);

const view = new DataView(capture.buffer, capture.byteOffset, capture.byteLength);
assert.equal(view.getUint32(0, true), 0x0a0d0d0a, 'section header magic');
let offset = 0, enhancedPackets = 0;
while (offset < capture.length) {
  const type = view.getUint32(offset, true);
  const size = view.getUint32(offset + 4, true);
  assert(size >= 12 && size % 4 === 0, `valid block size at ${offset}`);
  assert.equal(view.getUint32(offset + size - 4, true), size, 'matching trailing block size');
  if (type === 6) ++enhancedPackets;
  offset += size;
}
assert.equal(offset, capture.length, 'blocks span complete capture');
assert.equal(enhancedPackets, 9, 'three handshakes plus three payload packets');

console.log(`pcapng_test: ${enhancedPackets} packets, ${capture.length} bytes`);
