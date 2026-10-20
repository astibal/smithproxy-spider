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

function frame(type, flags, stream, data) {
  const result = new Uint8Array(9 + data.length);
  result[0] = data.length >>> 16; result[1] = data.length >>> 8; result[2] = data.length;
  result[3] = type; result[4] = flags;
  new DataView(result.buffer).setUint32(5, stream);
  result.set(data, 9); return result;
}
const tuple = {sessionId: 'h2', sourceAddress: '192.0.2.10', sourcePort: 40194,
  destinationAddress: '198.51.100.20', destinationPort: 80, timestampMs: 1700000000000};
const header = (side, fields) => ({...tuple, side,
  payload: frame(1, 4, 1, Uint8Array.of(0x88)),
  enrichments: [{metadata: {operation: 'hpack.decode', source: {stream_id: 1},
    headers: fields.map(([name, value]) => ({name, value}))}}]});
const body = text.encode('hello decoded world');
const fixture = [
  {...tuple, side: 'L', payload: text.encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')},
  {...tuple, side: 'L', payload: frame(4, 0, 0, new Uint8Array())},
  {...tuple, side: 'R', payload: frame(4, 0, 0, new Uint8Array())},
  header('L', [[':method', 'GET'], [':scheme', 'http'], [':authority', 'example.com'], [':path', '/']]),
  header('R', [[':status', '200'], ['content-encoding', 'gzip'], ['content-length', '3']]),
  {...tuple, side: 'R', payload: frame(0, 1, 1, Uint8Array.of(1,2,3)),
    enrichments: [{payload: body, metadata: {operation: 'gzip.inflate', finished: true,
      source: {stream_id: 1, ranges: [[9,12]], decoded_ranges: [[0,body.length]]}}}]},
];
const transformed = pcapng.decodedRecords(fixture);
assert.equal(transformed.length, fixture.length);
assert.equal(new TextDecoder().decode(transformed.at(-1).payload.subarray(9)), 'hello decoded world');
assert(!new TextDecoder().decode(transformed[4].payload).includes('content-encoding'));
assert(new TextDecoder().decode(transformed[3].payload).includes(':authority'));
assert.deepEqual(fixture.at(-1).payload.subarray(9), Uint8Array.of(1,2,3), 'original untouched');
const huge = new Uint8Array(70000).fill(65);
const largeFixture = fixture.slice(0, -1).concat({...fixture.at(-1),
  enrichments: [{payload: huge, metadata: {operation: 'gzip.inflate', finished: true,
    source: {stream_id: 1, ranges: [[9,12]], decoded_ranges: [[0,huge.length]]}}}]});
const largeData = pcapng.decodedRecords(largeFixture).at(-1).payload;
let frameOffset = 0, bodyLength = 0;
while (frameOffset < largeData.length) {
  const size = largeData[frameOffset] * 65536 + largeData[frameOffset + 1] * 256 + largeData[frameOffset + 2];
  assert(size <= 16384);
  assert.equal(largeData[frameOffset + 4] & 1, frameOffset + 9 + size === largeData.length ? 1 : 0);
  bodyLength += size; frameOffset += size + 9;
}
assert.equal(bodyLength, huge.length);
const splitHeader = fixture[3].payload;
const splitFixture = [...fixture.slice(0, 3),
  {...fixture[3], payload: splitHeader.subarray(0, 5), enrichments: []},
  {...fixture[3], payload: splitHeader.subarray(5)}, ...fixture.slice(4)];
assert.deepEqual(pcapng.decodedRecords(splitFixture).map(r => r.payload), transformed.map(r => r.payload));
assert.throws(() => pcapng.decodedRecords(fixture.map((r, i) => i === 4 ? {...r, enrichments: []} : r)), /Missing decoded HPACK/);
assert.throws(() => pcapng.decodedRecords(fixture.slice(0, -1).concat({
  ...fixture.at(-1), enrichments: [{...fixture.at(-1).enrichments[0],
    metadata: {...fixture.at(-1).enrichments[0].metadata, finished: false}}]
})), /Incomplete decompressed/);
assert.throws(() => pcapng.decodedRecords([{...tuple, side: 'L', payload: text.encode('GET / HTTP/1.1\r\n\r\n')}]), /complete HTTP\/2/);
// Exercise the actual PCAP reader when installed; no fixture artifacts are persisted.
const {spawnSync} = require('child_process');
const decodedCapture = pcapng.build(fixture, {decoded: true});
const fs = require('fs'), os = require('os'), path = require('path');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'spider-pcap-test-'));
const capturePath = path.join(temp, 'decoded.pcapng');
fs.writeFileSync(capturePath, decodedCapture);
const tshark = spawnSync('tshark', ['-r', capturePath, '-d', 'tcp.port==80,http2', '-T', 'fields',
  '-e', 'http2.header.name', '-e', 'http2.header.value', '-e', 'http2.data.data'],
  {env: {...process.env, WIRESHARK_CONFIG_DIR: temp}});
fs.unlinkSync(capturePath);
fs.rmdirSync(temp);
if (!tshark.error) {
  assert.equal(tshark.status, 0, tshark.stderr.toString());
  const output = tshark.stdout.toString();
  assert(output.includes(':authority') && output.includes('example.com'), output);
  assert(!output.includes('content-encoding'), output);
  assert(output.includes(Buffer.from(body).toString('hex')), output);
}
console.log('pcapng_test: decoded H2 literals, body, fail-closed and tshark checks passed');
