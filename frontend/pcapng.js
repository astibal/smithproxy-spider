(function (root) {
  'use strict';

  const encoder = new TextEncoder();
  const align4 = value => (value + 3) & ~3;

  function ipv4(value) {
    const parts = String(value).split('.').map(Number);
    return parts.length === 4 && parts.every(part => Number.isInteger(part) && part >= 0 && part <= 255)
      ? Uint8Array.from(parts) : null;
  }

  function ipv6(value) {
    const text = String(value).split('%')[0];
    const halves = text.split('::');
    if (halves.length > 2) return null;
    const words = part => part ? part.split(':').flatMap(word => {
      const v4 = ipv4(word);
      return v4 ? [((v4[0] << 8) | v4[1]), ((v4[2] << 8) | v4[3])] : [parseInt(word, 16)];
    }) : [];
    const left = words(halves[0]), right = words(halves[1] || '');
    const missing = 8 - left.length - right.length;
    if (missing < 0 || (halves.length === 1 && missing !== 0) ||
        [...left, ...right].some(word => !Number.isInteger(word) || word < 0 || word > 0xffff)) return null;
    const all = [...left, ...Array(missing).fill(0), ...right];
    const result = new Uint8Array(16);
    all.forEach((word, index) => { result[index * 2] = word >> 8; result[index * 2 + 1] = word; });
    return result;
  }

  function checksum(parts) {
    let sum = 0, high = null;
    for (const part of parts) for (const byte of part) {
      if (high === null) high = byte;
      else { sum += (high << 8) | byte; high = null; sum = (sum & 0xffff) + (sum >>> 16); }
    }
    if (high !== null) sum += high << 8;
    while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return (~sum) & 0xffff;
  }

  function packet(flow, fromClient, payload, seq, ack, flags, ipId) {
    const cleanAddress = value => String(value).replace(/^\[|\]$/g, '');
    const source = cleanAddress(fromClient ? flow.sourceAddress : flow.destinationAddress);
    const destination = cleanAddress(fromClient ? flow.destinationAddress : flow.sourceAddress);
    const sourcePort = fromClient ? flow.sourcePort : flow.destinationPort;
    const destinationPort = fromClient ? flow.destinationPort : flow.sourcePort;
    const v4source = ipv4(source), v4destination = ipv4(destination);
    const v6source = v4source ? null : ipv6(source), v6destination = v4source ? null : ipv6(destination);
    if ((!v4source || !v4destination) && (!v6source || !v6destination)) return null;

    const tcp = new Uint8Array(20 + payload.length);
    const tcpView = new DataView(tcp.buffer);
    tcpView.setUint16(0, sourcePort); tcpView.setUint16(2, destinationPort);
    tcpView.setUint32(4, seq); tcpView.setUint32(8, ack);
    tcp[12] = 0x50; tcp[13] = flags; tcpView.setUint16(14, 65535);
    tcp.set(payload, 20);

    let network, etherType, pseudo;
    if (v4source) {
      network = new Uint8Array(20 + tcp.length);
      const view = new DataView(network.buffer);
      network[0] = 0x45; view.setUint16(2, network.length); view.setUint16(4, ipId & 0xffff);
      view.setUint16(6, 0x4000); network[8] = 64; network[9] = 6;
      network.set(v4source, 12); network.set(v4destination, 16);
      view.setUint16(10, checksum([network.subarray(0, 20)]));
      pseudo = new Uint8Array(12);
      pseudo.set(v4source, 0); pseudo.set(v4destination, 4); pseudo[9] = 6;
      new DataView(pseudo.buffer).setUint16(10, tcp.length);
      etherType = 0x0800;
    } else {
      network = new Uint8Array(40 + tcp.length);
      const view = new DataView(network.buffer);
      network[0] = 0x60; view.setUint16(4, tcp.length); network[6] = 6; network[7] = 64;
      network.set(v6source, 8); network.set(v6destination, 24);
      pseudo = new Uint8Array(40);
      pseudo.set(v6source, 0); pseudo.set(v6destination, 16);
      new DataView(pseudo.buffer).setUint32(32, tcp.length); pseudo[39] = 6;
      etherType = 0x86dd;
    }
    tcpView.setUint16(16, checksum([pseudo, tcp]));
    network.set(tcp, network.length - tcp.length);

    const ethernet = new Uint8Array(14 + network.length);
    const clientMac = Uint8Array.of(0x02, 0x53, 0x58, 0x00, 0x00, 0x01);
    const serverMac = Uint8Array.of(0x02, 0x53, 0x58, 0x00, 0x00, 0x02);
    ethernet.set(fromClient ? serverMac : clientMac, 0);
    ethernet.set(fromClient ? clientMac : serverMac, 6);
    new DataView(ethernet.buffer).setUint16(12, etherType);
    ethernet.set(network, 14);
    return ethernet;
  }

  function block(type, body) {
    const size = 12 + align4(body.length);
    const bytes = new Uint8Array(size);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, type, true); view.setUint32(4, size, true);
    bytes.set(body, 8); view.setUint32(size - 4, size, true);
    return bytes;
  }

  function enhancedPacket(bytes, timestampUs) {
    const body = new Uint8Array(20 + align4(bytes.length));
    const view = new DataView(body.buffer);
    const stamp = BigInt(Math.max(0, Math.floor(timestampUs)));
    view.setUint32(4, Number((stamp >> 32n) & 0xffffffffn), true);
    view.setUint32(8, Number(stamp & 0xffffffffn), true);
    view.setUint32(12, bytes.length, true); view.setUint32(16, bytes.length, true);
    body.set(bytes, 20);
    return block(6, body);
  }

  function build(records) {
    const chunks = [];
    const section = new Uint8Array(16), sectionView = new DataView(section.buffer);
    sectionView.setUint32(0, 0x1a2b3c4d, true); sectionView.setUint16(4, 1, true);
    sectionView.setUint16(6, 0, true); sectionView.setBigInt64(8, -1n, true);
    chunks.push(block(0x0a0d0d0a, section));
    const iface = new Uint8Array(8), ifaceView = new DataView(iface.buffer);
    ifaceView.setUint16(0, 1, true); ifaceView.setUint32(4, 0xffffffff, true);
    chunks.push(block(1, iface));

    const flows = new Map();
    let lastTimestamp = 0, ipId = 1;
    const emit = (state, fromClient, payload, timestamp, flags) => {
      const seq = fromClient ? state.clientSeq : state.serverSeq;
      const ack = fromClient ? state.serverSeq : state.clientSeq;
      const bytes = packet(state.flow, fromClient, payload, seq, ack, flags, ipId++);
      if (!bytes) return;
      lastTimestamp = Math.max(lastTimestamp + 1, timestamp);
      chunks.push(enhancedPacket(bytes, lastTimestamp));
      const advance = payload.length + ((flags & 0x02) ? 1 : 0) + ((flags & 0x01) ? 1 : 0);
      if (fromClient) state.clientSeq = (state.clientSeq + advance) >>> 0;
      else state.serverSeq = (state.serverSeq + advance) >>> 0;
    };

    for (const record of records) {
      let state = flows.get(record.sessionId);
      const timestamp = Number.isFinite(record.timestampMs) ? Math.floor(record.timestampMs * 1000) : lastTimestamp + 1000;
      if (!state) {
        state = {flow: record, clientSeq: 0x10000000, serverSeq: 0x20000000};
        flows.set(record.sessionId, state);
        emit(state, true, new Uint8Array(), timestamp - 3, 0x02);
        emit(state, false, new Uint8Array(), timestamp - 2, 0x12);
        emit(state, true, new Uint8Array(), timestamp - 1, 0x10);
      }
      emit(state, record.side !== 'R', record.payload, timestamp, record.payload.length ? 0x18 : 0x10);
    }
    const size = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
    return output;
  }

  const api = Object.freeze({build});
  root.SpiderPcapng = api;
  if (typeof module !== 'undefined') module.exports = api;
})(globalThis);
