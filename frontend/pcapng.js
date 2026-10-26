(function (root) {
  'use strict';

  const encoder = new TextEncoder();
  const align4 = value => (value + 3) & ~3;
  const concat = parts => {
    const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.length; }
    return result;
  };
  function literalString(text) {
    const bytes = encoder.encode(text), prefix = [];
    let length = bytes.length;
    if (length < 127) prefix.push(length);
    else {
      prefix.push(127); length -= 127;
      while (length >= 128) { prefix.push((length % 128) + 128); length = Math.floor(length / 128); }
      prefix.push(length);
    }
    return concat([Uint8Array.from(prefix), bytes]);
  }
  function hpack(fields) {
    return concat(fields.map(field => {
      if (field.name_encoding || field.value_encoding)
        throw new Error('Decoded export cannot reconstruct escaped header bytes.');
      return concat([Uint8Array.of(0), literalString(field.name), literalString(field.value)]);
    }));
  }
  function frame(type, flags, stream, bytes) {
    const head = new Uint8Array(9);
    head[0] = bytes.length >>> 16; head[1] = bytes.length >>> 8; head[2] = bytes.length;
    head[3] = type; head[4] = flags;
    new DataView(head.buffer).setUint32(5, stream);
    return concat([head, bytes]);
  }
  function frames(type, flags, stream, bytes) {
    const result = [];
    for (let offset = 0; offset < bytes.length || offset === 0; offset += 16384) {
      const last = offset + 16384 >= bytes.length;
      result.push(frame(type === 1 && offset ? 9 : type,
        type === 1 ? ((offset ? 0 : flags & 1) | (last ? 4 : 0)) : (last ? flags : flags & ~1),
        stream, bytes.subarray(offset, offset + 16384)));
    }
    return concat(result);
  }

  // Rebuild complete retained H2 directions. Never splice decoded bytes into raw frame lengths.
  function decodedRecords(records) {
    const groups = new Map(), output = [];
    records.forEach((record, index) => {
      const key = JSON.stringify([record.sessionId, record.side]);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push({...record, index});
    });
    for (const group of groups.values()) {
      let base = 0;
      const edits = [], headers = [];
      for (const record of group) {
        record.start = base; base += record.payload.length; record.end = base;
        for (const item of record.enrichments || []) {
          const m = item.metadata || {};
          if (m.operation === 'hpack.decode') headers.push({record, m, used: false});
          if (!['gzip.inflate', 'deflate.inflate'].includes(m.operation)) continue;
          const ranges = m.source?.ranges, decoded = m.source?.decoded_ranges;
          if (!ranges?.length || !decoded || ranges.length !== decoded.length)
            throw new Error('Decoded export needs exact inflate ranges; capture fresh traffic.');
          let next = 0;
          ranges.forEach(([a, b], i) => {
            const [c, d] = decoded[i];
            if (![a,b,c,d].every(Number.isSafeInteger) || a < 0 || b <= a ||
                b > record.payload.length || c !== next || d < c || d > item.payload.length)
              throw new Error('Invalid inflate range metadata.');
            edits.push({start: record.start + a, end: record.start + b,
              bytes: item.payload.subarray(c, d), stream: m.source.stream_id, finished: m.finished, used: false});
            next = d;
          });
          if (next !== item.payload.length) throw new Error('Incomplete inflate range metadata.');
        }
      }
      const wire = concat(group.map(r => r.payload));
      const preface = encoder.encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
      let pos = 0, pending = null;
      const parsed = [];
      if (wire.length >= preface.length && preface.every((b, i) => wire[i] === b)) {
        parsed.push({start: 0, end: preface.length, bytes: preface}); pos = preface.length;
      }
      while (pos < wire.length) {
        if (pos + 9 > wire.length) throw new Error('Incomplete H2 frame in retained capture.');
        const size = wire[pos] * 65536 + wire[pos + 1] * 256 + wire[pos + 2];
        const end = pos + 9 + size, type = wire[pos + 3], flags = wire[pos + 4];
        const stream = new DataView(wire.buffer).getUint32(pos + 5) & 0x7fffffff;
        if (end > wire.length || type > 9) throw new Error('Decoded export currently requires complete HTTP/2 frames.');
        const f = {start: pos, end, type, flags, stream, bytes: wire.subarray(pos, end)};
        if (pending && (type !== 9 || stream !== pending.stream))
          throw new Error('Missing H2 header continuation.');
        if (type === 5) throw new Error('Decoded PUSH_PROMISE export is not supported yet.');
        if (type === 1) { pending = f; pending.bytes = new Uint8Array(); }
        if (type === 1 || type === 9) {
          if (!pending) throw new Error('Missing H2 header block start.');
          if (flags & 4) {
            const owner = group.find(r => end > r.start && end <= r.end);
            const header = headers.find(h => !h.used && h.record === owner && h.m.source?.stream_id === stream);
            if (!header) throw new Error(`Missing decoded HPACK headers for stream ${stream}; capture with inspection active from the start.`);
            header.used = true; pending.header = header.m.headers; pending.end = end;
            parsed.push(pending); pending = null;
          }
        } else parsed.push(f);
        pos = end;
      }
      if (pending) throw new Error('Incomplete H2 header block.');
      const decodedStreams = new Set(edits.map(e => e.stream));
      for (const stream of decodedStreams) {
        if (!stream || !edits.some(e => e.stream === stream && e.finished))
          throw new Error(`Incomplete decompressed body on stream ${stream}.`);
        if (!parsed.some(f => f.header && f.stream === stream &&
            f.header.some(h => h.name === 'content-encoding')))
          throw new Error(`Missing content-encoding headers for stream ${stream}.`);
      }
      for (const f of parsed) {
        if (f.header) {
          const fields = decodedStreams.has(f.stream)
            ? f.header.filter(h => !['content-encoding', 'content-length'].includes(h.name)) : f.header;
          f.bytes = frames(1, f.flags, f.stream, hpack(fields));
        } else if (f.type === 0 && decodedStreams.has(f.stream)) {
          const pad = f.flags & 8 ? wire[f.start + 9] : 0;
          const start = f.start + 9 + (f.flags & 8 ? 1 : 0), end = f.end - pad;
          let cursor = start;
          const parts = [];
          for (const edit of edits.filter(e => e.stream === f.stream && e.start >= start && e.end <= end)) {
            if (edit.start !== cursor || edit.used) throw new Error('Incomplete compressed DATA coverage.');
            parts.push(edit.bytes); cursor = edit.end; edit.used = true;
          }
          if (cursor !== end) throw new Error('Missing decompression data for an H2 DATA frame.');
          f.bytes = frames(0, f.flags & 1, f.stream, concat(parts));
        }
        const owner = group.find(r => f.end > r.start && f.end <= r.end);
        output.push({...owner, payload: f.bytes, order: f.end});
      }
      if (edits.some(e => !e.used)) throw new Error('Inflate ranges do not align with H2 DATA frames.');
    }
    return output.sort((a, b) => a.index - b.index || a.order - b.order);
  }

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

  function build(records, {decoded = false} = {}) {
    if (decoded) records = decodedRecords(records);
    const chunks = [];
    const comment = encoder.encode(`Spider Synthetic${decoded ? '+Decoded' : ''}: reconstructed TCP, not an original packet capture.${decoded ? ' H2 headers re-encoded as HPACK literals; available complete gzip/deflate bodies inflated.' : ' Retained application bytes unchanged.'}`);
    const section = new Uint8Array(16 + 4 + align4(comment.length) + 4), sectionView = new DataView(section.buffer);
    sectionView.setUint32(0, 0x1a2b3c4d, true); sectionView.setUint16(4, 1, true);
    sectionView.setUint16(6, 0, true); sectionView.setBigInt64(8, -1n, true);
    sectionView.setUint16(16, 1, true); sectionView.setUint16(18, comment.length, true);
    section.set(comment, 20);
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
      // Both IPv4 and IPv6 lengths must fit, including synthetic TCP/IP headers.
      for (let offset = 0; offset < record.payload.length || offset === 0; offset += 16384) {
        const payload = record.payload.subarray(offset, offset + 16384);
        emit(state, record.side !== 'R', payload, timestamp, payload.length ? 0x18 : 0x10);
      }
    }
    const size = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const output = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
    return output;
  }

  const api = Object.freeze({build, decodedRecords});
  root.SpiderPcapng = api;
  if (typeof module !== 'undefined') module.exports = api;
})(globalThis);
