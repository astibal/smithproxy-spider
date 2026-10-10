const byId = id => document.getElementById(id);
const backend = byId('backend'), token = byId('token'), status = byId('status');
const chain = byId('chain'), events = byId('events');
const sessions = byId('sessions');
const historyList = byId('history-list'), sessionDetail = byId('session-detail');
const smithproxyUrl = byId('smithproxy-url'), smithproxyKey = byId('smithproxy-key');
const smithproxyVerify = byId('smithproxy-verify'), configureStatus = byId('configure-status');
let revision = 0, timer, eventRecords = [], historyRecords = [], selectedSessionId = null;
let payloadRecords = [], selectedPayload = null, payloadBytes = new Uint8Array(), scriptSlot = 1;
let eventSocket = null, reconnectTimer = null, followPayload = true, liveEdit = false;
let replacementBase64 = null;
const eventFilters = {ping: false, sessions: true, status: true, other: true};
const defaultScript = `// api.bytes        Uint8Array with the original payload
// api.text         UTF-8 decoded view
// api.side         "L" (client) or "R" (server)
// api.sessionId    Smithproxy session identifier
// api.sessionLabel endpoints and detected protocol
// api.print(...)   append to Script output
//
// Return undefined/null to keep the payload unchanged.
// Return a string, Uint8Array, or ArrayBuffer to replace it.

api.print(api.sessionId, api.side, api.bytes.length + " bytes");
return undefined;
`;

const suggestedBackend = `${location.protocol}//${location.hostname}:18080`;
backend.value = localStorage.getItem('spider-backend') || suggestedBackend;
token.value = sessionStorage.getItem('spider-token') || '';
smithproxyUrl.value = localStorage.getItem('smithproxy-url') || smithproxyUrl.value;
smithproxyVerify.checked = localStorage.getItem('smithproxy-verify') !== 'false';
const savedSidebarWidth = Number(localStorage.getItem('spider-sidebar-width'));
if (savedSidebarWidth >= 280) byId('sidebar').style.width = `${savedSidebarWidth}px`;
if ('ResizeObserver' in window) {
  new ResizeObserver(entries => {
    if (window.innerWidth > 800) {
      localStorage.setItem('spider-sidebar-width', String(Math.round(entries[0].contentRect.width)));
    }
  }).observe(byId('sidebar'));
}
const workbenchLayout = byId('workbench-layout');
const savedPayloadPane = Number(localStorage.getItem('spider-payload-pane'));
const savedCodeSize = Number(localStorage.getItem('spider-code-size'));
let codeSize = savedCodeSize >= 11 && savedCodeSize <= 22 ? savedCodeSize : 13;
if (savedPayloadPane >= 20 && savedPayloadPane <= 75) {
  workbenchLayout.style.setProperty('--payload-pane', `${savedPayloadPane}%`);
}
workbenchLayout.style.setProperty('--code-size', `${codeSize}px`);

const baseUrl = () => backend.value.replace(/\/$/, '');
function tokenValue() {
  const value = token.value.trim();
  if (/[^\x20-\x7e]/.test(value)) {
    throw new Error('Token contains masked bullets or other non-ASCII characters; paste the actual token from the runner status');
  }
  return value;
}
const headers = () => ({'X-Spider-Token': tokenValue()});

function eventCategory(event) {
  if (event.action === 'ping') return 'ping';
  if (event.action === 'spider-smithproxy-status') return 'status';
  if (['access-request', 'connection-content', 'connection-start',
       'connection-stop', 'connection-info', 'neighbor'].includes(event.action)) return 'sessions';
  return 'other';
}

function renderEvents() {
  events.textContent = eventRecords
    .filter(record => eventFilters[eventCategory(record.event)])
    .slice().reverse()
    .map(record => `r${record.revision} ${JSON.stringify(record.event, null, 2)}`)
    .join('\n\n');
}

function decodeBase64(value) {
  const binary = atob(value || '');
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function encodeHex(bytes) {
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.subarray(offset, offset + 16);
    const hex = Array.from(row, value => value.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const ascii = Array.from(row, value => value >= 32 && value < 127 ? String.fromCharCode(value) : '.').join('');
    rows.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`);
  }
  return rows.join('\n');
}

function renderPayload() {
  byId('payload-text').value = new TextDecoder().decode(payloadBytes);
  byId('payload-hex').textContent = encodeHex(payloadBytes);
  const info = selectedPayload?.event?.details?.info || {};
  byId('workbench-source').textContent = selectedPayload
    ? `r${selectedPayload.revision} · ${info.side || '?'} · ${payloadBytes.length} B · ${info.session || selectedPayload.event.id}`
    : `${payloadBytes.length} B sample`;
  byId('workbench-source').className = '';
  const pending = selectedPayload?.event?.decision?.state === 'pending' && !selectedPayload.decided;
  byId('accept-payload').disabled = !pending;
  byId('accept-session').disabled = !pending;
  byId('discard-payload').disabled = !pending;
  byId('replace-payload').disabled = !pending || replacementBase64 === null;
}

function setPayloadMode(mode) {
  const hex = mode === 'hex';
  byId('payload-text').hidden = hex;
  byId('payload-hex').hidden = !hex;
  for (const button of document.querySelectorAll('#payload-modes button')) {
    button.setAttribute('aria-pressed', String(button.dataset.mode === mode));
  }
  localStorage.setItem('spider-payload-mode', mode);
}

function setCodeSize(next) {
  codeSize = Math.max(11, Math.min(22, next));
  workbenchLayout.style.setProperty('--code-size', `${codeSize}px`);
  localStorage.setItem('spider-code-size', String(codeSize));
}

function setPayloadPane(clientX) {
  const bounds = workbenchLayout.getBoundingClientRect();
  const percent = Math.max(20, Math.min(75, (clientX - bounds.left) / bounds.width * 100));
  workbenchLayout.style.setProperty('--payload-pane', `${percent}%`);
  localStorage.setItem('spider-payload-pane', percent.toFixed(1));
}

function renderPayloadList() {
  const list = byId('payload-list');
  byId('payload-count').textContent = payloadRecords.length;
  list.replaceChildren();
  if (!payloadRecords.length) {
    list.textContent = 'none';
    list.className = 'payload-list empty';
    return;
  }
  list.className = 'payload-list';
  for (const record of payloadRecords) {
    const info = record.event.details?.info || {};
    const size = Math.floor((info.content?.length || 0) * 3 / 4);
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `payload-row${record === selectedPayload ? ' selected' : ''}` +
      `${record.event.decision?.state === 'pending' && !record.decided ? ' pending' : ''}` +
      `${record.decided ? ' decided' : ''}`;
    row.innerHTML = `<span>r${record.revision}</span><b>${escapeHtml(info.side || '?')}</b>` +
      `<span>${escapeHtml(formatBytes(size) || `${size} B`)}</span>` +
      `<span>${escapeHtml(info.session || record.event.id || 'unlabelled')}</span>`;
    row.onclick = () => selectPayload(record, false);
    list.append(row);
  }
  if (followPayload) list.scrollTop = list.scrollHeight;
}

function selectPayload(record, follow = false) {
  selectedPayload = record;
  followPayload = follow;
  byId('follow-payload').setAttribute('aria-pressed', String(followPayload));
  if (!selectedPayload) {
    byId('workbench-source').textContent = 'no connection-content captured yet';
    byId('workbench-source').className = 'empty';
    return;
  }
  payloadBytes = decodeBase64(selectedPayload.event.details?.info?.content);
  replacementBase64 = null;
  byId('replacement-text').value = '';
  renderPayload();
  renderPayloadList();
}

function ingestEvent(record) {
  if (!record || !record.event || record.revision <= revision) return;
  revision = record.revision;
  eventRecords.push(record);
  if (eventRecords.length > 2000) eventRecords = eventRecords.slice(-2000);
  if (record.event.action === 'connection-content' &&
      typeof record.event.details?.info?.content === 'string') {
    payloadRecords.push(record);
    if (payloadRecords.length > 2000) payloadRecords = payloadRecords.slice(-2000);
    if (followPayload || !selectedPayload) selectPayload(record, true);
    else renderPayloadList();
  }
  renderEvents();
}

function loadScriptSlot(number) {
  scriptSlot = number;
  byId('script-editor').value = localStorage.getItem(`spider-script-${number}`) || defaultScript;
  for (const button of document.querySelectorAll('#script-slots button')) {
    button.setAttribute('aria-pressed', String(Number(button.dataset.slot) === number));
  }
}

function runScript() {
  const worker = new Worker('script-worker.js');
  const scriptStatus = byId('script-status');
  const scriptOutput = byId('script-output');
  scriptStatus.textContent = 'running…';
  scriptStatus.className = '';
  byId('run-script').disabled = true;
  const timeout = setTimeout(() => {
    worker.terminate();
    scriptStatus.textContent = 'stopped after 2 s';
    scriptStatus.className = 'error';
    scriptOutput.textContent = 'Script exceeded the execution limit.';
    byId('run-script').disabled = false;
  }, 2000);
  worker.onmessage = ({data}) => {
    clearTimeout(timeout);
    worker.terminate();
    byId('run-script').disabled = false;
    scriptOutput.textContent = [...data.logs, ...(data.error ? [data.error] : [])].join('\n');
    if (!data.ok) {
      scriptStatus.textContent = 'failed';
      scriptStatus.className = 'error';
      byId('replacement-text').value = '';
      replacementBase64 = null;
      renderPayload();
      return;
    }
    if (data.replacement === null) {
      scriptStatus.textContent = 'unchanged';
      scriptStatus.className = 'ok';
      byId('replacement-text').value = '';
      replacementBase64 = null;
    } else {
      const replacement = decodeBase64(data.replacement);
      replacementBase64 = data.replacement;
      scriptStatus.textContent = `replace · ${replacement.length} B`;
      scriptStatus.className = 'ok';
      byId('replacement-text').value = new TextDecoder().decode(replacement);
    }
    renderPayload();
  };
  const info = selectedPayload?.event?.details?.info || {};
  worker.postMessage({script: byId('script-editor').value, bytes: Array.from(payloadBytes),
    side: info.side || '', sessionId: selectedPayload?.event?.id || '', sessionLabel: info.session || ''});
}

function formatTime(value) {
  return value ? new Date(value).toLocaleString() : '—';
}

function formatDuration(start, end) {
  if (!start) return '—';
  const milliseconds = Math.max(0, (end || Date.now()) - start);
  if (milliseconds < 1000) return `${milliseconds} ms`;
  if (milliseconds < 60000) return `${(milliseconds / 1000).toFixed(1)} s`;
  return `${Math.floor(milliseconds / 60000)}m ${Math.floor((milliseconds % 60000) / 1000)}s`;
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return null;
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

function detailRow(label, value, extraClass = '') {
  if (value === undefined || value === null || value === '') return '';
  return `<div class="detail-row ${extraClass}"><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function renderSessionDetail(detail) {
  const info = detail.last_event?.details?.info || {};
  const tls = info.tls || {};
  const l7 = info.l7 || {};
  const urls = Array.isArray(l7.details) ? l7.details : [];
  const signatures = Array.isArray(l7.signatures) ? l7.signatures : [];
  const ja4h = Array.isArray(l7.ja4h) ? l7.ja4h : [];
  const eventTimeline = (detail.events || []).map(event => {
    const timestamp = formatTime(event.spider_received_at_ms);
    return `<details class="timeline-event"><summary><b>${escapeHtml(event.action || 'event')}</b><time>${escapeHtml(timestamp)}</time></summary><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre></details>`;
  }).join('');
  sessionDetail.innerHTML =
    `<div class="detail-hero"><span class="state ${escapeHtml(detail.state)}">${escapeHtml(detail.state)}</span><strong>${escapeHtml(tls.sni || l7.app || detail.label || detail.id)}</strong><small>${escapeHtml(detail.id)}</small></div>` +
    `<dl class="detail-grid">` +
      detailRow('Started', formatTime(detail.started_at_ms)) +
      detailRow('Ended', detail.ended_at_ms ? formatTime(detail.ended_at_ms) : 'active') +
      detailRow('Duration', formatDuration(detail.started_at_ms, detail.ended_at_ms)) +
      detailRow('Events', detail.event_count) +
      detailRow('Connection', info.session || detail.label, 'wide') +
      detailRow('SNI', tls.sni) +
      detailRow('Application', l7.app) +
      detailRow('Policy', info.policy) +
      detailRow('Uploaded', formatBytes(info.bytes_up)) +
      detailRow('Downloaded', formatBytes(info.bytes_down)) +
      detailRow('JA4 client', info.ja4_ch, 'wide') +
      detailRow('JA4 server', info.ja4_sh, 'wide') +
    `</dl>` +
    (urls.length ? `<div class="detail-block"><h3>Requests</h3>${urls.map(url => `<code>${escapeHtml(url)}</code>`).join('')}</div>` : '') +
    (signatures.length ? `<div class="detail-block"><h3>Signatures</h3><div class="chips">${signatures.map(value => `<span>${escapeHtml(value)}</span>`).join('')}</div></div>` : '') +
    (ja4h.length ? `<div class="detail-block"><h3>JA4H</h3>${ja4h.map(value => `<code>${escapeHtml(value)}</code>`).join('')}</div>` : '') +
    `<div class="detail-block"><h3>Event timeline</h3>${eventTimeline || '<span class="empty">none</span>'}</div>` +
    `<details class="raw-detail"><summary>Raw JSON</summary><pre>${escapeHtml(JSON.stringify(detail, null, 2))}</pre></details>`;
  sessionDetail.className = 'session-detail-content';
}

function sessionSubtitle(item) {
  const info = item.last_event?.details?.info || {};
  const sni = info.tls?.sni;
  const app = info.l7?.app;
  return [item.label || 'unlabelled', sni, app].filter(Boolean).join(' · ');
}

function renderHistory() {
  byId('history-count').textContent = `${historyRecords.length}`;
  historyList.replaceChildren();
  if (historyRecords.length === 0) {
    historyList.textContent = 'none';
    historyList.className = 'history-list empty';
    return;
  }
  historyList.className = 'history-list';
  for (const item of historyRecords) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `history-row ${item.state === 'completed' ? 'completed' : 'active'}${item.id === selectedSessionId ? ' selected' : ''}`;
    row.innerHTML = `<span><b>${escapeHtml(item.id)}</b><i>${escapeHtml(item.state)}</i></span>` +
      `<small>${escapeHtml(sessionSubtitle(item))}</small>` +
      `<time>${escapeHtml(formatTime(item.updated_at_ms))} · ${item.event_count} events</time>`;
    row.onclick = () => selectSession(item.id);
    historyList.append(row);
  }
}

async function loadSessionDetail() {
  if (!selectedSessionId) return;
  const reload = byId('reload-detail');
  reload.disabled = true;
  try {
    const response = await fetch(`${baseUrl()}/api/session?id=${encodeURIComponent(selectedSessionId)}`,
      {headers: headers()});
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    renderSessionDetail(body);
    byId('detail-title').textContent = `Session detail · ${selectedSessionId}`;
  } catch (error) {
    sessionDetail.textContent = error.message;
    sessionDetail.className = 'error';
  } finally {
    reload.disabled = false;
  }
}

function showTab(tabId) {
  for (const panel of document.querySelectorAll('.tab-panel')) panel.hidden = panel.id !== tabId;
  for (const button of document.querySelectorAll('.tabs button')) {
    button.setAttribute('aria-selected', String(button.dataset.tab === tabId));
  }
}

function selectSession(id) {
  selectedSessionId = id;
  showTab('history-tab');
  renderHistory();
  loadSessionDetail();
}

function socketSend(message) {
  if (eventSocket?.readyState !== WebSocket.OPEN) return false;
  eventSocket.send(JSON.stringify(message));
  return true;
}

function connectEventSocket() {
  clearTimeout(reconnectTimer);
  if (eventSocket) eventSocket.close();
  const url = new URL(baseUrl());
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = `${url.pathname.replace(/\/$/, '')}/api/events/ws`;
  const protocols = tokenValue() ? ['spider', tokenValue()] : ['spider'];
  const socket = new WebSocket(url, protocols);
  eventSocket = socket;
  socket.onopen = () => {
    socket.send(JSON.stringify({type: 'subscribe', after: revision}));
    socket.send(JSON.stringify({type: 'live-edit', enabled: liveEdit}));
  };
  socket.onmessage = message => {
    const data = JSON.parse(message.data);
    if (data.type === 'event') ingestEvent({revision: data.revision, event: data.event});
    if (data.type === 'gap') {
      status.textContent = `stream gap · oldest r${data.oldest_available}`;
      status.className = 'error';
    }
  };
  socket.onerror = () => socket.close();
  socket.onclose = () => {
    if (eventSocket !== socket) return;
    status.textContent = 'reconnecting event stream…';
    status.className = 'error';
    reconnectTimer = setTimeout(connectEventSocket, 1000);
  };
}

function decideSelected(action) {
  const decisionId = selectedPayload?.event?.decision?.id;
  if (!decisionId) return;
  const message = {type: 'decision', decision_id: decisionId, action};
  if (action === 'replace') {
    if (replacementBase64 === null) return;
    message.content = replacementBase64;
  }
  if (!socketSend(message)) return;
  const sessionId = selectedPayload.event.id;
  if (action === 'accept-session') {
    for (const record of payloadRecords) {
      if (record.event.id === sessionId) record.decided = true;
    }
  } else {
    selectedPayload.decided = true;
  }
  renderPayload();
  renderPayloadList();
}

async function poll() {
  try {
    const [statusResponse, sessionResponse, historyResponse] = await Promise.all([
      fetch(`${baseUrl()}/api/status`, {headers: headers()}),
      fetch(`${baseUrl()}/api/sessions`, {headers: headers()}),
      fetch(`${baseUrl()}/api/session-history`, {headers: headers()}),
    ]);
    if (!statusResponse.ok) throw new Error(`status HTTP ${statusResponse.status}`);
    if (!sessionResponse.ok) throw new Error(`sessions HTTP ${sessionResponse.status}`);
    if (!historyResponse.ok) throw new Error(`history HTTP ${historyResponse.status}`);
    const [current, sessionData, historyData] = await Promise.all([
      statusResponse.json(), sessionResponse.json(), historyResponse.json(),
    ]);
    historyRecords = historyData.sessions;
    renderHistory();
    const proxy = current.smithproxy || {};
    const callback = current.last_callback || {};
    const callbackAge = callback.received_at_ms
      ? `${Math.max(0, Math.floor((Date.now() - callback.received_at_ms) / 1000))}s ago`
      : 'never';
    const leaseExpiry = proxy.lease_expires_at
      ? new Date(proxy.lease_expires_at * 1000).toLocaleTimeString()
      : 'n/a';
    chain.textContent =
      `PC frontend       connected\n` +
      `Spider backend    connected · r${current.revision}\n` +
      `Smithproxy API    ${proxy.state || 'unknown'}\n` +
      `Webhook API       ${proxy.webhook_api || 'n/a'}\n` +
      `Lease expires     ${leaseExpiry}\n` +
      `Callbacks         ${current.callbacks_received} · last ${callback.action || 'n/a'} ${callbackAge}` +
      `${proxy.detail ? `\n${proxy.detail}` : ''}`;
    if (sessionData.sessions.length === 0) {
      sessions.textContent = 'none';
      sessions.className = 'empty';
    } else {
      sessions.className = '';
      sessions.replaceChildren();
      for (const item of sessionData.sessions.sort((a, b) => b.revision - a.revision)) {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'session';
        row.innerHTML = `<b>${escapeHtml(item.id)}</b> ${escapeHtml(item.state)}<br><span>${escapeHtml(item.label || 'unlabelled')}</span>`;
        row.onclick = () => selectSession(item.id);
        sessions.append(row);
      }
    }
    status.textContent = `${eventSocket?.readyState === WebSocket.OPEN ? 'live' : 'connecting'} · r${revision}`;
    status.className = 'ok';
  } catch (error) {
    status.textContent = `offline · ${error.message}`;
    status.className = 'error';
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

function connect() {
  try {
    tokenValue();
  } catch (error) {
    sessionStorage.removeItem('spider-token');
    token.value = '';
    status.textContent = `offline · ${error.message}`;
    status.className = 'error';
    clearInterval(timer);
    clearTimeout(reconnectTimer);
    if (eventSocket) eventSocket.close();
    return;
  }
  localStorage.setItem('spider-backend', backend.value);
  sessionStorage.setItem('spider-token', tokenValue());
  revision = 0;
  eventRecords = [];
  payloadRecords = [];
  selectedPayload = null;
  historyRecords = [];
  selectedSessionId = null;
  events.textContent = '';
  renderPayloadList();
  clearInterval(timer);
  connectEventSocket();
  poll();
  timer = setInterval(poll, 1000);
}

async function configureSmithproxy() {
  configureStatus.textContent = 'connecting…';
  configureStatus.className = '';
  try {
    const response = await fetch(`${baseUrl()}/api/config/smithproxy`, {
      method: 'POST',
      headers: {...headers(), 'Content-Type': 'application/json'},
      body: JSON.stringify({url: smithproxyUrl.value, api_key: smithproxyKey.value,
                            verify_tls: smithproxyVerify.checked}),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    localStorage.setItem('smithproxy-url', smithproxyUrl.value);
    localStorage.setItem('smithproxy-verify', smithproxyVerify.checked);
    smithproxyKey.value = '';
    configureStatus.textContent = 'configuration accepted';
    configureStatus.className = 'ok';
  } catch (error) {
    configureStatus.textContent = error.message;
    configureStatus.className = 'error';
  }
}

byId('connect').onclick = connect;
byId('configure').onclick = configureSmithproxy;
byId('toggle-token').onclick = () => {
  const visible = token.type === 'text';
  token.type = visible ? 'password' : 'text';
  byId('toggle-token').title = visible ? 'Show token' : 'Hide token';
  byId('toggle-token').setAttribute('aria-label', visible ? 'Show token' : 'Hide token');
  token.focus();
};
byId('clear-token').onclick = () => {
  token.value = '';
  sessionStorage.removeItem('spider-token');
  token.focus();
};
for (const button of document.querySelectorAll('#event-filters button')) {
  if (!button.dataset.filter) continue;
  button.onclick = () => {
    const category = button.dataset.filter;
    eventFilters[category] = !eventFilters[category];
    button.setAttribute('aria-pressed', String(eventFilters[category]));
    renderEvents();
  };
}
byId('clear-events').onclick = () => {
  eventRecords = [];
  renderEvents();
};
for (const button of document.querySelectorAll('.tabs button')) {
  button.onclick = () => showTab(button.dataset.tab);
}
byId('reload-detail').onclick = loadSessionDetail;
byId('follow-payload').onclick = () => {
  followPayload = !followPayload;
  byId('follow-payload').setAttribute('aria-pressed', String(followPayload));
  if (followPayload && payloadRecords.length) selectPayload(payloadRecords[payloadRecords.length - 1], true);
};
byId('sample-payload').onclick = () => {
  selectedPayload = null;
  payloadBytes = new TextEncoder().encode('GET / HTTP/1.1\r\nHost: example.test\r\n\r\n');
  renderPayload();
};
byId('live-edit').onclick = () => {
  liveEdit = !liveEdit;
  byId('live-edit').setAttribute('aria-pressed', String(liveEdit));
  byId('live-edit').textContent = `Live edit: ${liveEdit ? 'on' : 'off'}`;
  socketSend({type: 'live-edit', enabled: liveEdit});
};
byId('accept-payload').onclick = () => decideSelected('accept');
byId('accept-session').onclick = () => decideSelected('accept-session');
byId('replace-payload').onclick = () => decideSelected('replace');
byId('discard-payload').onclick = () => decideSelected('discard');
byId('payload-text').oninput = event => {
  payloadBytes = new TextEncoder().encode(event.target.value);
  byId('payload-hex').textContent = encodeHex(payloadBytes);
};
for (const button of document.querySelectorAll('#payload-modes button')) {
  button.onclick = () => setPayloadMode(button.dataset.mode);
}
byId('font-smaller').onclick = () => setCodeSize(codeSize - 1);
byId('font-larger').onclick = () => setCodeSize(codeSize + 1);
const workbenchDivider = byId('workbench-divider');
workbenchDivider.onpointerdown = event => {
  workbenchDivider.setPointerCapture(event.pointerId);
  setPayloadPane(event.clientX);
};
workbenchDivider.onpointermove = event => {
  if (workbenchDivider.hasPointerCapture(event.pointerId)) setPayloadPane(event.clientX);
};
workbenchDivider.onkeydown = event => {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  const current = parseFloat(getComputedStyle(workbenchLayout).getPropertyValue('--payload-pane')) || 42;
  const next = Math.max(20, Math.min(75, current + (event.key === 'ArrowLeft' ? -2 : 2)));
  workbenchLayout.style.setProperty('--payload-pane', `${next}%`);
  localStorage.setItem('spider-payload-pane', String(next));
};
for (const button of document.querySelectorAll('#script-slots button')) {
  button.onclick = () => loadScriptSlot(Number(button.dataset.slot));
}
byId('script-editor').oninput = event => localStorage.setItem(`spider-script-${scriptSlot}`, event.target.value);
byId('run-script').onclick = runScript;
byId('reset-script').onclick = () => {
  localStorage.removeItem(`spider-script-${scriptSlot}`);
  loadScriptSlot(scriptSlot);
};
byId('clear-history').onclick = async () => {
  try {
    const response = await fetch(`${baseUrl()}/api/session-history`, {
      method: 'DELETE', headers: headers(),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    historyRecords = historyRecords.filter(item => item.state !== 'completed');
    if (!historyRecords.some(item => item.id === selectedSessionId)) {
      selectedSessionId = null;
      byId('detail-title').textContent = 'Session detail';
      sessionDetail.textContent = 'select a session';
      sessionDetail.className = 'empty';
      byId('reload-detail').disabled = true;
    }
    renderHistory();
  } catch (error) {
    sessionDetail.textContent = error.message;
    sessionDetail.className = 'error';
  }
};
loadScriptSlot(1);
setPayloadMode(localStorage.getItem('spider-payload-mode') === 'hex' ? 'hex' : 'ascii');
connect();
