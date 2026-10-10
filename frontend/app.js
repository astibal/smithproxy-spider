const byId = id => document.getElementById(id);
const backend = byId('backend'), token = byId('token'), status = byId('status');
const chain = byId('chain'), events = byId('events');
const sessions = byId('sessions');
const historyList = byId('history-list'), sessionDetail = byId('session-detail');
const smithproxyUrl = byId('smithproxy-url'), smithproxyKey = byId('smithproxy-key');
const smithproxyVerify = byId('smithproxy-verify'), configureStatus = byId('configure-status');
let revision = 0, timer, eventRecords = [], historyRecords = [], selectedSessionId = null;
let payloadRecords = [], selectedPayload = null, payloadBytes = new Uint8Array(), scriptSlot = 1;
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
}

function refreshPayloadSelect() {
  const select = byId('payload-select');
  const previous = select.value;
  select.replaceChildren(new Option('follow latest payload', ''));
  for (const record of payloadRecords.slice().reverse()) {
    const info = record.event.details?.info || {};
    const size = info.content ? decodeBase64(info.content).length : 0;
    select.add(new Option(`r${record.revision} · ${info.side || '?'} · ${size} B · ${info.session || record.event.id}`, String(record.revision)));
  }
  if ([...select.options].some(option => option.value === previous)) select.value = previous;
}

function loadSelectedPayload() {
  const requested = Number(byId('payload-select').value);
  selectedPayload = requested
    ? payloadRecords.find(record => record.revision === requested)
    : payloadRecords[payloadRecords.length - 1];
  if (!selectedPayload) {
    byId('workbench-source').textContent = 'no connection-content captured yet';
    byId('workbench-source').className = 'empty';
    return;
  }
  payloadBytes = decodeBase64(selectedPayload.event.details?.info?.content);
  renderPayload();
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
      return;
    }
    if (data.replacement === null) {
      scriptStatus.textContent = 'unchanged';
      scriptStatus.className = 'ok';
      byId('replacement-text').value = '';
    } else {
      const replacement = decodeBase64(data.replacement);
      scriptStatus.textContent = `replace · ${replacement.length} B`;
      scriptStatus.className = 'ok';
      byId('replacement-text').value = new TextDecoder().decode(replacement);
    }
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

async function poll() {
  try {
    const [eventResponse, statusResponse, sessionResponse, historyResponse] = await Promise.all([
      fetch(`${baseUrl()}/api/events?after=${revision}`, {headers: headers()}),
      fetch(`${baseUrl()}/api/status`, {headers: headers()}),
      fetch(`${baseUrl()}/api/sessions`, {headers: headers()}),
      fetch(`${baseUrl()}/api/session-history`, {headers: headers()}),
    ]);
    if (!eventResponse.ok) throw new Error(`events HTTP ${eventResponse.status}`);
    if (!statusResponse.ok) throw new Error(`status HTTP ${statusResponse.status}`);
    if (!sessionResponse.ok) throw new Error(`sessions HTTP ${sessionResponse.status}`);
    if (!historyResponse.ok) throw new Error(`history HTTP ${historyResponse.status}`);
    const [data, current, sessionData, historyData] = await Promise.all([
      eventResponse.json(), statusResponse.json(), sessionResponse.json(), historyResponse.json(),
    ]);
    revision = data.revision;
    eventRecords.push(...data.events);
    if (eventRecords.length > 500) eventRecords = eventRecords.slice(-500);
    const newPayloads = data.events.filter(record => record.event.action === 'connection-content' &&
      typeof record.event.details?.info?.content === 'string');
    if (newPayloads.length) {
      payloadRecords.push(...newPayloads);
      if (payloadRecords.length > 100) payloadRecords = payloadRecords.slice(-100);
      refreshPayloadSelect();
      if (byId('payload-select').value === '') loadSelectedPayload();
    }
    renderEvents();
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
    status.textContent = `live · r${revision}`;
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
  clearInterval(timer);
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
byId('load-payload').onclick = loadSelectedPayload;
byId('sample-payload').onclick = () => {
  selectedPayload = null;
  payloadBytes = new TextEncoder().encode('GET / HTTP/1.1\r\nHost: example.test\r\n\r\n');
  renderPayload();
};
byId('payload-text').oninput = event => {
  payloadBytes = new TextEncoder().encode(event.target.value);
  byId('payload-hex').textContent = encodeHex(payloadBytes);
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
connect();
