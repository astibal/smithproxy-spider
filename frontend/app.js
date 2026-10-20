const byId = id => document.getElementById(id);
const backend = byId('backend'), token = byId('token'), status = byId('status');
const chain = byId('chain'), events = byId('events');
const sessions = byId('sessions');
const historyList = byId('history-list'), sessionDetail = byId('session-detail');
const smithproxyUrl = byId('smithproxy-url'), smithproxyKey = byId('smithproxy-key');
const smithproxyVerify = byId('smithproxy-verify'), configureStatus = byId('configure-status');
let revision = 0, timer, eventRecords = [], historyRecords = [], selectedSessionId = null;
let selectedSessionDetail = null;
let payloadRecords = [], selectedPayload = null, payloadBytes = new Uint8Array(), scriptSlot = 1;
let scriptLanguage = 'python';
let inspectionPollInFlight = false;
const flowRecords = new Map();
const startedConnections = new Set();
const liveSiftClassifications = new Map();
const followedFlows = new Map();
let flowMenuSession = null;
let payloadListView = localStorage.getItem('spider-payload-list-view') === 'flows' ? 'flows' : 'payloads';
let payloadScope = localStorage.getItem('spider-payload-scope') === 'l7' ? 'l7' : 'wire';
let eventSocket = null, reconnectTimer = null, followPayload = true, liveEdit = false;
let replacementBase64 = null;
let activeTab = 'workbench-tab', renderFrame = null, eventsDirty = true, payloadsDirty = true;
let inspectionPayloadsReceived = 0, inspectionLastSeenAt = 0;
const inspectionIngress = [];
const inspectionRuns = {completed: 0, failed: 0, running: 0};
let payloadCacheBytes = 0, payloadsDropped = 0, payloadBytesDropped = 0, evictionTimes = [];
let evictionActivityPending = 0, evictionActivityTimer = null;
let pollInFlight = false;
let backendDiagnostics = null;
const frontendDiagnostics = {
  startedAtMs: Date.now(), pollAttempts: 0, pollSuccesses: 0, pollErrors: 0,
  lastPollStartedAtMs: 0, lastPollSuccessAtMs: 0, lastPollErrorAtMs: 0,
  lastPollDurationMs: 0, lastPollError: '', wsConnects: 0, wsOpens: 0,
  wsCloses: 0, wsErrors: 0, wsMessages: 0, wsEvents: 0, wsGaps: 0,
  lastWsOpenAtMs: 0, lastWsMessageAtMs: 0, lastWsEventAtMs: 0, lastWsCloseAtMs: 0,
};
let lastConnectionActivityState = null;
let payloadMemoryLimit = Number(localStorage.getItem('spider-payload-memory-mib')) || 64;
let payloadRecordLimit = Number(localStorage.getItem('spider-payload-record-limit')) || 200;
let eventRecordLimit = Number(localStorage.getItem('spider-event-record-limit')) || 2000;
let activeSessionRecords = [];
let endpointTtlSeconds = Math.max(10, Math.min(3600,
  Number(localStorage.getItem('spider-endpoint-ttl-seconds')) || 600));
let endpointDisplayLimit = Number(localStorage.getItem('spider-endpoint-display-limit') || 10);
if (![0, 10, 20].includes(endpointDisplayLimit)) endpointDisplayLimit = 10;
const observedSources = new Map(), observedDestinations = new Map(), observedPorts = new Map();
const observedSift = new Map();
const observedSiftSessions = new Map();
const reverseHostnames = new Map();
let hostnameRevision = -1;
let hostnameResolving = localStorage.getItem('spider-hostname-resolving') !== 'false';
let hideResolvedIps = localStorage.getItem('spider-hide-resolved-ips') === 'true';
let compactSessionLabels = localStorage.getItem('spider-compact-session-labels') === 'true';
let hostnameSort = {key: 'ip', direction: 1};
let hostnameExceptions = new Set();
try {
  const savedExceptions = JSON.parse(localStorage.getItem('spider-hostname-exceptions') || '[]');
  if (Array.isArray(savedExceptions)) hostnameExceptions = new Set(savedExceptions.filter(String));
} catch (_) {}
let sessionGroupOrder = ['src', 'dst', 'dport'];
let sessionGroupsEnabled = new Set(sessionGroupOrder);
const openSessionGroups = new Set();
try {
  const savedGrouping = JSON.parse(localStorage.getItem('spider-session-grouping') || 'null');
  if (Array.isArray(savedGrouping?.order) &&
      savedGrouping.order.length === 3 &&
      new Set(savedGrouping.order).size === 3 &&
      savedGrouping.order.every(key => ['src', 'dst', 'dport'].includes(key))) {
    sessionGroupOrder = savedGrouping.order;
  }
  if (Array.isArray(savedGrouping?.enabled)) {
    sessionGroupsEnabled = new Set(savedGrouping.enabled.filter(key => sessionGroupOrder.includes(key)));
  }
} catch (_) {}
if (localStorage.getItem('spider-session-layout') !== 'natural-order-v1') {
  sessionGroupOrder = ['src', 'dst', 'dport'];
  localStorage.setItem('spider-session-layout', 'natural-order-v1');
  localStorage.setItem('spider-session-grouping', JSON.stringify({
    order: sessionGroupOrder,
    enabled: sessionGroupOrder.filter(key => sessionGroupsEnabled.has(key)),
  }));
}
let trafficRules = [];
try {
  const savedRules = JSON.parse(localStorage.getItem('spider-traffic-rules') || '[]');
  if (Array.isArray(savedRules)) trafficRules = savedRules.map(rule => ({
    ...rule,
    id: rule.id || `address:${rule.address}`,
    kind: rule.kind || 'address',
    value: rule.value || rule.address,
    mode: rule.mode === 'ignore' ? 'forget' : rule.mode,
  })).filter(rule => rule && typeof rule.value === 'string' &&
    ['pass', 'focus', 'inspect', 'forget'].includes(rule.mode));
} catch (_) {}
let endpointAggregates = [];
try {
  const saved = JSON.parse(localStorage.getItem('spider-endpoint-aggregates') || '[]');
  if (Array.isArray(saved)) endpointAggregates = saved.filter(item => item &&
    typeof item.id === 'string' && ['hostname-suffix', 'hostname-glob', 'cidr'].includes(item.kind) &&
    typeof item.value === 'string');
} catch (_) {}
let siftAggregates = [];
try {
  const saved = JSON.parse(localStorage.getItem('spider-sift-aggregates') || '[]');
  if (Array.isArray(saved)) siftAggregates = saved.filter(value => typeof value === 'string' && value.trim());
} catch (_) {}
let bypassAll = localStorage.getItem('spider-bypass-all') === 'true';
const aggregateMembers = new Map();
let activityRecords = [], activitySequence = 0, activityUnread = 0;
const activityFilters = {rule: true, sift: true, system: true};
let flowViewLimitMiB = Math.max(1, Math.min(8192,
  Number(localStorage.getItem('spider-flow-view-limit-mib')) || 2));
const eventFilters = {ping: false, sessions: false, status: true, other: false};
const defaultPythonScript = `# api.bytes          original payload as bytes
# api.text           UTF-8 decoded view
# api.l7_bytes       concatenated detected L7 body ranges
# api.l7_ranges      (start, end) offsets into api.bytes
# api.l7_encodings   positional Content-Encoding values
# api.l7_state       "body", "none", "unknown", or "unavailable"
# api.enrichments    decoded/derived metadata and bytes
# api.side           "L" (client) or "R" (server)
# api.session_id     Smithproxy session identifier
# api.session_label  endpoints and detected protocol
# api.print(...)     append to Script output
# api.hexdump(...)   formatted preview of api.bytes
#
# Return None to keep the payload unchanged.
# Return str or bytes to replace it.

api.print(api.session_id, api.side, len(api.bytes), "bytes")
api.print(api.hexdump(limit=64))
return None
`;

function scriptStorageKey(slot = scriptSlot) {
  return scriptLanguage === 'python' ? `spider-python-script-${slot}` : `spider-script-${slot}`;
}

function defaultScript() {
  return defaultPythonScript;
}

const suggestedBackend = `${location.protocol}//${location.hostname}:18080`;
backend.value = localStorage.getItem('spider-backend') || suggestedBackend;
token.value = sessionStorage.getItem('spider-token') || '';
smithproxyUrl.value = localStorage.getItem('smithproxy-url') || smithproxyUrl.value;
smithproxyVerify.checked = localStorage.getItem('smithproxy-verify') !== 'false';
byId('resolve-hostnames').checked = hostnameResolving;
byId('hide-resolved-ips').checked = hideResolvedIps;
byId('compact-session-labels').checked = compactSessionLabels;

async function redeemSaslikBootstrap() {
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ''));
  const code = fragment.get('code');
  const saslikOrigin = fragment.get('saslik_origin');
  if (!code || !saslikOrigin) return;

  // Remove the capability before performing any network operation. It must
  // not survive in browser history, screenshots, or a copied address.
  history.replaceState(null, '', `${location.pathname}${location.search}`);
  token.value = '';
  sessionStorage.removeItem('spider-token');
  const bootstrapUrl = new URL('/api/spider/bootstrap/redeem', saslikOrigin);
  if (!['http:', 'https:'].includes(bootstrapUrl.protocol)) {
    throw new Error('Unsupported Saslik bootstrap URL');
  }
  const response = await fetch(bootstrapUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({code}),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `Bootstrap HTTP ${response.status}`);

  const backendUrl = new URL(value.backend);
  if (['127.0.0.1', 'localhost', '10.254.77.1', '10.254.77.2'].includes(backendUrl.hostname)) {
    backendUrl.hostname = bootstrapUrl.hostname;
  }
  backend.value = backendUrl.toString().replace(/\/$/, '');
  token.value = value.token;
}

async function bootstrapAndConnect() {
  try {
    await redeemSaslikBootstrap();
  } catch (error) {
    status.textContent = `offline · ${error.message}`;
    status.className = 'error';
  }
  connect();
}
byId('script-language').value = scriptLanguage;
const savedSidebarWidth = Number(localStorage.getItem('spider-sidebar-width'));
if (savedSidebarWidth >= 280) byId('sidebar').style.width = `${savedSidebarWidth}px`;
if ('ResizeObserver' in window) {
  new ResizeObserver(entries => {
    if (window.innerWidth > 800) {
      localStorage.setItem('spider-sidebar-width', String(Math.round(entries[0].contentRect.width)));
    }
  }).observe(byId('sidebar'));
}
const sidebarResizer = byId('sidebar-resizer');
sidebarResizer.onpointerdown = event => {
  const sidebar = byId('sidebar');
  const startX = event.clientX, startWidth = sidebar.getBoundingClientRect().width;
  sidebarResizer.setPointerCapture(event.pointerId);
  sidebarResizer.onpointermove = move => {
    const width = Math.max(280, Math.min(window.innerWidth * .7, startWidth + move.clientX - startX));
    sidebar.style.width = `${Math.round(width)}px`;
  };
  sidebarResizer.onpointerup = () => { sidebarResizer.onpointermove = null; };
};
sidebarResizer.onkeydown = event => {
  if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
  event.preventDefault();
  const sidebar = byId('sidebar');
  const change = event.key === 'ArrowLeft' ? -20 : 20;
  sidebar.style.width = `${Math.max(280, Math.min(window.innerWidth * .7,
    sidebar.getBoundingClientRect().width + change))}px`;
};
const sidebarTrafficPane = byId('sidebar-traffic-pane');
function showSidebarTab(name) {
  const selected = name === 'status' ? 'status' : 'traffic';
  byId('sidebar-status-pane').hidden = selected !== 'status';
  sidebarTrafficPane.hidden = selected !== 'traffic';
  for (const button of document.querySelectorAll('[data-sidebar-tab]')) {
    button.setAttribute('aria-selected', String(button.dataset.sidebarTab === selected));
  }
  localStorage.setItem('spider-sidebar-tab', selected);
}
for (const button of document.querySelectorAll('[data-sidebar-tab]')) {
  button.onclick = () => showSidebarTab(button.dataset.sidebarTab);
}
function setSessionPaneHeight(height) {
  const available = sidebarTrafficPane.getBoundingClientRect().height;
  const maximum = Math.max(80, available - 230);
  const value = Math.max(70, Math.min(maximum, height));
  sidebarTrafficPane.style.setProperty('--session-pane-height', `${Math.round(value)}px`);
  localStorage.setItem('spider-session-pane-height', String(Math.round(value)));
}
const trafficPanelResizer = byId('traffic-panel-resizer');
trafficPanelResizer.onpointerdown = event => {
  const sessionPanel = sidebarTrafficPane.querySelector('.session-panel');
  const startY = event.clientY, startHeight = sessionPanel.getBoundingClientRect().height;
  trafficPanelResizer.setPointerCapture(event.pointerId);
  trafficPanelResizer.onpointermove = move => setSessionPaneHeight(startHeight + move.clientY - startY);
  trafficPanelResizer.onpointerup = () => { trafficPanelResizer.onpointermove = null; };
};
trafficPanelResizer.onkeydown = event => {
  if (!['ArrowUp', 'ArrowDown'].includes(event.key)) return;
  event.preventDefault();
  const height = sidebarTrafficPane.querySelector('.session-panel').getBoundingClientRect().height;
  setSessionPaneHeight(height + (event.key === 'ArrowUp' ? -20 : 20));
};
const savedSessionPaneHeight = Number(localStorage.getItem('spider-session-pane-height'));
if (savedSessionPaneHeight >= 70) {
  sidebarTrafficPane.style.setProperty('--session-pane-height', `${savedSessionPaneHeight}px`);
}
showSidebarTab(localStorage.getItem('spider-sidebar-tab') || 'traffic');
function formatEndpointTtl(seconds) {
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return '1 h';
}
const endpointTtl = byId('endpoint-ttl');
endpointTtl.value = endpointTtlSeconds;
byId('endpoint-ttl-value').value = formatEndpointTtl(endpointTtlSeconds);
endpointTtl.oninput = () => {
  endpointTtlSeconds = Number(endpointTtl.value);
  localStorage.setItem('spider-endpoint-ttl-seconds', String(endpointTtlSeconds));
  byId('endpoint-ttl-value').value = formatEndpointTtl(endpointTtlSeconds);
  updateObservedEndpoints([], Date.now());
  renderEndpointBuilder();
};
const endpointLimit = byId('endpoint-limit');
endpointLimit.value = String(endpointDisplayLimit);
endpointLimit.onchange = () => {
  endpointDisplayLimit = Number(endpointLimit.value);
  localStorage.setItem('spider-endpoint-display-limit', String(endpointDisplayLimit));
  renderEndpointBuilder();
};
const workbenchLayout = byId('workbench-layout');
const savedPayloadPane = Number(localStorage.getItem('spider-payload-pane'));
const savedPayloadListHeight = Number(localStorage.getItem('spider-payload-list-height'));
const savedPayloadViewHeight = Number(localStorage.getItem('spider-payload-view-height'));
const savedCodeSize = Number(localStorage.getItem('spider-code-size'));
let codeSize = savedCodeSize >= 11 && savedCodeSize <= 22 ? savedCodeSize : 13;
if (savedPayloadPane >= 20 && savedPayloadPane <= 75) {
  workbenchLayout.style.setProperty('--payload-pane', `${savedPayloadPane}%`);
}
workbenchLayout.style.setProperty('--code-size', `${codeSize}px`);
workbenchLayout.style.setProperty('--payload-list-height', `${savedPayloadListHeight >= 80 ? savedPayloadListHeight : 155}px`);
workbenchLayout.style.setProperty('--payload-view-height', `${savedPayloadViewHeight >= 80 ? savedPayloadViewHeight : 300}px`);

const baseUrl = () => backend.value.replace(/\/$/, '');
function tokenValue() {
  const value = token.value.trim();
  if (/[^\x20-\x7e]/.test(value)) {
    throw new Error('Token contains masked bullets or other non-ASCII characters; paste the actual token from the runner status');
  }
  return value;
}
const headers = () => ({'X-Spider-Token': tokenValue()});

function modeEffect(mode) {
  if (mode === 'forget') return 'Spider permanently declines future content callbacks for matching connections.';
  if (mode === 'pass') return 'Payloads will reach Spider, but will be excluded from flow analysis.';
  if (mode === 'focus') return 'Non-matching traffic will be passed after classification.';
  if (mode === 'inspect') return 'Matching payloads will always be sent through the active script.';
  return '';
}

function addActivity(category, action, subject, effect = '', severity = 'info') {
  const record = {id: ++activitySequence, at: Date.now(), category, action, subject, effect, severity};
  activityRecords.push(record);
  if (activityRecords.length > 500) activityRecords.splice(0, activityRecords.length - 500);
  if (!byId('activity-drawer').open) ++activityUnread;
  renderActivity();
}

function renderActivity() {
  const target = byId('activity-list');
  const visible = activityRecords.filter(item => activityFilters[item.category] !== false).slice().reverse();
  target.replaceChildren();
  target.className = `activity-list${visible.length ? '' : ' empty'}`;
  if (!visible.length) target.textContent = 'No matching activity yet.';
  for (const item of visible) {
    const row = document.createElement('div');
    row.className = `activity-row ${item.category} ${item.severity}`;
    const time = document.createElement('time');
    time.textContent = new Date(item.at).toLocaleTimeString();
    const action = document.createElement('b'); action.textContent = item.action;
    const subject = document.createElement('code'); subject.textContent = item.subject;
    row.append(time, action, subject);
    if (item.effect) {
      const effect = document.createElement('p'); effect.textContent = item.effect;
      row.append(effect);
    }
    target.append(row);
  }
  const unread = byId('activity-unread');
  unread.hidden = activityUnread === 0;
  unread.textContent = `${activityUnread} new`;
  byId('activity-summary').textContent = activityRecords.length
    ? `${activityRecords.at(-1).action}: ${activityRecords.at(-1).subject}` : 'ready';
}

function ruleLabel(rule) {
  if (rule.kind === 'hostname-suffix') return `*.${rule.value}`;
  if (rule.kind === 'hostname-glob') return rule.value;
  if (rule.kind === 'sift') return classificationLabel(rule.value);
  if (rule.kind === 'sift-glob') return classificationGlobLabel(rule.value);
  return rule.value;
}

function expandedTrafficRules() {
  const expanded = [];
  for (const rule of trafficRules) {
    if (rule.kind === 'sift' || rule.kind === 'sift-glob') {
      expanded.push({id: rule.id, kind: rule.kind, value: rule.value, mode: rule.mode});
      continue;
    }
    const addresses = rule.kind === 'address' ? [rule.value] : aggregateMatchingAddresses(rule);
    for (const address of addresses) {
      expanded.push({id: `${rule.id}@${address}`, parent_id: rule.id, address, mode: rule.mode});
    }
  }
  return expanded;
}

function syncTrafficRules() {
  localStorage.setItem('spider-traffic-rules', JSON.stringify(trafficRules));
  localStorage.setItem('spider-bypass-all', String(bypassAll));
  socketSend({type: 'traffic-rules', bypass_all: bypassAll, rules: expandedTrafficRules()});
  renderTrafficRules();
  renderEndpointBuilder();
}

function renderTrafficRules() {
  const target = byId('traffic-rules');
  byId('focus-indicator').hidden = !trafficRules.some(rule => rule.mode === 'focus');
  byId('bypass-indicator').hidden = !bypassAll;
  byId('bypass-all').setAttribute('aria-pressed', String(bypassAll));
  const counts = {pass: 0, focus: 0, inspect: 0, forget: 0};
  for (const rule of trafficRules) ++counts[rule.mode];
  const breakdown = Object.entries(counts).filter(([, count]) => count)
    .map(([mode, count]) => `${mode.toUpperCase()} ${count}`).join(' · ');
  byId('traffic-rules-summary').textContent = `Rules (${trafficRules.length})${breakdown ? ` · ${breakdown}` : ''}`;
  target.replaceChildren();
  if (!trafficRules.length) {
    target.textContent = 'right-click an endpoint or Sift label to classify it';
    target.className = 'traffic-rules empty';
    return;
  }
  target.className = 'traffic-rules';
  for (let index = 0; index < trafficRules.length; ++index) {
    const rule = trafficRules[index];
    const row = document.createElement('div');
    row.className = `traffic-rule ${rule.mode}`;
    const mode = document.createElement('b'); mode.textContent = rule.mode.toUpperCase();
    const address = document.createElement('code'); address.textContent = ruleLabel(rule);
    address.title = modeEffect(rule.mode);
    const matches = document.createElement('small');
    matches.textContent = `${Number(rule.matches || 0).toLocaleString()} hits`;
    const up = document.createElement('button'); up.textContent = '↑'; up.disabled = index === 0;
    up.onclick = () => { [trafficRules[index - 1], trafficRules[index]] = [rule, trafficRules[index - 1]]; syncTrafficRules(); };
    const down = document.createElement('button'); down.textContent = '↓'; down.disabled = index === trafficRules.length - 1;
    down.onclick = () => { [trafficRules[index], trafficRules[index + 1]] = [trafficRules[index + 1], rule]; syncTrafficRules(); };
    const remove = document.createElement('button');
    remove.textContent = '×';
    remove.onclick = () => {
      trafficRules = trafficRules.filter(item => item !== rule);
      addActivity('rule', 'RULE REMOVED', `${rule.mode.toUpperCase()} ${ruleLabel(rule)}`,
        'Future traffic will no longer inherit this behavior.');
      syncTrafficRules();
    };
    row.append(mode, address, matches, up, down, remove);
    target.append(row);
  }
}

function parseSessionLabel(label) {
  const match = String(label || '').match(/^([^_]+)_(.+):(\d+)\+([^_]+)_(.+):(\d+)$/);
  if (!match) return null;
  return {sourceProtocol: match[1].toLowerCase(), sourceHost: match[2], sourcePort: Number(match[3]),
          destinationProtocol: match[4].toLowerCase(), destinationHost: match[5], destinationPort: Number(match[6])};
}

function saveSessionGrouping() {
  localStorage.setItem('spider-session-grouping', JSON.stringify({
    order: sessionGroupOrder,
    enabled: sessionGroupOrder.filter(key => sessionGroupsEnabled.has(key)),
  }));
}

function sessionGroupValue(item, key) {
  const connection = parseSessionLabel(item.label || item.last_event?.details?.info?.session);
  if (!connection) return 'unknown';
  if (key === 'src') return resolvedAddress(connection.sourceHost);
  if (key === 'dst') return resolvedAddress(connection.destinationHost);
  return String(connection.destinationPort);
}

function renderSessionBranch(target, items, dimensions, depth = 0, parentPath = '') {
  if (depth >= dimensions.length) {
    for (const item of [...items].sort((a, b) => String(a.id).localeCompare(String(b.id), undefined, {numeric: true}))) {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'session-key';
      const key = document.createElement('span');
      key.textContent = item.id;
      row.append(key);
      const classifications = siftClassifications(item);
      if (classifications.length) {
        const summary = document.createElement('small');
        summary.className = 'session-classification';
        summary.textContent = classifications.map(classificationLabel).join(' › ');
        summary.title = classifications.join('\n');
        row.append(summary);
      }
      row.title = resolvedSessionLabel(item.label) || item.id;
      row.onclick = () => pinSession(item);
      target.append(row);
    }
    return;
  }

  const dimension = dimensions[depth];
  const groups = new Map();
  for (const item of items) {
    const value = sessionGroupValue(item, dimension);
    if (!groups.has(value)) groups.set(value, []);
    groups.get(value).push(item);
  }
  for (const [value, members] of [...groups].sort((a, b) =>
    a[0].localeCompare(b[0], undefined, {numeric: true}))) {
    const path = `${parentPath}/${dimension}:${value}`;
    const details = document.createElement('details');
    details.className = 'session-group';
    details.open = openSessionGroups.has(path);
    const summary = document.createElement('summary');
    summary.append(document.createTextNode(`${dimension} ${value}`));
    const count = document.createElement('span');
    count.textContent = String(members.length);
    summary.append(count);
    const children = document.createElement('div');
    children.className = 'session-group-children';
    renderSessionBranch(children, members, dimensions, depth + 1, path);
    details.ontoggle = () => {
      if (details.open) openSessionGroups.add(path);
      else openSessionGroups.delete(path);
    };
    details.append(summary, children);
    target.append(details);
  }
}

function renderActiveSessions(items) {
  sessions.replaceChildren();
  if (!items.length) {
    sessions.textContent = 'none';
    sessions.className = 'empty';
    return;
  }
  sessions.className = 'session-tree';
  const dimensions = sessionGroupOrder.filter(key => sessionGroupsEnabled.has(key));
  renderSessionBranch(sessions, items, dimensions);
}

function moveSessionGroup(key, offset) {
  const from = sessionGroupOrder.indexOf(key);
  const to = Math.max(0, Math.min(sessionGroupOrder.length - 1, from + offset));
  if (from === to) return;
  sessionGroupOrder.splice(from, 1);
  sessionGroupOrder.splice(to, 0, key);
  openSessionGroups.clear();
  saveSessionGrouping();
  renderSessionGroupControls();
  renderActiveSessions(activeSessionRecords);
  renderEndpointBuilder(activeSessionRecords);
}

function renderSessionGroupControls() {
  const controls = byId('session-group-controls');
  controls.replaceChildren();
  for (const key of sessionGroupOrder) {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.group = key;
    button.draggable = true;
    button.textContent = key;
    button.title = 'Click to toggle; drag or Alt+Left/Right to change priority';
    button.setAttribute('aria-pressed', String(sessionGroupsEnabled.has(key)));
    button.onclick = () => {
      if (sessionGroupsEnabled.has(key)) sessionGroupsEnabled.delete(key);
      else sessionGroupsEnabled.add(key);
      openSessionGroups.clear();
      saveSessionGrouping();
      renderSessionGroupControls();
      renderActiveSessions(activeSessionRecords);
      renderEndpointBuilder(activeSessionRecords);
    };
    button.onkeydown = event => {
      if (!event.altKey || !['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      event.preventDefault();
      moveSessionGroup(key, event.key === 'ArrowLeft' ? -1 : 1);
    };
    button.ondragstart = event => {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', key);
      button.classList.add('dragging');
    };
    button.ondragend = () => button.classList.remove('dragging');
    button.ondragover = event => {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
    };
    button.ondrop = event => {
      event.preventDefault();
      const moved = event.dataTransfer.getData('text/plain');
      if (!sessionGroupOrder.includes(moved) || moved === key) return;
      const from = sessionGroupOrder.indexOf(moved);
      sessionGroupOrder.splice(from, 1);
      let to = sessionGroupOrder.indexOf(key);
      if (event.clientX > button.getBoundingClientRect().left + button.offsetWidth / 2) ++to;
      sessionGroupOrder.splice(to, 0, moved);
      openSessionGroups.clear();
      saveSessionGrouping();
      renderSessionGroupControls();
      renderActiveSessions(activeSessionRecords);
      renderEndpointBuilder(activeSessionRecords);
    };
    controls.append(button);
  }
}

function updateObservedEndpoints(items, now = Date.now()) {
  const sourceCounts = new Map();
  const destinations = new Map();
  const portCounts = new Map();
  for (const item of items) {
    const connection = parseSessionLabel(item.label || item.last_event?.details?.info?.session);
    if (!connection) continue;
    const protocol = ['udp', 'quic'].includes(connection.sourceProtocol) ? 'udp' : 'tcp';
    const source = sourceCounts.get(connection.sourceHost) || {count: 0, protocol};
    source.count += 1;
    sourceCounts.set(connection.sourceHost, source);
    const destination = destinations.get(connection.destinationHost) || {count: 0, protocol};
    destination.count += 1;
    destinations.set(connection.destinationHost, destination);
    const port = portCounts.get(connection.destinationPort) || {count: 0, protocol};
    port.count += 1;
    portCounts.set(connection.destinationPort, port);
  }
  for (const [key, data] of sourceCounts) observedSources.set(key, {...data, lastSeen: now});
  for (const [key, data] of destinations) observedDestinations.set(key, {...data, lastSeen: now});
  for (const [key, data] of portCounts) observedPorts.set(key, {...data, lastSeen: now});
  const cutoff = now - endpointTtlSeconds * 1000;
  for (const values of [observedSources, observedDestinations, observedPorts]) {
    for (const [key, data] of values) if (data.lastSeen < cutoff) values.delete(key);
  }
}

function endpointIntensity(data, now = Date.now()) {
  const ttl = endpointTtlSeconds * 1000;
  const remaining = data.lastSeen + ttl - now;
  const fadeWindow = Math.max(ttl * .1, 5000);
  if (remaining > fadeWindow) return 1;
  return Math.max(.3, remaining / fadeWindow);
}

function decorateExpiringEndpoint(button, data, now) {
  const intensity = endpointIntensity(data, now);
  if (intensity >= 1) return;
  button.classList.add('expiring');
  button.style.setProperty('--endpoint-intensity', intensity.toFixed(2));
  button.title = `Expires in ${Math.max(0, Math.ceil((data.lastSeen + endpointTtlSeconds * 1000 - now) / 1000))} s`;
}

function limitedEndpoints(entries) {
  return endpointDisplayLimit ? entries.slice(0, endpointDisplayLimit) : entries;
}

function endpointDisplay(address) {
  return resolvedAddress(address);
}

function hostnameMatchesSuffix(hostname, suffix) {
  const normalized = normalizeHostname(hostname);
  const wanted = normalizeHostname(suffix).replace(/^\*\./, '');
  return normalized === wanted || normalized.endsWith(`.${wanted}`);
}

function hostnameMatchesGlob(hostname, pattern) {
  const expression = normalizeHostname(pattern)
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replaceAll('*', '[^.]*');
  return new RegExp(`^${expression}$`, 'i').test(normalizeHostname(hostname));
}

function ipv4Number(value) {
  const parts = String(value).split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part) || Number(part) > 255) return null;
    result = (result * 256 + Number(part)) >>> 0;
  }
  return result;
}

function addressMatchesCidr(address, cidr) {
  const [network, prefixText] = String(cidr).split('/');
  const value = ipv4Number(address), base = ipv4Number(network), prefix = Number(prefixText);
  if (value === null || base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (base & mask);
}

function addressMatchesAggregate(address, aggregate) {
  if (aggregate.kind === 'cidr') return addressMatchesCidr(address, aggregate.value);
  const entry = reverseHostnames.get(address);
  if (aggregate.kind === 'hostname-suffix') return (entry?.candidates || [])
    .some(hostname => hostnameMatchesSuffix(hostname, aggregate.value));
  return aggregate.kind === 'hostname-glob' && (entry?.candidates || [])
    .some(hostname => hostnameMatchesGlob(hostname, aggregate.value));
}

function aggregateMatchingAddresses(aggregate) {
  const candidates = new Set([
    ...reverseHostnames.keys(), ...observedSources.keys(), ...observedDestinations.keys(),
  ]);
  return [...candidates].filter(address => addressMatchesAggregate(address, aggregate)).sort();
}

function aggregateForAddress(address) {
  return endpointAggregates.find(aggregate => addressMatchesAggregate(address, aggregate));
}

function trafficRuleFor(address) {
  return trafficRules.find(rule => rule.kind === 'address' && rule.value === address) ||
    trafficRules.find(rule => rule.kind !== 'address' && addressMatchesAggregate(address, rule));
}

function endpointRulePriority(address) {
  const index = trafficRules.findIndex(rule =>
    (rule.kind === 'address' && rule.value === address) ||
    (rule.kind !== 'address' && addressMatchesAggregate(address, rule)));
  return index < 0 ? Number.MAX_SAFE_INTEGER : index;
}

function compareEndpoints(a, b) {
  const priority = endpointRulePriority(a[0]) - endpointRulePriority(b[0]);
  return priority || b[1].count - a[1].count || a[0].localeCompare(b[0]);
}

function classifyEndpoint(target, mode) {
  if (!target) return;
  const id = target.id || `address:${target.value}`;
  const previous = trafficRules.find(rule => rule.id === id);
  trafficRules = trafficRules.filter(rule => rule.id !== id);
  if (mode !== 'clear') {
    const rule = {id, kind: target.kind || 'address', value: target.value, mode, matches: 0};
    trafficRules.push(rule);
    addActivity('rule', mode.toUpperCase(), `${mode.toUpperCase()} ${ruleLabel(rule)}`,
      modeEffect(mode));
  } else if (previous) {
    addActivity('rule', 'RULE REMOVED', `${previous.mode.toUpperCase()} ${ruleLabel(previous)}`,
      'Future traffic will no longer inherit this behavior.');
  }
  syncTrafficRules();
}

let endpointMenuTarget = null;
function openEndpointMenu(event, target) {
  event.preventDefault();
  const menu = byId('endpoint-menu');
  endpointMenuTarget = typeof target === 'string'
    ? {id: `address:${target}`, kind: 'address', value: target} : target;
  const aggregateActions = endpointMenuTarget?.kind === 'address';
  byId('aggregate-hostname').hidden = !aggregateActions ||
    !reverseHostnames.get(endpointMenuTarget?.value)?.preferred;
  byId('aggregate-network').hidden = !aggregateActions || ipv4Number(endpointMenuTarget?.value) === null;
  byId('aggregate-sift').hidden = endpointMenuTarget?.kind !== 'sift';
  byId('remove-aggregate').hidden = !['hostname-suffix', 'hostname-glob', 'cidr', 'sift-glob'].includes(endpointMenuTarget?.kind);
  menu.hidden = false;
  menu.style.left = `${Math.min(event.clientX, innerWidth - 140)}px`;
  menu.style.top = `${Math.min(event.clientY, innerHeight - 190)}px`;
}

function suggestedHostnameSuffix(address) {
  const hostname = reverseHostnames.get(address)?.preferred || '';
  const parts = normalizeHostname(hostname).split('.').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

function suggestedNetwork(address) {
  const parts = String(address).split('.');
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : '';
}

function createEndpointAggregate(kind, value) {
  value = String(value).trim();
  if (kind === 'hostname-suffix') {
    value = normalizeHostname(value);
    const wildcardCount = [...value].filter(character => character === '*').length;
    if (wildcardCount === 1 && value.startsWith('*.')) value = value.slice(2);
    else if (wildcardCount) kind = 'hostname-glob';
  }
  if (!value) return;
  if (kind === 'cidr' && !String(value).includes('/')) return;
  const id = `${kind}:${value}`;
  if (endpointAggregates.some(item => item.id === id)) return;
  const aggregate = {id, kind, value};
  endpointAggregates.push(aggregate);
  localStorage.setItem('spider-endpoint-aggregates', JSON.stringify(endpointAggregates));
  const members = new Set(aggregateMatchingAddresses(aggregate));
  aggregateMembers.set(id, members);
  addActivity('rule', 'AGGREGATE', `${ruleLabel(aggregate)} created`,
    `${members.size} currently known ${members.size === 1 ? 'address' : 'addresses'} grouped; no traffic behavior is assigned yet.`);
  renderEndpointBuilder();
}

function classificationGlobMatches(value, glob) {
  const expression = '^' + String(glob).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*') + '$';
  return new RegExp(expression, 'i').test(String(value));
}

function classificationGlobLabel(glob) {
  const parts = String(glob).split('.');
  const category = parts.shift();
  const prefix = category === 'app' ? 'APP' : category === 'protocol' ? 'L7' : category?.toUpperCase();
  return `${prefix || 'SIFT'} ${parts.join(' · ')}`.trim();
}

function createSiftAggregate(value) {
  const glob = String(value || '').trim().toLowerCase();
  if (!glob || siftAggregates.includes(glob)) return;
  siftAggregates.push(glob);
  localStorage.setItem('spider-sift-aggregates', JSON.stringify(siftAggregates));
  const matches = [...observedSift.keys()].filter(value => classificationGlobMatches(value, glob));
  addActivity('rule', 'AGGREGATE', `${classificationGlobLabel(glob)} created`,
    `${matches.length} currently known Sift ${matches.length === 1 ? 'label' : 'labels'} grouped; no traffic behavior is assigned yet.`);
  renderEndpointBuilder();
}

function refreshAggregateMembership(logChanges = true) {
  let rulesChanged = false;
  for (const aggregate of endpointAggregates) {
    const previous = aggregateMembers.get(aggregate.id);
    const current = new Set(aggregateMatchingAddresses(aggregate));
    aggregateMembers.set(aggregate.id, current);
    const rule = trafficRules.find(item => item.id === aggregate.id);
    if (!previous) {
      rulesChanged ||= Boolean(rule && current.size);
      continue;
    }
    for (const address of current) {
      if (previous.has(address)) continue;
      rulesChanged ||= Boolean(rule);
      if (logChanges) addActivity('rule', 'MEMBER ADDED',
        `${address} joined ${ruleLabel(aggregate)}`,
        rule ? modeEffect(rule.mode) : 'The address is now grouped by this aggregate; no traffic behavior is assigned.');
    }
    for (const address of previous) {
      if (current.has(address)) continue;
      rulesChanged ||= Boolean(rule);
      if (logChanges) addActivity('rule', 'MEMBER EXPIRED',
        `${address} left ${ruleLabel(aggregate)}`,
        rule ? `Its inherited ${rule.mode.toUpperCase()} behavior is no longer active.` :
          'The address is no longer part of this display aggregate.');
    }
  }
  if (rulesChanged) syncTrafficRules();
}

function normalizeHostname(value) {
  return value.toLowerCase().replace(/\.+$/, '');
}

function observeSiftClassification(sessionId, classification) {
  if (!sessionId || !classification) return;
  const firstSeen = !observedSift.has(classification);
  if (!observedSiftSessions.has(classification)) observedSiftSessions.set(classification, new Set());
  observedSiftSessions.get(classification).add(sessionId);
  observedSift.set(classification, observedSiftSessions.get(classification).size);
  if (firstSeen) {
    for (const glob of siftAggregates) {
      if (!classificationGlobMatches(classification, glob)) continue;
      const rule = trafficRules.find(item => item.id === `sift-glob:${glob}`);
      addActivity('rule', 'MEMBER ADDED',
        `${classificationLabel(classification)} joined ${classificationGlobLabel(glob)}`,
        rule ? modeEffect(rule.mode) :
          'The label is now grouped by this Sift aggregate; no traffic behavior is assigned.');
    }
  }
}

function ingestHostnameInfo(event) {
  const list = event.details?.info?.list;
  if (!Array.isArray(list)) return;
  for (const item of list) {
    if (!item || typeof item.hostname !== 'string' || !Array.isArray(item.address)) continue;
    const hostname = normalizeHostname(item.hostname);
    if (!hostname) continue;
    for (const address of item.address) {
      if (typeof address !== 'string') continue;
      const existing = reverseHostnames.get(address) || {preferred: hostname, candidates: [], entries: []};
      if (!existing.candidates.includes(hostname)) existing.candidates.push(hostname);
      let detail = existing.entries.find(candidate => candidate.hostname === hostname);
      if (!detail) {
        detail = {hostname, origins: [], types: []};
        existing.entries.push(detail);
      }
      if (typeof item.origin === 'string' && !detail.origins.includes(item.origin)) detail.origins.push(item.origin);
      if (typeof item.type === 'string' && !detail.types.includes(item.type)) detail.types.push(item.type);
      existing.candidates.sort(compareHostnames);
      existing.preferred = existing.candidates[0];
      reverseHostnames.set(address, existing);
    }
  }
  refreshAggregateMembership();
}

function compareHostnames(left, right) {
  const a = normalizeHostname(left), b = normalizeHostname(right);
  const aKey = [a ? a.split('.').length : 0, a.split('.')[0].length, a.length];
  const bKey = [b ? b.split('.').length : 0, b.split('.')[0].length, b.length];
  for (let i = 0; i < aKey.length; ++i) if (aKey[i] !== bKey[i]) return aKey[i] - bKey[i];
  return a.localeCompare(b);
}

function resolvedAddress(address) {
  if (!hostnameResolving || hostnameExceptions.has(address)) return address;
  const preferred = reverseHostnames.get(address)?.preferred;
  return preferred ? (hideResolvedIps ? preferred : `${preferred} · ${address}`) : address;
}

function resolvedSessionLabel(label) {
  const connection = parseSessionLabel(label);
  if (!connection) return resolveText(label);
  if (compactSessionLabels) {
    return `${resolvedAddress(connection.sourceHost)}-${resolvedAddress(connection.destinationHost)}:` +
      `${connection.destinationPort}`;
  }
  return `${connection.sourceProtocol}_${resolvedAddress(connection.sourceHost)}:${connection.sourcePort}+` +
    `${connection.destinationProtocol}_${resolvedAddress(connection.destinationHost)}:${connection.destinationPort}`;
}

function resolveText(value) {
  let result = String(value ?? '');
  if (!hostnameResolving) return result;
  const addresses = [...reverseHostnames.keys()].sort((a, b) => b.length - a.length);
  for (const address of addresses) {
    if (!hostnameExceptions.has(address)) result = result.replaceAll(address, resolvedAddress(address));
  }
  return result;
}

function saveHostnameExceptions() {
  localStorage.setItem('spider-hostname-exceptions', JSON.stringify([...hostnameExceptions].sort()));
}

function refreshResolvedViews() {
  openSessionGroups.clear();
  renderActiveSessions(activeSessionRecords);
  renderEndpointBuilder();
  renderHistory();
  if (selectedSessionDetail) renderSessionDetail(selectedSessionDetail);
  if (selectedPayload) renderPayload();
  renderPayloadList();
  renderHostnames();
}

function renderHostnames() {
  const target = byId('hostname-list');
  const sortValue = ([address, entry]) => {
    if (hostnameSort.key === 'hostname') return entry.preferred || '';
    if (hostnameSort.key === 'origin') {
      return entry.entries?.find(candidate => candidate.hostname === entry.preferred)?.origins?.join('+') || '';
    }
    return address;
  };
  const entries = [...reverseHostnames.entries()].sort((a, b) => {
    const primary = sortValue(a).localeCompare(sortValue(b), undefined,
      {numeric: true, sensitivity: 'base'});
    const stable = primary || a[0].localeCompare(b[0], undefined, {numeric: true});
    return hostnameSort.direction * stable;
  });
  byId('hostname-count').textContent = `${entries.length}`;
  for (const button of document.querySelectorAll('[data-hostname-sort]')) {
    const active = button.dataset.hostnameSort === hostnameSort.key;
    button.setAttribute('aria-pressed', String(active));
    button.textContent = button.dataset.hostnameSort +
      (active ? ` ${hostnameSort.direction > 0 ? '↑' : '↓'}` : '');
  }
  target.replaceChildren();
  if (!entries.length) {
    target.textContent = 'none';
    target.className = 'hostname-list empty';
    return;
  }
  target.className = 'hostname-list';
  for (const [address, entry] of entries) {
    const row = document.createElement('div');
    row.className = 'hostname-row';
    const ip = document.createElement('code');
    ip.textContent = address;
    const names = document.createElement('div');
    names.className = 'hostname-names';
    for (const hostname of entry.candidates || [entry.preferred]) {
      const chip = document.createElement('span');
      const detail = entry.entries?.find(candidate => candidate.hostname === hostname);
      const origins = detail?.origins?.join('+');
      chip.textContent = origins ? `${hostname} · ${origins}` : hostname;
      if (hostname === entry.preferred) {
        chip.className = 'preferred';
        chip.title = 'Preferred reverse display name';
      }
      names.append(chip);
    }
    const exception = document.createElement('label');
    exception.className = 'hostname-exception';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = hostnameExceptions.has(address);
    checkbox.onchange = () => {
      if (checkbox.checked) hostnameExceptions.add(address);
      else hostnameExceptions.delete(address);
      saveHostnameExceptions();
      refreshResolvedViews();
    };
    exception.append(checkbox, document.createTextNode('keep IP'));
    row.append(ip, names, exception);
    target.append(row);
  }
}

function attachEndpointScrollHint(target) {
  let indicator = target.parentElement.querySelector('.endpoint-more');
  if (!indicator) {
    indicator = document.createElement('span');
    indicator.className = 'endpoint-more';
    indicator.textContent = '↓';
    indicator.setAttribute('aria-hidden', 'true');
    target.parentElement.append(indicator);
  }
  const refresh = () => {
    const hasMore = target.scrollTop + target.clientHeight < target.scrollHeight - 2;
    target.classList.toggle('has-more', hasMore);
    indicator.hidden = !hasMore;
    target.title = hasMore ? 'Scroll for more endpoints' : '';
  };
  target.onscroll = refresh;
  requestAnimationFrame(refresh);
}

function renderEndpointBuilder() {
  const now = Date.now();

  const enabledDimensions = sessionGroupOrder.filter(key => sessionGroupsEnabled.has(key));
  const columns = byId('endpoint-columns');
  columns.style.gridTemplateColumns = enabledDimensions.length
    ? enabledDimensions.map(key => key === 'dport'
      ? 'minmax(52px,max-content)' : 'minmax(0,1fr)').join(' ')
    : '1fr';
  for (const column of columns.children) {
    const dimension = column.dataset.dimension;
    column.hidden = !sessionGroupsEnabled.has(dimension);
    column.style.order = String(sessionGroupOrder.indexOf(dimension));
  }

  const portTarget = byId('observed-ports');
  portTarget.replaceChildren();
  portTarget.className = `endpoint-list${observedPorts.size ? '' : ' empty'}`;
  if (!observedPorts.size) portTarget.textContent = 'none';
  for (const [port, data] of limitedEndpoints([...observedPorts]
      .sort((a, b) => b[1].count - a[1].count || a[0] - b[0]))) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'endpoint-port';
    const number = document.createElement('span'); number.textContent = String(port);
    const count = document.createElement('small'); count.textContent = String(data.count);
    button.append(number, count);
    portTarget.append(button);
  }
  attachEndpointScrollHint(portTarget);

  const siftTarget = byId('observed-sift');
  siftTarget.replaceChildren();
  siftTarget.className = `endpoint-list sift-endpoints${observedSift.size ? '' : ' empty'}`;
  if (!observedSift.size) siftTarget.textContent = 'none';
  const aggregatedSift = new Set();
  for (const glob of siftAggregates) {
    const matches = [...observedSift].filter(([classification]) =>
      classificationGlobMatches(classification, glob));
    matches.forEach(([classification]) => aggregatedSift.add(classification));
    const target = {id: `sift-glob:${glob}`, kind: 'sift-glob', value: glob};
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'endpoint-choice aggregate';
    const rule = trafficRules.find(item => item.id === target.id);
    if (rule) button.dataset.ruleMode = rule.mode;
    const label = document.createElement('span'); label.textContent = classificationGlobLabel(glob);
    const count = document.createElement('small');
    count.textContent = `${matches.length} labels · ${matches.reduce((sum, [, value]) => sum + value, 0)}`;
    button.append(label, count);
    button.oncontextmenu = event => openEndpointMenu(event, target);
    siftTarget.append(button);
  }
  for (const [classification, countValue] of [...observedSift]
      .filter(([classification]) => !aggregatedSift.has(classification))
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))) {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'endpoint-choice';
    const id = `sift:${classification}`;
    const rule = trafficRules.find(item => item.id === id);
    if (rule) button.dataset.ruleMode = rule.mode;
    const label = document.createElement('span'); label.textContent = classificationLabel(classification);
    const count = document.createElement('small'); count.textContent = String(countValue);
    button.append(label, count);
    button.title = 'This rule takes effect after Sift classifies the flow; earlier payloads may already have passed.';
    button.oncontextmenu = event => openEndpointMenu(event,
      {id, kind: 'sift', value: classification});
    siftTarget.append(button);
  }

  const sourceTarget = byId('observed-sources');
  sourceTarget.replaceChildren();
  sourceTarget.className = `endpoint-list${observedSources.size ? '' : ' empty'}`;
  if (!observedSources.size) sourceTarget.textContent = 'none';
  for (const [host, data] of limitedEndpoints([...observedSources]
      .sort(compareEndpoints))) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'endpoint-choice';
    const rule = trafficRuleFor(host);
    if (rule) button.dataset.ruleMode = rule.mode;
    const address = document.createElement('span'); address.textContent = endpointDisplay(host);
    const count = document.createElement('small'); count.textContent = `${data.protocol} · ${data.count}`;
    button.append(address, count);
    decorateExpiringEndpoint(button, data, now);
    button.oncontextmenu = event => openEndpointMenu(event, host);
    sourceTarget.append(button);
  }
  attachEndpointScrollHint(sourceTarget);

  const destinationTarget = byId('observed-destinations');
  destinationTarget.replaceChildren();
  const aggregatedAddresses = new Set();
  for (const aggregate of endpointAggregates) {
    const members = [...observedDestinations].filter(([address]) =>
      addressMatchesAggregate(address, aggregate));
    members.forEach(([address]) => aggregatedAddresses.add(address));
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'endpoint-choice aggregate';
    const rule = trafficRules.find(item => item.id === aggregate.id);
    if (rule) button.dataset.ruleMode = rule.mode;
    const label = document.createElement('span'); label.textContent = ruleLabel(aggregate);
    const hostnames = new Set(members.flatMap(([address]) =>
      reverseHostnames.get(address)?.candidates || []));
    const count = document.createElement('small');
    count.textContent = `${hostnames.size} hosts · ${members.length} IPs · ` +
      `${members.reduce((sum, [, data]) => sum + data.count, 0)}`;
    button.append(label, count);
    button.oncontextmenu = event => openEndpointMenu(event, aggregate);
    destinationTarget.append(button);
  }
  const destinations = [...observedDestinations]
    .filter(([address]) => !aggregatedAddresses.has(address));
  destinationTarget.className = `endpoint-list${destinationTarget.childElementCount || destinations.length ? '' : ' empty'}`;
  if (!destinationTarget.childElementCount && !destinations.length) destinationTarget.textContent = 'none';
  for (const [host, data] of limitedEndpoints(destinations
      .sort(compareEndpoints))) {
    const hostButton = document.createElement('button');
    hostButton.type = 'button'; hostButton.className = 'endpoint-choice';
    const rule = trafficRuleFor(host);
    if (rule) hostButton.dataset.ruleMode = rule.mode;
    const address = document.createElement('span'); address.textContent = endpointDisplay(host);
    const count = document.createElement('small'); count.textContent = String(data.count);
    hostButton.append(address, count);
    decorateExpiringEndpoint(hostButton, data, now);
    hostButton.oncontextmenu = event => openEndpointMenu(event, host);
    destinationTarget.append(hostButton);
  }
  attachEndpointScrollHint(destinationTarget);
}

function pinSession() { showTab('workbench-tab'); }

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

function clampInteger(value, minimum, maximum, fallback) {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, parsed)) : fallback;
}

payloadMemoryLimit = clampInteger(payloadMemoryLimit, 8, 2048, 64);
payloadRecordLimit = clampInteger(payloadRecordLimit, 10, 10000, 200);
eventRecordLimit = clampInteger(eventRecordLimit, 100, 20000, 2000);

function payloadSize(record) {
  const enrichmentBytes = Array.isArray(record?.enrichments)
    ? record.enrichments.reduce((total, item) => total +
        (item?.payload?.byteLength || 0) + JSON.stringify(item?.metadata || {}).length * 2, 0)
    : 0;
  if (record?.binaryPayload instanceof Uint8Array) {
    return record.binaryPayload.byteLength + enrichmentBytes + 1024;
  }
  const content = record.event.details?.info?.content;
  if (typeof content !== 'string') return 0;
  // A JS string may occupy two bytes per character. Include a small object overhead.
  return content.length * 2 + enrichmentBytes + 1024;
}

function decodedPayloadSize(content) {
  if (typeof content !== 'string' || content.length === 0) return 0;
  const padding = content.endsWith('==') ? 2 : content.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor(content.length * 3 / 4) - padding);
}

function summarizeEvent(record) {
  const event = {...record.event};
  const details = event.details;
  const info = details?.info;
  if (typeof info?.content === 'string') {
    event.details = {...details, info: {...info,
      content: `[binary data: ${decodedPayloadSize(info.content)} bytes]`,
    }};
  }
  if (record.binaryPayload instanceof Uint8Array && info) {
    event.details = {...details, info: {...info,
      content: `[binary data: ${record.binaryPayload.byteLength} bytes]`,
    }};
  }
  return {revision: record.revision, event};
}

function trimPayloadCache() {
  const byteLimit = payloadMemoryLimit * 1024 * 1024;
  while (payloadRecords.length > payloadRecordLimit || payloadCacheBytes > byteLimit) {
    const removed = payloadRecords.shift();
    if (!removed) break;
    const bytes = removed.cacheBytes || payloadSize(removed);
    payloadCacheBytes = Math.max(0, payloadCacheBytes - bytes);
    payloadsDropped += 1;
    evictionActivityPending += 1;
    if (!evictionActivityTimer) evictionActivityTimer = setTimeout(() => {
      addActivity('system', 'CACHE EVICTION', `${evictionActivityPending} payloads evicted`,
        'Opened flows may no longer contain their beginning; increase the browser cache limit if needed.', 'warn');
      evictionActivityPending = 0;
      evictionActivityTimer = null;
    }, 500);
    payloadBytesDropped += bytes;
    evictionTimes.push(Date.now());
    for (const followed of followedFlows.values()) {
      if (scopeMatches(followed, removed)) followed.evicted += 1;
    }
    if (selectedPayload === removed) selectedPayload = null;
    const flow = flowRecords.get(removed.event.id);
    if (flow) flow.evicted += 1;
    if (flow?.latest === removed) {
      flow.latest = [...payloadRecords].reverse().find(record => record.event.id === removed.event.id) || null;
    }
  }
  const cutoff = Date.now() - 60000;
  evictionTimes = evictionTimes.filter(time => time >= cutoff);
  if (!selectedPayload && payloadRecords.length && followPayload) {
    selectedPayload = payloadRecords[payloadRecords.length - 1];
  }
  updateCacheStats();
}

function updateCacheStats() {
  const cutoff = Date.now() - 60000;
  evictionTimes = evictionTimes.filter(time => time >= cutoff);
  const limitBytes = payloadMemoryLimit * 1024 * 1024;
  const ratio = limitBytes ? payloadCacheBytes / limitBytes : 0;
  const recent = evictionTimes.length;
  const summary = `${formatBytes(payloadCacheBytes)} / ${payloadMemoryLimit} MiB · ${payloadRecords.length} payloads`;
  byId('cache-summary').textContent = summary;
  const stats = byId('cache-stats');
  const alert = byId('cache-alert');
  if (recent > 0) {
    stats.textContent = `${payloadsDropped} evicted (${recent} in the last minute, ${formatBytes(payloadBytesDropped)} total). Increase the limit if older payloads are needed.`;
    stats.className = 'cache-stats pressure';
    alert.hidden = false;
    alert.className = 'cache-alert pressure';
    alert.textContent = '=!!=';
    alert.title = `${recent} payloads evicted in the last minute`;
  } else if (ratio >= 0.8 || payloadRecords.length >= payloadRecordLimit * 0.8) {
    stats.textContent = 'Cache is near its limit. Increase it only if older payloads disappear too soon.';
    stats.className = 'cache-stats warn';
    alert.hidden = false;
    alert.className = 'cache-alert warn';
    alert.textContent = '=!=';
    alert.title = 'Browser cache is near its configured limit';
  } else {
    stats.textContent = `${Math.round(ratio * 100)}% memory pressure. Current limit is healthy.`;
    stats.className = 'cache-stats';
    alert.hidden = true;
    alert.className = 'cache-alert';
    alert.textContent = '=!=';
    alert.title = '';
  }
}

function scheduleRender(eventsChanged = false, payloadsChanged = false) {
  eventsDirty ||= eventsChanged;
  payloadsDirty ||= payloadsChanged;
  if (renderFrame !== null) return;
  renderFrame = requestAnimationFrame(() => {
    renderFrame = null;
    if (eventsDirty && activeTab === 'events-tab') {
      renderEvents();
      eventsDirty = false;
    }
    if (payloadsDirty && activeTab === 'workbench-tab') {
      if (selectedPayload) {
        payloadBytes = recordPayloadBytes(selectedPayload);
        replacementBase64 = null;
        renderPayload();
      }
      renderPayloadList();
      payloadsDirty = false;
    }
    if (payloadsDirty || activeTab.startsWith('flow-follow-')) {
      for (const sessionId of followedFlows.keys()) {
        if (activeTab === followedFlows.get(sessionId).id) renderFlowTab(sessionId);
      }
      payloadsDirty = false;
    }
  });
}

function decodeBase64(value) {
  const binary = atob(value || '');
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

function encodeBase64(bytes) {
  let binary = '';
  const block = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += block) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + block));
  }
  return btoa(binary);
}

function recordPayloadBytes(record) {
  return record?.binaryPayload instanceof Uint8Array
    ? record.binaryPayload : decodeBase64(record?.event?.details?.info?.content);
}

function encodeHex(bytes, baseOffset = 0) {
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.subarray(offset, offset + 16);
    const hex = Array.from(row, value => value.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const ascii = Array.from(row, value => value >= 32 && value < 127 ? String.fromCharCode(value) : '.').join('');
    rows.push(`${(baseOffset + offset).toString(16).padStart(8, '0')}  ${hex}  |${ascii}|`);
  }
  return rows.join('\n');
}

function l7PayloadView(record, source = null) {
  const info = record?.event?.details?.info;
  if (source === null) source = recordPayloadBytes(record);
  if (!info || !Array.isArray(info.L7_payload_start) ||
      !Array.isArray(info.L7_payload_end) ||
      info.L7_payload_start.length !== info.L7_payload_end.length ||
      !info.L7_payload_start.length) {
    return {state: 'unavailable', ranges: [], encodings: [], bytes: new Uint8Array()};
  }
  const starts = info.L7_payload_start.map(Number);
  const ends = info.L7_payload_end.map(Number);
  if (starts.some(value => value === -1) || ends.some(value => value === -1)) {
    return {state: 'unknown', ranges: [], encodings: [], bytes: new Uint8Array()};
  }
  if (starts.length === 1 && starts[0] === 0 && ends[0] === 0) {
    return {state: 'none', ranges: [], encodings: [], bytes: new Uint8Array()};
  }
  const ranges = [];
  for (let index = 0; index < starts.length; ++index) {
    const start = starts[index], end = ends[index];
    if (!Number.isInteger(start) || !Number.isInteger(end) ||
        start < 0 || end < start || end > source.length) {
      return {state: 'invalid', ranges: [], encodings: [], bytes: new Uint8Array()};
    }
    ranges.push({start, end});
  }
  const length = ranges.reduce((total, range) => total + range.end - range.start, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const range of ranges) {
    const part = source.subarray(range.start, range.end);
    bytes.set(part, offset);
    offset += part.length;
  }
  const supplied = Array.isArray(info.L7_encoding) ? info.L7_encoding : [];
  const encodings = ranges.map((_, index) => String(supplied[index] || '').trim());
  return {state: 'body', ranges, encodings, bytes};
}

function contentAnnotations(record, sourceLength = null) {
  const raw = record?.event?.details?.info?.content_annotations;
  if (!Array.isArray(raw)) return [];
  const limit = sourceLength === null ? Number.MAX_SAFE_INTEGER : sourceLength;
  const result = [];
  for (const item of raw) {
    const start = Number(Array.isArray(item) ? item[0] : item?.start);
    const end = Number(Array.isArray(item) ? item[1] : item?.end);
    const kind = String(Array.isArray(item) ? item[2] : item?.kind || '').trim();
    const attributes = Array.isArray(item) ? item[3] : item?.attributes;
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 ||
        end <= start || start >= limit || !kind) continue;
    result.push({start, end: Math.min(end, limit), kind,
      attributes: attributes && typeof attributes === 'object' && !Array.isArray(attributes)
        ? attributes : {}});
  }
  return result.sort((a, b) => a.start - b.start || a.end - b.end);
}

function annotationLabel(annotation) {
  return annotation.kind.replace(/^http1\./, 'H1 ').replace(/^h2\./, 'H2 ').replaceAll('_', ' ');
}

function annotationClass(annotation) {
  return annotation?.kind.split('.').slice(0, 2).join('-').replace(/[^a-z0-9-]/gi, '-') || '';
}

function appendAnnotationRail(target, record, wireBytes) {
  const annotations = contentAnnotations(record, wireBytes.length);
  if (!annotations.length) return false;
  const rail = document.createElement('div');
  rail.className = 'content-annotation-rail';
  rail.setAttribute('aria-label', `${annotations.length} content annotations`);
  for (const annotation of annotations) {
    const part = document.createElement('span');
    const family = annotationClass(annotation);
    part.className = `content-annotation ${family}`;
    part.style.flexGrow = String(annotation.end - annotation.start);
    const attributes = Object.entries(annotation.attributes)
      .map(([key, value]) => `${key}=${value}`).join(' · ');
    part.textContent = annotationLabel(annotation);
    part.title = `${annotation.kind} [${annotation.start}, ${annotation.end})` +
      (attributes ? `\n${attributes}` : '');
    rail.append(part);
  }
  target.append(rail);
  return true;
}

function appendAnnotatedPayload(target, bytes, annotations, mode) {
  if (!annotations.length) return false;
  const annotationAt = offset => annotations.find(item => offset >= item.start && offset < item.end);
  const appendRun = (text, annotation) => {
    if (!text) return;
    if (!annotation) {
      target.append(document.createTextNode(text));
      return;
    }
    const span = document.createElement('span');
    span.className = `annotation-bytes ${annotationClass(annotation)}`;
    span.textContent = text;
    span.title = `${annotation.kind} [${annotation.start}, ${annotation.end})`;
    target.append(span);
  };
  const appendRange = (start, end, render) => {
    let cursor = start;
    while (cursor < end) {
      const annotation = annotationAt(cursor);
      let boundary = end;
      if (annotation) boundary = Math.min(boundary, annotation.end);
      else {
        const next = annotations.find(item => item.start > cursor);
        if (next) boundary = Math.min(boundary, next.start);
      }
      appendRun(render(cursor, boundary), annotation);
      cursor = boundary;
    }
  };
  if (mode !== 'hex') {
    appendRange(0, bytes.length, (start, end) =>
      new TextDecoder().decode(bytes.subarray(start, end)));
    return true;
  }
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const end = Math.min(offset + 16, bytes.length);
    target.append(document.createTextNode(`${offset.toString(16).padStart(8, '0')}  `));
    appendRange(offset, end, (start, stop) => Array.from(bytes.subarray(start, stop),
      value => value.toString(16).padStart(2, '0')).join(' ') + (stop < end ? ' ' : ''));
    const used = (end - offset) * 3 - 1;
    target.append(document.createTextNode(`${' '.repeat(Math.max(0, 47 - used))}  |`));
    appendRange(offset, end, (start, stop) => Array.from(bytes.subarray(start, stop),
      value => value >= 32 && value < 127 ? String.fromCharCode(value) : '.').join(''));
    target.append(document.createTextNode(`|${end < bytes.length ? '\n' : ''}`));
  }
  return true;
}

function l7PayloadSummary(view) {
  if (view.state === 'unknown') return 'L7 location unknown';
  if (view.state === 'none') return 'no L7 body';
  if (view.state === 'invalid') return 'invalid L7 ranges';
  if (view.state === 'unavailable') return 'no L7 metadata';
  const encodings = [...new Set(view.encodings.filter(Boolean))];
  const ranges = `${view.ranges.length} ${view.ranges.length === 1 ? 'range' : 'ranges'}`;
  return `L7 ${formatBytes(view.bytes.length)} · ${ranges}` +
    (encodings.length ? ` · ${encodings.join(', ')}` : '');
}

function l7PayloadMarker(record, source = null) {
  const view = l7PayloadView(record, source);
  const marker = document.createElement('span');
  marker.className = `l7-marker ${view.state}`;
  if (view.state === 'body') marker.textContent = `L7 ${formatBytes(view.bytes.length)}`;
  else if (view.state === 'none') marker.textContent = 'NO BODY';
  else if (view.state === 'unknown') marker.textContent = 'L7 ?';
  else if (view.state === 'invalid') marker.textContent = 'L7 !';
  else marker.textContent = 'L7 —';
  const ranges = view.ranges.map((range, index) =>
    `[${range.start}, ${range.end})${view.encodings[index] ? ` ${view.encodings[index]}` : ''}`);
  marker.title = ranges.length ? ranges.join(', ') : l7PayloadSummary(view);
  marker.tabIndex = 0;
  marker.setAttribute('role', 'button');
  marker.setAttribute('aria-label', `Show ${l7PayloadSummary(view)}`);
  const showL7 = event => {
    event.preventDefault();
    event.stopPropagation();
    if (record) selectPayload(record, false);
    setPayloadScope('l7');
  };
  marker.onclick = showL7;
  marker.onkeydown = event => {
    if (event.key === 'Enter' || event.key === ' ') showL7(event);
  };
  return marker;
}

function enrichmentMarker(record, activate = null, active = false) {
  if (!record?.enrichments?.length) return null;
  const descriptions = record.enrichments.map(item => {
    const metadata = item?.metadata || {};
    const operation = String(metadata.operation || '');
    const headers = enrichmentHeaders(item);
    if (operation === 'hpack.decode') return `H2 headers${headers.length ? ` (${headers.length})` : ''}`;
    if (operation === 'http1.parse-head') {
      const kind = metadata.message?.kind;
      return `H1${kind ? ` ${kind}` : ''} headers${headers.length ? ` (${headers.length})` : ''}`;
    }
    if (operation === 'gzip.inflate') return 'gzip decoded';
    if (operation === 'deflate.inflate') return 'deflate decoded';
    const contentType = String(metadata.content_type || '').split(';', 1)[0];
    return contentType && contentType !== 'application/octet-stream'
      ? contentType : operation || 'derived content';
  });
  const unique = [...new Set(descriptions)];
  const label = unique.length <= 2 ? unique.join(' + ') : `${unique[0]} +${unique.length - 1}`;
  const marker = document.createElement('span');
  marker.className = 'enrichment-marker';
  marker.textContent = label;
  marker.title = record.enrichments.map((item, index) => {
    const metadata = item?.metadata || {};
    const headers = enrichmentHeaders(item);
    return `${index + 1}. ${descriptions[index]}` +
      `${metadata.operation ? ` · ${metadata.operation}` : ''}` +
      `${item?.payload?.length ? ` · ${formatBytes(item.payload.length)}` : ''}` +
      `${headers.length ? ` · ${headers.length} fields` : ''}`;
  }).join('\n');
  marker.tabIndex = 0;
  marker.setAttribute('role', 'button');
  marker.setAttribute('aria-pressed', String(active));
  marker.setAttribute('aria-label', `Toggle enrichment: ${label}`);
  const show = event => {
    event.preventDefault();
    event.stopPropagation();
    if (activate) activate();
    else {
      selectPayload(record, false);
      const viewer = byId('enrichment-viewer');
      viewer.hidden = false;
      viewer.open = true;
    }
  };
  marker.onclick = show;
  marker.onkeydown = event => {
    if (event.key === 'Enter' || event.key === ' ') show(event);
  };
  return marker;
}

function enrichmentHeaders(item) {
  const metadata = item?.metadata || {};
  const fields = Array.isArray(metadata.headers) ? metadata.headers : metadata.message?.headers;
  return Array.isArray(fields) ? fields.filter(field => field && typeof field.name === 'string') : [];
}

function enrichmentStartLine(item) {
  const message = item?.metadata?.message;
  if (!message || typeof message !== 'object') return '';
  if (message.kind === 'request')
    return `${message.method || '?'} ${message.target || '?'} ${message.version || ''}`.trim();
  if (message.kind === 'response')
    return `${message.version || ''} ${message.status || '?'} ${message.reason || ''}`.trim();
  return '';
}

function enrichmentStreamId(item) {
  const value = Number(item?.metadata?.source?.stream_id);
  return Number.isInteger(value) && value > 0 ? value : null;
}

function enrichmentContentType(record, item, records) {
  const streamId = enrichmentStreamId(item);
  const side = record.event.details?.info?.side === 'R' ? 'R' : 'L';
  for (let index = records.indexOf(record); index >= 0; --index) {
    const candidate = records[index];
    if (candidate.event.id !== record.event.id ||
        (candidate.event.details?.info?.side === 'R' ? 'R' : 'L') !== side) continue;
    for (const enrichment of [...(candidate.enrichments || [])].reverse()) {
      if (streamId !== null && enrichmentStreamId(enrichment) !== streamId) continue;
      const type = enrichmentHeaders(enrichment).find(field =>
        field.name.toLowerCase() === 'content-type')?.value;
      if (type) return String(type);
    }
  }
  return item?.metadata?.content_type || 'application/octet-stream';
}

function enrichmentViewKind(contentType) {
  const mime = String(contentType).split(';', 1)[0].trim().toLowerCase();
  return new Set([
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif',
    'image/bmp', 'image/x-icon', 'image/vnd.microsoft.icon',
  ]).has(mime) ? {kind: 'image', mime} : null;
}

function humanContentKind(contentType) {
  const mime = String(contentType || 'application/octet-stream').split(';', 1)[0].trim().toLowerCase();
  const visual = enrichmentViewKind(mime);
  if (visual) return visual;
  if (mime.startsWith('text/') || /(?:json|xml|javascript|x-www-form-urlencoded)$/.test(mime)) {
    return {kind: 'text', mime};
  }
  return {kind: 'bytes', mime};
}

function humanRecordStreamId(record) {
  const annotation = contentAnnotations(record).find(item =>
    item.kind === 'h2.data' && Number.isInteger(Number(item.attributes?.stream_id)));
  return annotation ? Number(annotation.attributes.stream_id) : null;
}

function humanRecordContentType(record, records) {
  const streamId = humanRecordStreamId(record);
  const side = record.event.details?.info?.side === 'R' ? 'R' : 'L';
  for (let index = records.indexOf(record); index >= 0; --index) {
    const candidate = records[index];
    if (candidate.event.id !== record.event.id ||
        (candidate.event.details?.info?.side === 'R' ? 'R' : 'L') !== side) continue;
    for (const enrichment of [...(candidate.enrichments || [])].reverse()) {
      if (streamId !== null && enrichmentStreamId(enrichment) !== streamId) continue;
      const type = enrichmentHeaders(enrichment).find(field =>
        field.name.toLowerCase() === 'content-type')?.value;
      if (type) return String(type);
    }
  }
  return null;
}

function sniffHumanContentType(bytes) {
  if (!bytes?.length) return null;
  if (bytes.length >= 8 && [137, 80, 78, 71, 13, 10, 26, 10]
      .every((value, index) => bytes[index] === value)) return 'image/png';
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff)
    return 'image/jpeg';
  if (bytes.length >= 6 && new TextDecoder().decode(bytes.subarray(0, 6)).startsWith('GIF8'))
    return 'image/gif';
  if (bytes.length >= 12 && new TextDecoder().decode(bytes.subarray(0, 4)) === 'RIFF' &&
      new TextDecoder().decode(bytes.subarray(8, 12)) === 'WEBP') return 'image/webp';
  const sample = new TextDecoder().decode(bytes.subarray(0, Math.min(bytes.length, 4096))).trimStart();
  if (sample.startsWith('{') || sample.startsWith('[')) return 'application/json';
  if (/^<!doctype\s+html|^<html[\s>]/i.test(sample)) return 'text/html';
  if (/^<\?xml[\s?]|^<svg[\s>]/i.test(sample)) return 'application/xml';
  const inspected = bytes.subarray(0, Math.min(bytes.length, 1024));
  const printable = [...inspected].filter(value => value === 9 || value === 10 || value === 13 ||
    (value >= 32 && value < 127)).length;
  return printable / inspected.length >= 0.85 ? 'text/plain' : null;
}

function humanRepresentation(record, records, fallbackBytes) {
  const enrichments = record?.enrichments || [];
  const payloadItem = [...enrichments].reverse().find(item => item?.payload?.length);
  if (payloadItem) {
    const contentType = enrichmentContentType(record, payloadItem, records);
    return {...humanContentKind(contentType), contentType, bytes: payloadItem.payload,
      operation: payloadItem.metadata?.operation || 'derived content'};
  }
  const headerItem = [...enrichments].reverse().find(item => enrichmentHeaders(item).length);
  if (headerItem) {
    const headers = enrichmentHeaders(headerItem);
    const startLine = enrichmentStartLine(headerItem);
    return {kind: 'headers', contentType: 'HTTP fields', operation: headerItem.metadata?.operation ||
      'decoded headers', text: `${startLine ? `${startLine}\n` : ''}${headers.map(field =>
        `${field.name}: ${field.value ?? ''}`).join('\n')}`};
  }
  const l7 = l7PayloadView(record);
  const bytes = l7.state === 'body' ? l7.bytes : fallbackBytes || new Uint8Array();
  const contentType = humanRecordContentType(record, records) || sniffHumanContentType(bytes);
  return {...humanContentKind(contentType),
    contentType: contentType || 'unclassified bytes', operation: contentType ? 'content' : 'payload', bytes};
}

function humanText(representation, byteLimit = null) {
  const source = representation.bytes || new Uint8Array();
  const bytes = byteLimit === null ? source : source.subarray(0, byteLimit);
  const decoded = new TextDecoder().decode(bytes);
  if (representation.kind !== 'text' || !/(?:\/|\+)json$/.test(representation.contentType.split(';', 1)[0])) {
    return decoded;
  }
  if (bytes.length !== source.length) return decoded;
  try {
    return JSON.stringify(JSON.parse(decoded), null, 2);
  } catch (_) {
    return decoded;
  }
}

function closeFloatingEnrichment() {
  const floating = document.querySelector('.floating-enrichment');
  if (!floating) return;
  if (floating.dataset.objectUrl) URL.revokeObjectURL(floating.dataset.objectUrl);
  floating.remove();
}

function createFloatingEnrichment(title) {
  closeFloatingEnrichment();
  const floating = document.createElement('section');
  floating.className = 'floating-enrichment';
  floating.setAttribute('role', 'dialog');
  floating.setAttribute('aria-label', title);
  const head = document.createElement('header');
  const label = document.createElement('b');
  label.textContent = title;
  const close = document.createElement('button');
  close.type = 'button'; close.textContent = '×'; close.title = 'Close floating view';
  close.onclick = closeFloatingEnrichment;
  head.append(label, close);
  floating.append(head);
  document.body.append(floating);
  head.onpointerdown = event => {
    if (event.target.closest('button')) return;
    event.preventDefault();
    const bounds = floating.getBoundingClientRect();
    const offsetX = event.clientX - bounds.left, offsetY = event.clientY - bounds.top;
    head.setPointerCapture(event.pointerId);
    head.onpointermove = move => {
      if (!head.hasPointerCapture(move.pointerId)) return;
      floating.style.left = `${Math.max(0, Math.min(innerWidth - 120, move.clientX - offsetX))}px`;
      floating.style.top = `${Math.max(0, Math.min(innerHeight - 48, move.clientY - offsetY))}px`;
      floating.style.right = 'auto';
    };
    head.onpointerup = move => {
      head.releasePointerCapture(move.pointerId);
      head.onpointermove = null;
      head.onpointerup = null;
    };
  };
  return floating;
}

function openFloatingEnrichment(item, supported, title) {
  const floating = createFloatingEnrichment(title);
  const objectUrl = URL.createObjectURL(new Blob([item.payload], {type: supported.mime}));
  floating.dataset.objectUrl = objectUrl;
  const image = document.createElement('img');
  image.alt = title;
  const status = document.createElement('small');
  status.textContent = `decoding ${supported.mime}…`;
  image.onload = () => {
    status.textContent = `${image.naturalWidth} × ${image.naturalHeight} · ${formatBytes(item.payload.length)} · ${supported.mime}`;
  };
  image.onerror = () => {
    status.textContent = `Browser could not decode this ${supported.mime} payload.`;
  };
  image.src = objectUrl;
  floating.append(image, status);
}

function openFloatingHuman(representation) {
  const title = `${representation.operation} · ${representation.contentType}`;
  const floating = createFloatingEnrichment(title);
  const status = document.createElement('small');
  if (representation.kind === 'image') {
    const objectUrl = URL.createObjectURL(new Blob([representation.bytes],
      {type: representation.contentType}));
    floating.dataset.objectUrl = objectUrl;
    const image = document.createElement('img');
    image.alt = title;
    image.onload = () => {
      status.textContent = `${image.naturalWidth} × ${image.naturalHeight} · ${formatBytes(representation.bytes.length)}`;
    };
    image.onerror = () => { status.textContent = 'Browser could not render this payload.'; };
    image.src = objectUrl;
    floating.append(image, status);
    return;
  }
  const content = document.createElement('pre');
  const previewLimit = 8 * 1024 * 1024;
  if (representation.kind === 'headers') content.textContent = representation.text;
  else if (representation.kind === 'text') content.textContent = humanText(representation, previewLimit);
  else appendMixedAscii(content, representation.bytes.subarray(0, previewLimit));
  if (representation.bytes?.length > previewLimit) content.append(document.createTextNode(
    `\n[… ${formatBytes(representation.bytes.length - previewLimit)} omitted from this view]`));
  status.textContent = representation.bytes ? formatBytes(representation.bytes.length) : 'decoded metadata';
  floating.append(content, status);
}

function renderHumanPreview(target, record, records, fallbackBytes, limit = 640) {
  const representation = humanRepresentation(record, records, fallbackBytes);
  target.replaceChildren();
  target.classList.add('human-preview');
  const head = document.createElement('span');
  head.className = 'human-preview-head';
  const label = document.createElement('span');
  label.textContent = `${representation.operation} · ${representation.contentType}`;
  const floating = document.createElement('button');
  floating.type = 'button'; floating.textContent = 'Float';
  floating.title = 'Open the complete human-readable representation in a floating window';
  floating.onclick = event => {
    event.preventDefault();
    event.stopPropagation();
    openFloatingHuman(representation);
  };
  head.append(label, floating);
  target.append(head);
  if (representation.kind === 'image') {
    const image = document.createElement('img');
    image.className = 'human-preview-image';
    image.alt = `${representation.operation} preview`;
    const objectUrl = URL.createObjectURL(new Blob([representation.bytes],
      {type: representation.contentType}));
    image.onload = image.onerror = () => URL.revokeObjectURL(objectUrl);
    image.src = objectUrl;
    target.append(image);
    return;
  }
  const body = document.createElement('span');
  body.className = 'human-preview-body';
  const text = representation.kind === 'headers' ? representation.text :
    representation.kind === 'text' ? humanText(representation, limit) : null;
  if (text !== null) {
    body.textContent = text.slice(0, limit);
    if (representation.kind === 'text' && representation.bytes.length > limit) {
      body.append(document.createTextNode(
        `\n[… ${formatBytes(representation.bytes.length - limit)} more]`));
    } else if (text.length > limit) {
      body.append(document.createTextNode(`\n[… ${text.length - limit} more characters]`));
    }
  } else {
    appendMixedAscii(body, representation.bytes.subarray(0, limit));
    if (representation.bytes.length > limit) body.append(document.createTextNode(
      `\n[… ${formatBytes(representation.bytes.length - limit)} more]`));
  }
  target.append(body);
}

function appendEnrichmentView(card, item, contentType) {
  const supported = enrichmentViewKind(contentType);
  if (!supported || !item.payload?.length) return null;
  const viewer = document.createElement('div');
  viewer.className = 'inline-enrichment-media';
  viewer.hidden = true;
  const image = document.createElement('img');
  image.alt = `Decoded ${supported.mime} payload`;
  const status = document.createElement('small');
  viewer.append(image, status);
  card.append(viewer);
  let objectUrl = null;
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'inline-enrichment-view';
  button.textContent = 'View';
  button.title = `Render ${supported.mime} with the browser image decoder`;
  button.onclick = event => {
    event.preventDefault();
    event.stopPropagation();
    const opening = viewer.hidden;
    viewer.hidden = !opening;
    button.textContent = opening ? 'Hide' : 'View';
    button.setAttribute('aria-pressed', String(opening));
    if (!opening) return;
    status.textContent = 'decoding…';
    objectUrl = URL.createObjectURL(new Blob([item.payload], {type: supported.mime}));
    image.onload = () => {
      status.textContent = `${image.naturalWidth} × ${image.naturalHeight} · ${formatBytes(item.payload.length)}`;
      URL.revokeObjectURL(objectUrl);
      objectUrl = null;
    };
    image.onerror = () => {
      status.textContent = `Browser could not decode this ${supported.mime} payload.`;
      URL.revokeObjectURL(objectUrl);
      objectUrl = null;
    };
    image.src = objectUrl;
  };
  const floating = document.createElement('button');
  floating.type = 'button';
  floating.className = 'inline-enrichment-view';
  floating.textContent = 'Float';
  floating.title = 'Open a movable, resizable view without changing the flow layout';
  floating.onclick = event => {
    event.preventDefault();
    event.stopPropagation();
    openFloatingEnrichment(item, supported, `Enrichment · ${supported.mime}`);
  };
  return [button, floating];
}

function appendInlineEnrichments(target, record, records) {
  target.replaceChildren();
  for (const item of record.enrichments || []) {
    const metadata = item?.metadata || {};
    const headers = enrichmentHeaders(item);
    const card = document.createElement('details');
    card.className = 'inline-enrichment-card';
    card.open = true;
    const summary = document.createElement('summary');
    const operation = document.createElement('b');
    operation.textContent = metadata.operation || 'derived content';
    const description = document.createElement('span');
    const streamId = enrichmentStreamId(item);
    let contentType = metadata.content_type || 'application/octet-stream';
    if (headers.length) {
      description.textContent = `${headers.length} headers${streamId ? ` · H2 stream ${streamId}` : ''}`;
    } else {
      contentType = enrichmentContentType(record, item, records);
      description.textContent = `${contentType} · ${formatBytes(item.payload?.length || 0)}` +
        `${metadata.content_encoding ? ` · decoded ${metadata.content_encoding}` : ''}` +
        `${streamId ? ` · H2 stream ${streamId}` : ''}`;
    }
    const declared = metadata.provenance || {};
    const provenance = document.createElement('small');
    provenance.className = 'enrichment-provenance';
    const parts = [
      `hints: ${declared.ranges || 'smithproxy'}`,
      `type: ${declared.content_type || 'spider'}`,
      `decoded: ${declared.transform || 'spider'}`,
    ];
    if (declared.encoding) parts.splice(2, 0, `encoding: ${declared.encoding}`);
    provenance.textContent = parts.join(' · ');
    provenance.title = 'Origin of the ranges and metadata used to produce this derived view';
    summary.append(operation, description, provenance);
    card.append(summary);
    const view = appendEnrichmentView(card, item, contentType);
    if (view) summary.append(...view);
    if (headers.length) {
      const fields = document.createElement('pre');
      const startLine = enrichmentStartLine(item);
      fields.textContent = `${startLine ? `${startLine}\n` : ''}${headers.map(field =>
        `${field.name}: ${field.value ?? ''}`).join('\n')}`;
      card.append(fields);
    }
    if (item.payload?.length) {
      const payload = document.createElement('pre');
      payload.className = 'inline-enrichment-payload';
      const previewLimit = 16384;
      appendMixedAscii(payload, item.payload.subarray(0, previewLimit));
      if (item.payload.length > previewLimit) payload.append(document.createTextNode(
        `\n[… ${formatBytes(item.payload.length - previewLimit)} more]`));
      card.append(payload);
    }
    target.append(card);
  }
}

function attachInlineEnrichments(container, record, records, followed) {
  if (!record?.enrichments?.length) return null;
  followed.openEnrichments ||= new Set();
  const revision = String(record.revision);
  const panel = document.createElement('div');
  panel.className = 'inline-enrichments';
  panel.hidden = !followed.openEnrichments.has(revision);
  appendInlineEnrichments(panel, record, records);
  const marker = enrichmentMarker(record, () => {
    const opening = panel.hidden;
    panel.hidden = !opening;
    marker.setAttribute('aria-pressed', String(opening));
    if (opening) {
      followed.openEnrichments.add(revision);
    } else {
      followed.openEnrichments.delete(revision);
    }
  }, !panel.hidden);
  container.append(panel);
  return marker;
}

function flowPayloadBytes(record, wireBytes) {
  return payloadScope === 'l7' ? l7PayloadView(record, wireBytes).bytes : wireBytes;
}

function setPayloadScope(scope) {
  payloadScope = scope === 'l7' ? 'l7' : 'wire';
  localStorage.setItem('spider-payload-scope', payloadScope);
  renderPayload();
  for (const followed of followedFlows.values()) followed.renderedMode = null;
  for (const id of followedFlows.keys()) renderFlowTab(id);
}

function scriptL7Metadata(record, source) {
  const view = l7PayloadView(record, source);
  return {
    state: view.state,
    ranges: view.ranges.map(range => [range.start, range.end]),
    encodings: view.encodings,
    bytes: Array.from(view.bytes),
  };
}

function scriptEnrichments(record) {
  return (record?.enrichments || []).map(item => ({
    metadata: item.metadata || {},
    bytes: Array.from(item.payload || []),
  }));
}

function renderPayload() {
  const l7 = l7PayloadView(selectedPayload, payloadBytes);
  const shownBytes = payloadScope === 'l7' ? l7.bytes : payloadBytes;
  if (payloadMode === 'hex') byId('payload-hex').textContent = encodeHex(shownBytes);
  else byId('payload-text').value = new TextDecoder().decode(shownBytes);
  byId('payload-text').readOnly = payloadScope === 'l7';
  byId('payload-text').title = payloadScope === 'l7'
    ? 'L7 view is derived from wire content and is read-only' : '';
  for (const button of document.querySelectorAll('#payload-scope button')) {
    button.setAttribute('aria-pressed', String(button.dataset.scope === payloadScope));
    if (button.dataset.scope === 'l7') {
      const ranges = l7.ranges.map((range, index) =>
        `[${range.start}, ${range.end})${l7.encodings[index] ? ` ${l7.encodings[index]}` : ''}`);
      button.title = ranges.length ? ranges.join(', ') : l7PayloadSummary(l7);
    }
  }
  byId('payload-viewer').dataset.l7State = payloadScope === 'l7' ? l7.state : '';
  const info = selectedPayload?.event?.details?.info || {};
  byId('workbench-source').textContent = selectedPayload
    ? `r${selectedPayload.revision} · ${info.side || '?'} · ${payloadBytes.length} B · ${resolvedSessionLabel(info.session || selectedPayload.event.id)}`
    : `${payloadBytes.length} B sample`;
  byId('workbench-source').className = '';
  byId('payload-view-title').textContent = `${payloadMode.toUpperCase()} ${payloadScope === 'l7' ? 'L7 body' : 'wire payload'}`;
  byId('payload-view-status').textContent = selectedPayload
    ? `${info.side || '?'} · ${payloadScope === 'l7' ? l7PayloadSummary(l7) : formatBytes(payloadBytes.length)} · r${selectedPayload.revision}`
    : `${shownBytes.length} B`;
  const inspection = payloadInspectionInfo(selectedPayload);
  renderWorkbenchInfo(inspection, selectedPayload);
  renderEnrichments(selectedPayload);
  const pending = selectedPayload?.event?.decision?.state === 'pending' && !selectedPayload.decided;
  byId('accept-payload').disabled = !pending;
  byId('accept-session').disabled = !pending;
  byId('discard-payload').disabled = !pending;
  byId('replace-payload').disabled = !pending || replacementBase64 === null;
}

function renderEnrichments(record) {
  const viewer = byId('enrichment-viewer');
  const enrichments = Array.isArray(record?.enrichments) ? record.enrichments : [];
  viewer.hidden = false;
  viewer.classList.toggle('empty', enrichments.length === 0);
  if (!enrichments.length) {
    viewer.open = false;
  }
  byId('enrichment-count').textContent = String(enrichments.length);
  const content = byId('enrichment-content');
  content.replaceChildren();
  enrichments.forEach((item, index) => {
    const metadata = item?.metadata || {};
    const body = {...metadata};
    delete body.type;
    if (index) content.append(document.createTextNode('\n\n'));
    content.append(document.createTextNode(
      `${metadata.operation || metadata.content_type || 'derived content'}\n` +
      JSON.stringify(body, null, 2)));
    if (item.payload?.length) {
      const previewLimit = 8192;
      content.append(document.createTextNode(`\n\nDecoded payload (${formatBytes(item.payload.length)}):\n`));
      appendMixedAscii(content, item.payload.subarray(0, previewLimit));
      if (item.payload.length > previewLimit)
        content.append(document.createTextNode(
          `\n[… ${formatBytes(item.payload.length - previewLimit)} more]`));
    }
  });
}

function workbenchSiftClassifications(record) {
  const sessionId = record?.event?.id;
  if (!sessionId) return [];
  const live = liveSiftClassifications.get(sessionId);
  if (live?.length) return live;
  const session = activeSessionRecords.find(item => item.id === sessionId) ||
    historyRecords.find(item => item.id === sessionId);
  return siftClassifications(session);
}

function renderWorkbenchInfo(inspection, record) {
  const target = byId('workbench-info');
  const classifications = workbenchSiftClassifications(record);
  if (!inspection && !classifications.length) {
    target.textContent = 'no inspection metadata';
    target.className = 'empty';
    return;
  }
  target.className = 'workbench-info-line';
  target.innerHTML = inspection
    ? `<span class="inspection-summary">${escapeHtml(inspection)}</span>`
    : '';
  if (classifications.length) {
    target.insertAdjacentHTML('beforeend',
      `<b class="sift-label">Sift</b>${classificationChips(classifications)}`);
  }
}

function payloadInspectionInfo(record) {
  if (!record) return payloadBytes.length ? 'synthetic sample' : '';
  const info = record.event.details?.info || {};
  const connection = parseSessionLabel(info.session);
  const labels = [];
  if ([connection?.sourceProtocol, connection?.destinationProtocol].includes('ssli')) {
    labels.push('TLS inspection');
  }
  const layer = String(info.payload_layer || '').trim();
  if (layer) labels.push(`${layer.toUpperCase()} payload`);
  if (Array.isArray(info.L7_payload_start)) labels.push(l7PayloadSummary(l7PayloadView(record)));
  if (info.l7?.app) labels.push(String(info.l7.app));
  if (record.inspectResult) labels.push(`INSPECT ${record.inspectResult}`);
  if (record.event.decision?.state === 'pending' && !record.decided) labels.push('awaiting decision');
  else if (record.event.decision?.state === 'auto-accepted') labels.push('auto-accepted');
  return [...new Set(labels)].join(' · ');
}

let payloadMode = 'ascii';
function setPayloadMode(mode) {
  payloadMode = mode === 'hex' ? 'hex' : 'ascii';
  const hex = payloadMode === 'hex';
  byId('payload-text').hidden = hex;
  byId('payload-hex').hidden = !hex;
  for (const button of document.querySelectorAll('#payload-modes button')) {
    button.setAttribute('aria-pressed', String(button.dataset.mode === payloadMode));
  }
  localStorage.setItem('spider-payload-mode', payloadMode);
  renderPayload();
  for (const followed of followedFlows.values()) followed.renderedMode = null;
  for (const sessionId of followedFlows.keys()) renderFlowTab(sessionId);
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
  renderInspectionOverview();
  const list = byId('payload-list');
  const flows = [...flowRecords.values()].sort((a, b) =>
    Number(b.active) - Number(a.active) || b.lastRevision - a.lastRevision);
  const rows = payloadListView === 'flows' ? flows : payloadRecords;
  byId('payload-list-title').textContent = payloadListView === 'flows' ? 'Flows' : 'Payloads';
  byId('payload-count').textContent = rows.length;
  for (const button of document.querySelectorAll('#payload-views button')) {
    button.setAttribute('aria-pressed', String(button.dataset.view === payloadListView));
  }
  list.replaceChildren();
  if (!rows.length) {
    list.textContent = 'none';
    list.className = 'payload-list empty';
    return;
  }
  list.className = 'payload-list';
  if (payloadListView === 'flows') {
    const flowPeers = new Map();
    for (const flow of flows) {
      const connection = parseSessionLabel(flow.label);
      if (!connection) continue;
      const key = `${connection.sourceHost}|${connection.destinationHost}|${connection.destinationPort}`;
      flowPeers.set(key, (flowPeers.get(key) || 0) + 1);
    }
    for (const flow of flows) {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = `flow-row${selectedPayload?.event?.id === flow.id ? ' selected' : ''}` +
        `${flow.active ? '' : ' inactive'}`;
      const label = document.createElement('span');
      const connection = parseSessionLabel(flow.label);
      const peerKey = connection && `${connection.sourceHost}|${connection.destinationHost}|${connection.destinationPort}`;
      label.textContent = flowListLabel(flow.label || flow.id, (flowPeers.get(peerKey) || 0) > 1);
      const markers = [];
      if (!flow.complete) {
        const incomplete = document.createElement('b');
        incomplete.className = 'flow-incomplete-marker';
        incomplete.textContent = 'I';
        markers.push(incomplete);
      }
      if (flow.evicted) {
        const evicted = document.createElement('b');
        evicted.className = 'flow-evicted-marker';
        evicted.textContent = 'E';
        markers.push(evicted);
      }
      if (markers.length) label.prepend(...markers, ' ');
      const warnings = [];
      if (!flow.complete) warnings.push('Incomplete: connection-start was not observed');
      if (flow.evicted) warnings.push(`Evicted: ${flow.evicted} payloads left the browser cache`);
      label.title = `${warnings.length ? `${warnings.join('\n')}\n` : ''}${flow.label || flow.id}`;
      const left = document.createElement('span');
      left.className = 'flow-side';
      left.innerHTML = `L ${flow.L.count} · ${escapeHtml(formatBytes(flow.L.bytes))}` +
        `<small>${flow.L.l7Payloads ? `L7 ${escapeHtml(formatBytes(flow.L.l7Bytes))}` :
          flow.L.l7Unknown ? 'L7 ?' : 'no L7 body'}</small>`;
      const right = document.createElement('span');
      right.className = 'flow-side';
      right.innerHTML = `R ${flow.R.count} · ${escapeHtml(formatBytes(flow.R.bytes))}` +
        `<small>${flow.R.l7Payloads ? `L7 ${escapeHtml(formatBytes(flow.R.l7Bytes))}` :
          flow.R.l7Unknown ? 'L7 ?' : 'no L7 body'}</small>`;
      row.append(label, left, right);
      row.onclick = () => {
        if (!flow.latest) return;
        selectPayload(flow.latest, false);
        pinSession(flow.latest, false);
      };
      row.oncontextmenu = event => openFlowMenu(event, flow.id);
      list.append(row);
    }
    if (followPayload) list.scrollTop = 0;
    return;
  }
  for (let index = payloadRecords.length - 1; index >= 0; --index) {
    const record = payloadRecords[index];
    const info = record.event.details?.info || {};
    const size = recordPayloadBytes(record).length;
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `payload-row${record === selectedPayload ? ' selected' : ''}` +
      `${record.event.decision?.state === 'pending' && !record.decided ? ' pending' : ''}` +
      `${record.decided ? ' decided' : ''}`;
    row.innerHTML = `<span>r${record.revision}</span><b>${escapeHtml(info.side || '?')}</b>` +
      `<span>${escapeHtml(formatBytes(size) || `${size} B`)}</span>`;
    row.append(l7PayloadMarker(record));
    const enriched = enrichmentMarker(record);
    if (enriched) row.append(enriched);
    const session = document.createElement('span');
    session.className = 'payload-session-label';
    session.textContent = resolvedSessionLabel(info.session || record.event.id || 'unlabelled');
    row.append(session);
    row.onclick = () => {
      selectPayload(record, false);
      pinSession(record, false);
    };
    row.oncontextmenu = event => openFlowMenu(event, record.event.id);
    list.append(row);
  }
  if (followPayload) list.scrollTop = 0;
}

function flowTabId(sessionId) {
  let hash = 2166136261;
  for (const character of String(sessionId)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return `flow-follow-${(hash >>> 0).toString(16)}`;
}

function openFlowMenu(event, sessionId) {
  event.preventDefault();
  flowMenuSession = sessionId;
  const menu = byId('flow-menu');
  menu.hidden = false;
  menu.style.left = `${Math.min(event.clientX, innerWidth - 210)}px`;
  menu.style.top = `${Math.min(event.clientY, innerHeight - 130)}px`;
}

function strictConnectionLabel(label) {
  const connection = parseSessionLabel(label);
  if (!connection) return resolvedSessionLabel(label);
  return `${resolvedAddress(connection.sourceHost)}:${connection.sourcePort} → ` +
    `${resolvedAddress(connection.destinationHost)}:${connection.destinationPort}`;
}

function flowListLabel(label, showSourcePort = false) {
  const connection = parseSessionLabel(label);
  if (!connection) return resolvedSessionLabel(label);
  if (!compactSessionLabels || showSourcePort) return strictConnectionLabel(label);
  return `${resolvedAddress(connection.sourceHost)} → ` +
    `${resolvedAddress(connection.destinationHost)}:${connection.destinationPort}`;
}

function flowScope(sessionId, type = 'connection') {
  const flow = flowRecords.get(sessionId);
  const label = flow?.label || payloadRecords.find(record => record.event.id === sessionId)
    ?.event?.details?.info?.session || sessionId;
  const connection = parseSessionLabel(label);
  if (!connection || type === 'connection') return {
    key: `connection:${sessionId}`, type: 'connection', sessionId, label,
    title: `Conn :${connection?.sourcePort || '?'}`,
  };
  if (type === 'service') return {
    key: `service:${connection.sourceHost}|${connection.destinationHost}|${connection.destinationPort}`,
    type, sourceHost: connection.sourceHost, destinationHost: connection.destinationHost,
    destinationPort: connection.destinationPort, label,
    title: `Service ${resolvedAddress(connection.destinationHost)}:${connection.destinationPort}`,
  };
  return {
    key: `client:${connection.sourceHost}`, type: 'client', sourceHost: connection.sourceHost,
    label, title: `Client ${resolvedAddress(connection.sourceHost)}`,
  };
}

function scopeMatches(scope, record) {
  if (scope.type === 'connection') return record.event.id === scope.sessionId;
  const connection = parseSessionLabel(record.event.details?.info?.session);
  if (!connection || connection.sourceHost !== scope.sourceHost) return false;
  return scope.type === 'client' ||
    (connection.destinationHost === scope.destinationHost &&
     connection.destinationPort === scope.destinationPort);
}

function scopeMatchesEvent(scope, record) {
  if (scope.type === 'connection') return record.event.id === scope.sessionId;
  const explicit = record.event.details?.info?.session;
  const label = explicit || flowRecords.get(record.event.id)?.label;
  const connection = parseSessionLabel(label);
  if (!connection || connection.sourceHost !== scope.sourceHost) return false;
  return scope.type === 'client' ||
    (connection.destinationHost === scope.destinationHost &&
     connection.destinationPort === scope.destinationPort);
}

function renderFlowMessages(stream, followed) {
  const records = eventRecords.filter(record => scopeMatchesEvent(followed, record))
    .sort((a, b) => a.revision - b.revision);
  stream.className = 'flow-stream flow-messages';
  if (stream.dataset.renderKind !== 'messages') {
    stream.replaceChildren();
    stream.dataset.renderKind = 'messages';
  }
  followed.openMessages ||= new Set();
  const wanted = new Set(records.map(record => String(record.revision)));
  for (const message of stream.querySelectorAll('.flow-message[data-revision]')) {
    if (wanted.has(message.dataset.revision)) continue;
    followed.openMessages.delete(message.dataset.revision);
    message.remove();
  }
  const rendered = new Set([...stream.querySelectorAll('.flow-message[data-revision]')]
    .map(message => message.dataset.revision));
  for (const record of records) {
    const recordRevision = String(record.revision);
    if (rendered.has(recordRevision)) continue;
    const message = document.createElement('details');
    message.className = `flow-message ${eventCategory(record.event)}`;
    message.dataset.revision = recordRevision;
    message.open = followed.openMessages.has(recordRevision);
    message.ontoggle = () => {
      if (message.open) followed.openMessages.add(recordRevision);
      else followed.openMessages.delete(recordRevision);
    };
    const summary = document.createElement('summary');
    const action = document.createElement('b');
    const info = record.event.details?.info || {};
    const side = info.side === 'R' ? 'R' : info.side === 'L' ? 'L' : '·';
    action.textContent = `${side} | ${record.event.action || 'message'}`;
    const identity = document.createElement('span');
    const annotations = Array.isArray(info.content_annotations) ? info.content_annotations : [];
    const annotationKinds = [...new Set(annotations
      .map(item => Array.isArray(item) ? item[2] : '')
      .filter(Boolean))];
    const annotationInfo = annotations.length
      ? ` · annotations ${annotations.length}` +
        `${annotationKinds.length ? ` (${annotationKinds.join(', ')})` : ''}`
      : ' · annotations 0';
    identity.textContent = `r${record.revision} · ${record.event.id || 'no connection id'}` +
      annotationInfo;
    const timestamp = Number(record.event.spider_received_at_ms);
    const time = document.createElement('time');
    time.textContent = Number.isFinite(timestamp)
      ? new Date(timestamp).toLocaleTimeString([], {hour12: false}) : '—';
    if (Number.isFinite(timestamp)) {
      time.dateTime = new Date(timestamp).toISOString();
      time.title = new Date(timestamp).toISOString();
    }
    summary.append(action, identity, time);
    const json = document.createElement('pre');
    json.textContent = JSON.stringify(record.event, null, 2);
    message.append(summary, json);
    stream.append(message);
  }
  stream.querySelector('.empty')?.remove();
  if (!records.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'No retained JSON messages for this flow.';
    stream.append(empty);
  }
}

function scopeLabel(scope, records = []) {
  if (scope.type === 'connection') return strictConnectionLabel(scope.label);
  const count = new Set(records.map(record => record.event.id)).size;
  if (scope.type === 'service') {
    return `${resolvedAddress(scope.sourceHost)}:* → ${resolvedAddress(scope.destinationHost)}:` +
      `${scope.destinationPort} · ${count} connection${count === 1 ? '' : 's'}`;
  }
  const destinations = new Set(records.map(record => {
    const connection = parseSessionLabel(record.event.details?.info?.session);
    return connection && `${connection.destinationHost}:${connection.destinationPort}`;
  }).filter(Boolean)).size;
  return `${resolvedAddress(scope.sourceHost)}:* → * · ${count} connections · ${destinations} destinations · live`;
}

function openFlowTab(sessionId, type = 'connection') {
  if (!sessionId) return;
  const scope = flowScope(sessionId, type);
  const id = flowTabId(scope.key);
  if (!followedFlows.has(scope.key)) {
    const followed = {...scope, id, evicted: 0,
      view: type === 'connection' ? 'chunks' : 'lanes', expanded: false, collapsed: false,
      laneOrder: [], visibleLanes: new Set(), laneFit: true, laneWidth: 260, laneFont: 11,
      cardLevels: new Map(), openEnrichments: new Set(),
      payloadCaps: {L: 0, R: 0},
      keepAll: false, timeMode: 'elapsed',
      l7Context: false, annotations: true, human: false};
    followed.laneWidths = new Map();
    followedFlows.set(scope.key, followed);
    const button = document.createElement('button');
    button.type = 'button'; button.dataset.tab = id; button.className = 'flow-tab-button';
    const label = document.createElement('span');
    label.textContent = scope.title;
    const close = document.createElement('i'); close.textContent = '×'; close.title = 'Close flow tab';
    close.onclick = event => { event.stopPropagation(); closeFlowTab(scope.key); };
    button.append(label, close);
    button.onclick = () => showTab(id);
    byId('flow-tabs').append(button);
    byId('flow-tab-separator').hidden = false;
    const panel = document.createElement('div');
    panel.id = id; panel.className = 'tab-panel flow-follow-panel'; panel.hidden = true;
    document.querySelector('.workspace').append(panel);
    addActivity('system', 'FOLLOW', `${scope.title} opened`,
      'Matching payloads will be appended live while they remain in the browser cache.');
  }
  renderFlowTab(scope.key);
  showTab(id);
}

function closeFlowTab(scopeKey) {
  const followed = followedFlows.get(scopeKey);
  if (!followed) return;
  byId(followed.id)?.remove();
  document.querySelector(`[data-tab="${followed.id}"]`)?.remove();
  followedFlows.delete(scopeKey);
  byId('flow-tab-separator').hidden = followedFlows.size === 0;
  if (activeTab === followed.id) showTab('workbench-tab');
}

function flowDisplayBytes(followed, side, bytes) {
  const cap = followed.payloadCaps?.[side] || 0;
  if (cap === -1) return bytes.subarray(0, Math.ceil(bytes.length / 2));
  return cap && bytes.length > cap ? bytes.subarray(0, cap) : bytes;
}

function appendL7Context(target, record, wireBytes, mode, bodyLimit) {
  const view = l7PayloadView(record, wireBytes);
  if (view.state !== 'body') return false;
  let remaining = bodyLimit;
  for (const [index, range] of view.ranges.entries()) {
    if (remaining <= 0) break;
    const shownEnd = Math.min(range.end, range.start + remaining);
    const previousEnd = index ? view.ranges[index - 1].end : 0;
    const nextStart = view.ranges[index + 1]?.start ?? wireBytes.length;
    // Context is non-payload wire data adjacent to this range. A short chunk
    // delimiter must not make the 16-byte window spill into a neighbouring body.
    const beforeStart = Math.max(previousEnd, range.start - 16);
    const afterEnd = shownEnd === range.end ? Math.min(nextStart, range.end + 16) : range.end;
    const block = document.createElement('span');
    block.className = 'l7-context-range';
    const appendPart = (kind, bytes, offset, label) => {
      if (!bytes.length) return;
      const part = document.createElement('span');
      part.className = `l7-context-${kind}`;
      const caption = document.createElement('i');
      caption.textContent = label;
      part.append(caption);
      if (mode === 'hex') part.append(document.createTextNode(`${encodeHex(bytes, offset)}\n`));
      else {
        appendMixedAscii(part, bytes);
        part.append(document.createTextNode('\n'));
      }
      block.append(part);
    };
    appendPart('neighbor', wireBytes.subarray(beforeStart, range.start), beforeStart,
      `wire before [${beforeStart}, ${range.start})`);
    appendPart('body', wireBytes.subarray(range.start, shownEnd), range.start,
      `L7 body ${index + 1} [${range.start}, ${range.end})`);
    if (shownEnd === range.end) appendPart('neighbor', wireBytes.subarray(range.end, afterEnd), range.end,
      `wire after [${range.end}, ${afterEnd})`);
    target.append(block);
    remaining -= shownEnd - range.start;
  }
  return true;
}

function flowLaneColor(followed, sessionId) {
  if (!followed.laneOrder.includes(sessionId)) followed.laneOrder.push(sessionId);
  return `hsl(${(followed.laneOrder.indexOf(sessionId) * 67) % 360} 62% 62%)`;
}

function renderFlowStreamPayload(chunk, bytes, level, context = null) {
  const limits = [640, 8192, bytes.length];
  const limit = Math.min(bytes.length, limits[level] ?? limits[0]);
  const content = chunk.querySelector('pre');
  content.replaceChildren();
  if (!context || !appendL7Context(content, context.record, context.wireBytes, 'ascii', limit)) {
    appendMixedAscii(content, bytes.subarray(0, limit));
  }
  const remaining = bytes.length - limit;
  if (remaining) {
    const omitted = document.createElement('span');
    omitted.className = 'lane-card-omitted';
    omitted.textContent = ` … +${formatBytes(remaining)}`;
    content.append(omitted);
  }
  chunk.classList.toggle('stream-medium', level === 1);
  chunk.classList.toggle('stream-full', level === 2);
  chunk.classList.toggle('truncated', remaining > 0);
  const button = chunk.querySelector('.flow-stream-expand');
  if (button) {
    button.textContent = remaining ? (level === 0 ? 'Expand payload' : 'Show all') : 'Collapse';
    button.dataset.nextLevel = remaining ? String(Math.min(2, level + 1)) : '0';
  }
}

function renderFlowStreamLegend(stream, records, followed) {
  const laneIds = [...new Set(records.map(record => record.event.id))];
  let legend = stream.querySelector('.flow-stream-legend');
  const key = laneIds.join('|');
  if (legend?.dataset.key === key) return;
  legend?.remove();
  legend = document.createElement('div');
  legend.className = 'flow-stream-legend'; legend.dataset.key = key;
  for (const laneId of laneIds) {
    const item = document.createElement('span');
    item.style.setProperty('--flow-color', flowLaneColor(followed, laneId));
    item.textContent = `${followed.laneOrder.indexOf(laneId) + 1} · ${laneLabel(laneId)}`;
    item.title = laneId;
    legend.append(item);
  }
  stream.prepend(legend);
}

function clearFollowedFlow(followed) {
  const removed = payloadRecords.filter(record => scopeMatches(followed, record));
  if (!removed.length) return;
  const removedSet = new Set(removed);
  const affectedIds = new Set(removed.map(record => record.event.id));
  payloadRecords = payloadRecords.filter(record => !removedSet.has(record));
  payloadCacheBytes = payloadRecords.reduce((total, record) =>
    total + (record.cacheBytes || payloadSize(record)), 0);
  for (const id of affectedIds) flowRecords.delete(id);
  for (const record of payloadRecords) {
    if (affectedIds.has(record.event.id)) updateFlowRecord(record);
  }
  if (selectedPayload && removedSet.has(selectedPayload)) {
    selectedPayload = payloadRecords.at(-1) || null;
    if (selectedPayload) selectPayload(selectedPayload, followPayload);
    else {
      selectPayload(null);
      payloadBytes = new Uint8Array();
      replacementBase64 = null;
      byId('payload-text').value = '';
      byId('payload-hex').textContent = '';
    }
  }
  followed.evicted = 0;
  followed.cardLevels.clear();
  followed.renderedMode = null;
  updateCacheStats();
  addActivity('system', 'FLOW CACHE', `${removed.length} payloads cleared from ${followed.title}`,
    `${formatBytes(removed.reduce((sum, record) => sum + (record.cacheBytes || payloadSize(record)), 0))} released from the browser cache.`);
  scheduleRender(false, true);
}

function exportFollowedFlow(followed, records) {
  const packets = [];
  for (const record of records) {
    const info = record.event.details?.info || {};
    const connection = parseSessionLabel(info.session);
    if (!connection) continue;
    packets.push({
      sessionId: record.event.id,
      sourceAddress: connection.sourceHost,
      sourcePort: Number(connection.sourcePort),
      destinationAddress: connection.destinationHost,
      destinationPort: Number(connection.destinationPort),
      side: info.side === 'R' ? 'R' : 'L',
      payload: recordPayloadBytes(record),
      timestampMs: Number(record.event.spider_received_at_ms),
    });
  }
  if (!packets.length) {
    addActivity('system', 'PCAPNG', `Nothing exported from ${followed.title}`,
      'No retained payload had a usable IP connection tuple.', 'warn');
    return;
  }
  const bytes = SpiderPcapng.build(packets);
  const filename = `spider-${followed.type}-${Date.now()}.pcapng`;
  const link = document.createElement('a');
  link.href = URL.createObjectURL(new Blob([bytes], {type: 'application/x-pcapng'}));
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  addActivity('system', 'PCAPNG', `${filename} exported`,
    `${packets.length} retained payload blocks from ${new Set(packets.map(packet => packet.sessionId)).size} synthetic TCP flow(s).`);
}

function renderFlowTab(scopeKey) {
  const followed = followedFlows.get(scopeKey);
  const panel = followed && byId(followed.id);
  if (!panel) return;
  const retained = payloadRecords.filter(record => scopeMatches(followed, record))
    .sort((a, b) => a.revision - b.revision);
  const records = [];
  let displayBytes = 0;
  for (let index = retained.length - 1; index >= 0; --index) {
    const size = retained[index].cacheBytes || payloadSize(retained[index]);
    if (!followed.keepAll && records.length && displayBytes + size > flowViewLimitMiB * 1024 * 1024) break;
    displayBytes += size;
    records.unshift(retained[index]);
  }
  const omitted = retained.length - records.length;
  if (!panel.querySelector('.flow-stream')) {
    panel.innerHTML = '<div class="flow-follow-toolbar"><div class="flow-follow-head"><h2>Follow flow</h2><span class="flow-completeness" hidden></span><small></small>' +
      '<span class="flow-follow-classifications"></span><div class="flow-follow-controls">' +
      '<button type="button" data-flow-view="chunks" aria-pressed="true">Chunks</button>' +
      '<button type="button" data-flow-view="stream" aria-pressed="false">Stream</button>' +
      '<button type="button" data-flow-view="lanes" aria-pressed="false">Lanes</button>' +
      '<button type="button" data-flow-view="messages" aria-pressed="false">Messages</button>' +
      '<span class="flow-scope-controls"><button type="button" data-flow-scope="wire">Wire</button>' +
      '<button type="button" data-flow-scope="l7">L7</button>' +
      '<label class="l7-context-toggle" title="Show 16 wire bytes immediately before and after each L7 body range"><input type="checkbox" data-l7-context> ±16 B context</label></span>' +
      '<button type="button" data-flow-human title="Prefer decoded content and render formats understood by the browser">Human</button>' +
      '<button type="button" data-flow-annotations title="Show Smithproxy protocol annotations over each payload">Annotations</button>' +
      '<button type="button" data-flow-expand="all">Expand all</button>' +
      '<button type="button" data-flow-expand="none">Collapse all</button>' +
      '<button type="button" data-export-pcapng title="Export retained wire payloads as synthetic TCP traffic">PCAPNG</button>' +
      '<span class="lane-layout-controls"><button type="button" data-lane-fit>Fit width</button>' +
      '<button type="button" data-lane-width="-1" title="Narrower lanes">W−</button>' +
      '<button type="button" data-lane-width="1" title="Wider lanes">W+</button>' +
      '<label class="lane-width-slider" title="Uniform width of expanded lanes"><input type="range" min="120" max="640" step="10" data-lane-width-slider><output></output></label>' +
      '<button type="button" data-lane-font="-1" title="Smaller lane font">A−</button>' +
      '<button type="button" data-lane-font="1" title="Larger lane font">A+</button></span></div></div>' +
      '<div class="flow-cache-toolbar"><label class="flow-keep-all"><input type="checkbox" data-keep-all> Keep all</label>' +
      '<label>View <input class="flow-view-limit" type="number" min="1" max="8192" step="1"> MiB</label>' +
      '<label>L bytes <select data-payload-cap="L"><option value="0">all</option><option value="-1">first half</option><option value="64">first 64 B</option><option value="256">first 256 B</option><option value="1024">first 1 KiB</option><option value="4096">first 4 KiB</option><option value="16384">first 16 KiB</option></select></label>' +
      '<label>R bytes <select data-payload-cap="R"><option value="0">all</option><option value="-1">first half</option><option value="64">first 64 B</option><option value="256">first 256 B</option><option value="1024">first 1 KiB</option><option value="4096">first 4 KiB</option><option value="16384">first 16 KiB</option></select></label>' +
      '<label>Time <select data-time-mode><option value="elapsed">elapsed</option><option value="local">local</option><option value="utc">UTC</option></select></label>' +
      '<button type="button" class="danger-subtle" data-clear-flow>Clear flow cache</button></div></div>' +
      '<div class="flow-gap flow-eviction" hidden></div>' +
      '<div class="flow-gap flow-window" hidden></div><div class="flow-stream"></div>';
    const toolbar = panel.querySelector('.flow-follow-toolbar');
    const updateToolbarHeight = () => panel.style.setProperty(
      '--flow-toolbar-height', `${toolbar.getBoundingClientRect().height}px`);
    new ResizeObserver(updateToolbarHeight).observe(toolbar);
    requestAnimationFrame(updateToolbarHeight);
    for (const button of panel.querySelectorAll('[data-flow-view]')) {
      button.onclick = () => {
        followed.view = button.dataset.flowView;
        followed.renderedMode = null;
        renderFlowTab(scopeKey);
      };
    }
    for (const button of panel.querySelectorAll('[data-flow-scope]')) {
      button.onclick = () => setPayloadScope(button.dataset.flowScope);
    }
    panel.querySelector('[data-l7-context]').onchange = event => {
      followed.l7Context = event.target.checked;
      followed.renderedMode = null;
      renderFlowTab(scopeKey);
    };
    panel.querySelector('[data-flow-human]').onclick = () => {
      followed.human = !followed.human;
      followed.renderedMode = null;
      renderFlowTab(scopeKey);
    };
    panel.querySelector('[data-flow-annotations]').onclick = () => {
      followed.annotations = !followed.annotations;
      followed.renderedMode = null;
      renderFlowTab(scopeKey);
    };
    panel.querySelector('[data-export-pcapng]').onclick = () => {
      const exportRecords = payloadRecords.filter(record => scopeMatches(followed, record))
        .sort((a, b) => a.revision - b.revision);
      exportFollowedFlow(followed, exportRecords);
    };
    panel.querySelector('[data-flow-expand="all"]').onclick = () => {
      followed.expanded = true;
      followed.collapsed = false;
      for (const chunk of panel.querySelectorAll('.flow-chunk')) {
        chunk.open = true;
        chunk.classList.add('expanded');
      }
      panel.classList.add('flow-expanded');
    };
    panel.querySelector('[data-flow-expand="none"]').onclick = () => {
      followed.expanded = false;
      followed.collapsed = true;
      for (const chunk of panel.querySelectorAll('.flow-chunk')) {
        chunk.open = false;
        chunk.classList.remove('expanded');
      }
      panel.classList.remove('flow-expanded');
    };
    panel.querySelector('[data-lane-fit]').onclick = () => {
      followed.laneFit = !followed.laneFit;
      renderFlowTab(scopeKey);
    };
    for (const button of panel.querySelectorAll('[data-lane-width]')) {
      button.onclick = () => {
        followed.laneFit = false;
        followed.laneWidth = Math.max(120, Math.min(640,
          followed.laneWidth + Number(button.dataset.laneWidth) * 30));
        followed.laneWidths?.clear();
        renderFlowTab(scopeKey);
      };
    }
    const laneWidthSlider = panel.querySelector('[data-lane-width-slider]');
    laneWidthSlider.value = String(followed.laneWidth);
    laneWidthSlider.oninput = () => {
      const wasFit = followed.laneFit;
      const hadCustomWidths = Boolean(followed.laneWidths?.size);
      followed.laneFit = false;
      followed.laneWidth = Number(laneWidthSlider.value);
      followed.laneWidths?.clear();
      if (wasFit || hadCustomWidths) renderFlowTab(scopeKey);
      else {
        panel.querySelector('.flow-stream')?.style.setProperty('--lane-width', `${followed.laneWidth}px`);
        panel.querySelector('.lane-width-slider output').value = `${followed.laneWidth}px`;
      }
    };
    for (const button of panel.querySelectorAll('[data-lane-font]')) {
      button.onclick = () => {
        followed.laneFont = Math.max(8, Math.min(18,
          followed.laneFont + Number(button.dataset.laneFont)));
        renderFlowTab(scopeKey);
      };
    }
    const limit = panel.querySelector('.flow-view-limit');
    limit.value = String(flowViewLimitMiB);
    limit.onchange = () => {
      flowViewLimitMiB = Math.max(1, Math.min(8192, Number(limit.value) || 1));
      limit.value = String(flowViewLimitMiB);
      localStorage.setItem('spider-flow-view-limit-mib', String(flowViewLimitMiB));
      for (const item of followedFlows.values()) item.renderedMode = null;
      for (const id of followedFlows.keys()) renderFlowTab(id);
    };
    const keepAll = panel.querySelector('[data-keep-all]');
    keepAll.checked = followed.keepAll;
    keepAll.onchange = () => {
      followed.keepAll = keepAll.checked;
      followed.renderedMode = null;
      renderFlowTab(scopeKey);
    };
    for (const select of panel.querySelectorAll('[data-payload-cap]')) {
      const side = select.dataset.payloadCap;
      select.value = String(followed.payloadCaps[side]);
      select.onchange = () => {
        followed.payloadCaps[side] = Number(select.value);
        followed.renderedMode = null;
        renderFlowTab(scopeKey);
      };
    }
    const timeMode = panel.querySelector('[data-time-mode]');
    timeMode.value = followed.timeMode;
    timeMode.onchange = () => {
      followed.timeMode = timeMode.value;
      renderFlowTab(scopeKey);
    };
    panel.querySelector('[data-clear-flow]').onclick = () => clearFollowedFlow(followed);
  }
  for (const button of panel.querySelectorAll('[data-flow-view]')) {
    button.setAttribute('aria-pressed', String(button.dataset.flowView === followed.view));
  }
  const flowMessageCount = eventRecords.reduce((count, record) =>
    count + (scopeMatchesEvent(followed, record) ? 1 : 0), 0);
  panel.querySelector('[data-flow-view="messages"]').textContent = `Messages ${flowMessageCount}`;
  for (const button of panel.querySelectorAll('[data-flow-scope]')) {
    button.setAttribute('aria-pressed', String(button.dataset.flowScope === payloadScope));
  }
  const contextToggle = panel.querySelector('[data-l7-context]');
  contextToggle.checked = followed.l7Context;
  contextToggle.disabled = payloadScope !== 'l7' || followed.human;
  panel.querySelector('[data-flow-human]').setAttribute('aria-pressed', String(followed.human));
  panel.querySelector('[data-flow-annotations]').setAttribute(
    'aria-pressed', String(followed.annotations));
  panel.querySelector('[data-flow-expand="all"]').hidden = followed.view !== 'chunks';
  panel.querySelector('[data-flow-expand="none"]').hidden = followed.view !== 'chunks';
  panel.querySelector('.lane-layout-controls').hidden = followed.view !== 'lanes';
  panel.querySelector('.flow-scope-controls').hidden = followed.view === 'messages';
  panel.querySelector('[data-flow-human]').hidden = followed.view === 'messages';
  panel.querySelector('[data-flow-annotations]').hidden = followed.view === 'messages' || followed.human;
  panel.querySelector('[data-lane-fit]').setAttribute('aria-pressed', String(followed.laneFit));
  panel.querySelector('[data-lane-fit]').textContent = followed.laneFit ? 'Fit: on' : 'Fit width';
  panel.querySelector('[data-lane-width-slider]').value = String(followed.laneWidth);
  panel.querySelector('.lane-width-slider output').value = `${followed.laneWidth}px`;
  panel.classList.toggle('flow-expanded', followed.expanded);
  panel.querySelector('[data-keep-all]').checked = followed.keepAll;
  panel.querySelector('.flow-view-limit').disabled = followed.keepAll;
  panel.querySelector('.flow-view-limit').value = String(flowViewLimitMiB);
  panel.querySelector('.flow-follow-head small').textContent =
    scopeLabel(followed, records);
  const visibleConnections = followed.type === 'connection'
    ? new Set([followed.sessionId])
    : new Set(records.map(record => record.event.id).filter(Boolean));
  const incompleteConnections = [...visibleConnections]
    .filter(id => !startedConnections.has(id));
  const completeness = panel.querySelector('.flow-completeness');
  completeness.hidden = incompleteConnections.length === 0;
  completeness.textContent = incompleteConnections.length > 1
    ? `INCOMPLETE ${incompleteConnections.length}/${visibleConnections.size}` : 'INCOMPLETE';
  completeness.title = incompleteConnections.length
    ? `connection-start was not observed for: ${incompleteConnections.join(', ')}` : '';
  panel.querySelector('.flow-follow-head h2').textContent = followed.type === 'client'
    ? 'Client activity' : followed.type === 'service' ? 'Follow service' : 'Follow connection';
  const classification = workbenchSiftClassifications(records.at(-1));
  const classificationKey = JSON.stringify(classification);
  if (followed.classificationKey !== classificationKey) {
    panel.querySelector('.flow-follow-classifications').innerHTML =
      classification.length ? classificationChips(classification) : '';
    followed.classificationKey = classificationKey;
  }
  const eviction = panel.querySelector('.flow-eviction');
  eviction.hidden = !followed.evicted;
  eviction.textContent = followed.evicted
    ? `=!= ${followed.evicted} earlier payloads were evicted from the browser cache.` : '';
  const windowGap = panel.querySelector('.flow-window');
  windowGap.hidden = !omitted || followed.keepAll;
  windowGap.textContent = omitted
    ? `=!= ${omitted} retained payloads are outside this ${flowViewLimitMiB} MiB live view window.` : '';

  const stream = panel.querySelector('.flow-stream');
  stream.className = followed.view === 'lanes' ? 'flow-stream lane-board' : 'flow-stream';
  if (followed.view === 'messages') {
    renderFlowMessages(stream, followed);
    return;
  }
  const renderMode = `${followed.view}:${payloadMode}:${payloadScope}:${followed.l7Context}:${followed.annotations}:${followed.human}`;
  if (followed.renderedMode !== renderMode) {
    stream.replaceChildren();
    delete stream.dataset.layoutKey;
    delete stream.dataset.renderKind;
    followed.renderedMode = renderMode;
  }
  if (followed.view === 'lanes') {
    renderLaneBoard(stream, records, followed, scopeKey);
    return;
  }
  if (followed.view === 'stream') renderFlowStreamLegend(stream, records, followed);
  const wanted = new Set(records.map(record => String(record.revision)));
  for (const chunk of stream.querySelectorAll('[data-revision]')) {
    if (!wanted.has(chunk.dataset.revision)) chunk.remove();
  }
  const rendered = new Set([...stream.querySelectorAll('[data-revision]')]
    .map(chunk => chunk.dataset.revision));
  for (const record of records) {
    const recordRevision = String(record.revision);
    if (rendered.has(recordRevision)) continue;
    const info = record.event.details?.info || {};
    const wireBytes = recordPayloadBytes(record);
    const completeBytes = flowPayloadBytes(record, wireBytes);
    const side = info.side === 'R' ? 'R' : 'L';
    const bytes = flowDisplayBytes(followed, side, completeBytes);
    const chunk = followed.view === 'stream'
      ? document.createElement('article') : document.createElement('details');
    chunk.className = `${followed.view === 'stream' ? 'flow-stream-chunk' : 'flow-chunk'} ${side}`;
    chunk.dataset.revision = recordRevision;
    const direction = document.createElement('b');
    direction.textContent = side;
    const metadata = document.createElement('small');
    metadata.append(`r${record.revision}`, document.createElement('br'), formatBytes(bytes.length));
    if (bytes.length < completeBytes.length) metadata.append(document.createElement('br'),
      `of ${formatBytes(completeBytes.length)}`);
    const badges = document.createElement('span');
    badges.className = 'flow-payload-badges';
    badges.append(l7PayloadMarker(record, wireBytes));
    metadata.append(document.createElement('br'), badges);
    if (followed.view === 'stream') {
      const content = document.createElement('pre');
      const payload = document.createElement('div');
      payload.className = 'flow-payload-content';
      chunk.style.setProperty('--flow-color', flowLaneColor(followed, record.event.id));
      chunk.title = laneLabel(record.event.id);
      direction.textContent = `${side}·${followed.laneOrder.indexOf(record.event.id) + 1}`;
      if (!followed.human && bytes.length > 640) {
        const expand = document.createElement('button');
        expand.type = 'button'; expand.className = 'flow-stream-expand';
        expand.onclick = () => {
          const next = Number(expand.dataset.nextLevel || 0);
          followed.cardLevels.set(record.revision, next);
          renderFlowStreamPayload(chunk, bytes, next,
            followed.l7Context && payloadScope === 'l7' ? {record, wireBytes} : null);
        };
        metadata.append(document.createElement('br'), expand);
      }
      if (followed.annotations && !followed.human) appendAnnotationRail(payload, record, wireBytes);
      payload.append(content);
      chunk.append(direction, metadata, payload);
      const enriched = attachInlineEnrichments(chunk, record, records, followed);
      if (enriched) badges.append(enriched);
      if (followed.human) renderHumanPreview(content, record, records, bytes);
      else renderFlowStreamPayload(chunk, bytes, followed.cardLevels.get(record.revision) || 0,
        followed.l7Context && payloadScope === 'l7' ? {record, wireBytes} : null);
    } else {
      const summary = document.createElement('summary');
      summary.append(direction, metadata);
      const expand = document.createElement('button');
      expand.type = 'button';
      expand.className = 'flow-chunk-expand';
      expand.textContent = '⤢';
      expand.title = 'Toggle full payload height';
      expand.onclick = event => {
        event.preventDefault();
        event.stopPropagation();
        chunk.open = true;
        chunk.classList.toggle('expanded');
      };
      summary.append(expand);
      const content = document.createElement('pre');
      if (followed.human) {
        renderHumanPreview(content, record, records, bytes);
      } else if (!(followed.l7Context && payloadScope === 'l7' &&
                   appendL7Context(content, record, wireBytes, payloadMode, bytes.length))) {
        const annotations = followed.annotations && payloadScope === 'wire'
          ? contentAnnotations(record, bytes.length) : [];
        if (!appendAnnotatedPayload(content, bytes, annotations, payloadMode)) {
          content.textContent = payloadMode === 'hex'
            ? encodeHex(bytes) : new TextDecoder().decode(bytes);
        }
      }
      content.onwheel = event => {
        if (event.shiftKey) return;
        event.preventDefault();
        byId(followed.id).closest('.workspace').scrollBy({top: event.deltaY});
      };
      chunk.open = !followed.collapsed;
      chunk.classList.toggle('expanded', followed.expanded);
      chunk.append(summary);
      if (followed.annotations && !followed.human) appendAnnotationRail(chunk, record, wireBytes);
      chunk.append(content);
      const enriched = attachInlineEnrichments(chunk, record, records, followed);
      if (enriched) badges.append(enriched);
    }
    stream.append(chunk);
  }
  const empty = stream.querySelector('.empty');
  if (records.length) empty?.remove();
  else if (!empty) {
    const message = document.createElement('span');
    message.className = 'empty';
    message.textContent = 'No retained payloads for this flow.';
    stream.append(message);
  }
}

function laneLabel(sessionId) {
  const flow = flowRecords.get(sessionId);
  return strictConnectionLabel(flow?.label || sessionId);
}

function laneTimeLabel(timestamp, mode, origin) {
  if (!Number.isFinite(timestamp)) return '—';
  if (mode === 'elapsed') {
    const elapsed = Math.max(0, timestamp - origin);
    if (elapsed < 60000) return `+${(elapsed / 1000).toFixed(3)}s`;
    return `+${Math.floor(elapsed / 60000)}m${((elapsed % 60000) / 1000).toFixed(3).padStart(6, '0')}s`;
  }
  const date = new Date(timestamp);
  if (mode === 'utc') return `${date.toISOString().slice(11, 23)}Z`;
  return `${date.toLocaleTimeString([], {hour12: false})}.${String(date.getMilliseconds()).padStart(3, '0')}`;
}

function laneTimeTitle(record, origin) {
  const timestamp = Number(record.event.spider_received_at_ms);
  if (!Number.isFinite(timestamp)) return `r${record.revision} · receive timestamp unavailable`;
  const date = new Date(timestamp);
  return `r${record.revision} · elapsed ${laneTimeLabel(timestamp, 'elapsed', origin)}\n` +
    `local ${date.toLocaleString()}.${String(date.getMilliseconds()).padStart(3, '0')}\nUTC ${date.toISOString()}`;
}

function laneResponseCandidates(records) {
  const result = {starts: new Map(), pending: new Set()};
  const sessions = new Map();
  for (const record of records) {
    if (!sessions.has(record.event.id)) sessions.set(record.event.id, []);
    sessions.get(record.event.id).push(record);
  }
  for (const laneRecords of sessions.values()) {
    let pending = null;
    for (const record of laneRecords) {
      const side = record.event.details?.info?.side === 'R' ? 'R' : 'L';
      if (side === 'L') {
        pending = record;
      } else if (pending) {
        const started = Number(pending.event.spider_received_at_ms);
        const ended = Number(record.event.spider_received_at_ms);
        const link = {start: pending.revision, end: record.revision,
          delta: Number.isFinite(started) && Number.isFinite(ended) ? Math.max(0, ended - started) : null};
        result.starts.set(String(link.start), link);
        pending = null;
      }
    }
    if (pending) result.pending.add(String(pending.revision));
  }
  return result;
}

function lanePreviousDeltas(records) {
  const previous = new Map(), result = new Map();
  for (const record of records) {
    const timestamp = Number(record.event.spider_received_at_ms);
    const earlier = previous.get(record.event.id);
    if (Number.isFinite(timestamp) && Number.isFinite(earlier)) {
      result.set(String(record.revision), Math.max(0, timestamp - earlier));
    }
    if (Number.isFinite(timestamp)) previous.set(record.event.id, timestamp);
  }
  return result;
}

function laneDeltaLabel(delta) {
  if (!Number.isFinite(delta)) return 'Δ unknown';
  if (delta < 1000) return `Δ ${delta} ms`;
  if (delta < 60000) return `Δ ${(delta / 1000).toFixed(delta < 10000 ? 2 : 1)} s`;
  return `Δ ${Math.floor(delta / 60000)}m ${Math.floor((delta % 60000) / 1000)}s`;
}

function laneStepLabel(delta) {
  if (delta === 0) return 'prev <1 ms';
  return `prev ${laneDeltaLabel(delta).replace('Δ ', '+')}`;
}

function renderLaneCardPayload(card, bytes, level, context = null, human = null) {
  const limits = [320, 4096, bytes.length];
  const limit = Math.min(bytes.length, limits[level] ?? limits[0]);
  const preview = card.querySelector('pre');
  preview.replaceChildren();
  if (human) {
    renderHumanPreview(preview, human.record, human.records, bytes, limits[level] ?? limits[0]);
  } else if (!context || !appendL7Context(preview, context.record, context.wireBytes, 'ascii', limit)) {
    appendMixedAscii(preview, bytes.subarray(0, limit));
  }
  const remaining = human ? 0 : bytes.length - limit;
  if (remaining) {
    const omitted = document.createElement('span');
    omitted.className = 'lane-card-omitted';
    omitted.textContent = ` … +${formatBytes(remaining)}`;
    preview.append(omitted);
  }
  card.classList.toggle('medium', level === 1);
  card.classList.toggle('full', level === 2);
  card.classList.toggle('truncated', remaining > 0);
  const button = card.querySelector('.lane-card-expand');
  if (button) {
    button.textContent = remaining ? (level === 0 ? 'Expand payload' : 'Show all') : 'Collapse';
    button.dataset.nextLevel = remaining ? String(Math.min(2, level + 1)) : '0';
    button.title = !remaining ? 'Collapse payload preview' :
      `Show ${level === 0 ? 'a larger preview' : 'the complete payload'}`;
  }
}

function decorateLaneResponses(stream, records, followed) {
  const candidates = laneResponseCandidates(records);
  const previousDeltas = lanePreviousDeltas(records);
  for (const badge of stream.querySelectorAll('.lane-step-delta,.lane-delta,.lane-pending')) badge.remove();
  for (const card of stream.querySelectorAll('.lane-card')) card.classList.remove('response-start', 'response-end', 'response-pending');
  for (const [revision, delta] of previousDeltas) {
    const card = stream.querySelector(`.lane-card[data-revision="${revision}"]`);
    if (!card) continue;
    const badge = document.createElement('span');
    badge.className = 'lane-step-delta'; badge.textContent = laneStepLabel(delta);
    badge.title = 'Time since the previous payload received by Spider in this connection.';
    const head = card.querySelector('.lane-card-head');
    head?.insertBefore(badge, head.querySelector('.lane-card-expand'));
  }
  for (const [revision, link] of candidates.starts) {
    const card = stream.querySelector(`.lane-card[data-revision="${revision}"]`);
    if (card) card.classList.add('response-start');
    const response = stream.querySelector(`.lane-card[data-revision="${link.end}"]`);
    if (!response) continue;
    response.classList.add('response-end');
    const badge = document.createElement('span');
    badge.className = 'lane-delta'; badge.textContent = laneDeltaLabel(link.delta);
    badge.title = 'Spider receive-time delta for a candidate L→R direction transition; not wire RTT.';
    const head = response.querySelector('.lane-card-head');
    head?.insertBefore(badge, head.querySelector('.lane-card-expand'));
  }
  for (const revision of candidates.pending) {
    const card = stream.querySelector(`.lane-card[data-revision="${revision}"]`);
    if (!card) continue;
    card.classList.add('response-pending');
    const badge = document.createElement('span');
    badge.className = 'lane-pending'; badge.textContent = '× no response yet';
    badge.title = 'No later R payload has been observed for this L direction run.';
    const head = card.querySelector('.lane-card-head');
    head?.insertBefore(badge, head.querySelector('.lane-card-expand'));
  }
  cancelAnimationFrame(followed.connectorFrame || 0);
  followed.connectorFrame = requestAnimationFrame(() => {
    for (const connector of stream.querySelectorAll('.lane-response-link')) connector.remove();
    const board = stream.getBoundingClientRect();
    for (const [revision, link] of candidates.starts) {
      const start = stream.querySelector(`.lane-card[data-revision="${revision}"]`);
      const end = stream.querySelector(`.lane-card[data-revision="${link.end}"]`);
      if (!start || !end) continue;
      const a = start.getBoundingClientRect(), b = end.getBoundingClientRect();
      const height = b.top - a.bottom;
      if (height < 2) continue;
      const connector = document.createElement('i');
      connector.className = 'lane-response-link';
      connector.style.left = `${a.left - board.left + 8}px`;
      connector.style.top = `${a.bottom - board.top}px`;
      connector.style.height = `${height}px`;
      connector.title = 'Candidate L→R direction transition';
      stream.append(connector);
    }
  });
}

function renderLaneBoard(stream, records, followed, scopeKey) {
  const workspace = stream.closest('.workspace');
  const previousScroll = workspace.scrollTop;
  if (!(followed.laneWidths instanceof Map)) followed.laneWidths = new Map();
  const laneIds = [...new Set(records.map(record => record.event.id))];
  for (const laneId of laneIds) {
    if (followed.laneOrder.includes(laneId)) continue;
    followed.laneOrder.push(laneId);
    if (followed.visibleLanes.size < 2) followed.visibleLanes.add(laneId);
  }
  followed.laneOrder = followed.laneOrder.filter(laneId => laneIds.includes(laneId));
  const visible = followed.laneOrder.filter(laneId => followed.visibleLanes.has(laneId));
  const hidden = followed.laneOrder.filter(laneId => !followed.visibleLanes.has(laneId));
  const makeTemplate = () => `104px ${visible.map(laneId => followed.laneFit
    ? 'minmax(0,1fr)' : `${followed.laneWidths.get(laneId) || followed.laneWidth}px`).join(' ')} ` +
    `${hidden.map(() => '14px').join(' ')} 16px`;
  let template = makeTemplate();
  stream.className = 'flow-stream lane-board';
  stream.classList.toggle('fit-width', followed.laneFit);
  stream.style.setProperty('--lane-width', `${followed.laneWidth}px`);
  stream.style.setProperty('--lane-font-size', `${followed.laneFont}px`);
  const makeLayoutKey = () => `${visible.join('|')}::${hidden.join('|')}::${followed.laneFit}:` +
    `${followed.laneFont}:${followed.timeMode}:` +
    visible.map(laneId => followed.laneWidths.get(laneId) || 0).join(',');
  const layoutKey = makeLayoutKey();
  const rebuild = stream.dataset.layoutKey !== layoutKey;
  if (rebuild) {
    stream.replaceChildren();
    stream.dataset.layoutKey = layoutKey;
    const header = document.createElement('div');
    header.className = 'lane-row lane-header';
    header.style.gridTemplateColumns = template;
    const timeTitle = document.createElement('span');
    timeTitle.className = 'lane-time-title'; timeTitle.textContent = followed.timeMode;
    header.append(timeTitle);
    for (const laneId of visible) {
      const item = document.createElement('div');
      item.className = 'lane-title'; item.draggable = true; item.dataset.lane = laneId;
      item.style.setProperty('--lane-color', `hsl(${(followed.laneOrder.indexOf(laneId) * 67) % 360} 62% 62%)`);
      const text = document.createElement('span'); text.textContent = laneLabel(laneId); text.title = laneId;
      const collapse = document.createElement('button'); collapse.textContent = '→'; collapse.title = 'Collapse to activity rail';
      collapse.onclick = () => { followed.visibleLanes.delete(laneId); renderFlowTab(scopeKey); };
      const resize = document.createElement('i');
      resize.className = 'lane-resize'; resize.title = 'Drag to resize this lane';
      resize.onpointerdown = event => {
        event.preventDefault(); event.stopPropagation();
        const titles = [...header.querySelectorAll('.lane-title')];
        for (const title of titles) {
          followed.laneWidths.set(title.dataset.lane,
            Math.round(title.getBoundingClientRect().width));
        }
        followed.laneFit = false;
        stream.classList.remove('fit-width');
        stream.dataset.layoutKey = makeLayoutKey();
        const startX = event.clientX;
        const startWidth = followed.laneWidths.get(laneId) || followed.laneWidth;
        resize.setPointerCapture(event.pointerId);
        resize.classList.add('dragging');
        resize.onpointermove = move => {
          if (!resize.hasPointerCapture(move.pointerId)) return;
          followed.laneWidths.set(laneId,
            Math.max(120, Math.min(960, Math.round(startWidth + move.clientX - startX))));
          template = makeTemplate();
          for (const row of stream.querySelectorAll('.lane-row')) {
            row.style.gridTemplateColumns = template;
          }
          stream.dataset.layoutKey = makeLayoutKey();
        };
        resize.onpointerup = move => {
          resize.releasePointerCapture(move.pointerId);
          resize.classList.remove('dragging');
          resize.onpointermove = null; resize.onpointerup = null;
          renderFlowTab(scopeKey);
        };
      };
      item.append(text, collapse, resize);
      item.ondragstart = () => { followed.draggedLane = laneId; };
      item.ondragover = event => event.preventDefault();
      item.ondrop = event => {
        event.preventDefault();
        const from = followed.laneOrder.indexOf(followed.draggedLane);
        const to = followed.laneOrder.indexOf(laneId);
        if (from < 0 || to < 0 || from === to) return;
        const [moved] = followed.laneOrder.splice(from, 1);
        followed.laneOrder.splice(to, 0, moved);
        renderFlowTab(scopeKey);
      };
      header.append(item);
    }
    for (const laneId of hidden) {
      const rail = document.createElement('button');
      rail.className = 'lane-rail-title'; rail.textContent = '│'; rail.title = `Expand ${laneLabel(laneId)}`;
      rail.style.setProperty('--lane-color', `hsl(${(followed.laneOrder.indexOf(laneId) * 67) % 360} 62% 62%)`);
      rail.onclick = () => { followed.visibleLanes.add(laneId); renderFlowTab(scopeKey); };
      header.append(rail);
    }
    const all = document.createElement('span'); all.className = 'lane-all-title'; all.textContent = 'ALL';
    header.append(all); stream.append(header);
  }
  const wanted = new Set(records.map(record => String(record.revision)));
  for (const row of stream.querySelectorAll('.lane-row[data-revision]')) {
    if (!wanted.has(row.dataset.revision)) row.remove();
  }
  const rendered = new Set([...stream.querySelectorAll('.lane-row[data-revision]')]
    .map(row => row.dataset.revision));
  const timeOrigin = Number(records[0]?.event.spider_received_at_ms) || 0;
  for (const record of records) {
    if (rendered.has(String(record.revision))) continue;
    const row = document.createElement('div');
    row.className = 'lane-row'; row.dataset.revision = String(record.revision);
    row.style.gridTemplateColumns = template;
    const timestamp = Number(record.event.spider_received_at_ms);
    const time = document.createElement('time');
    time.className = 'lane-time';
    time.textContent = laneTimeLabel(timestamp, followed.timeMode, timeOrigin);
    time.title = laneTimeTitle(record, timeOrigin);
    if (Number.isFinite(timestamp)) time.dateTime = new Date(timestamp).toISOString();
    row.append(time);
    const visibleIndex = visible.indexOf(record.event.id);
    const hiddenIndex = hidden.indexOf(record.event.id);
    if (visibleIndex >= 0) {
      const info = record.event.details?.info || {};
      const side = info.side === 'R' ? 'R' : 'L';
      const wireBytes = recordPayloadBytes(record);
      const completeBytes = flowPayloadBytes(record, wireBytes);
      const bytes = flowDisplayBytes(followed, side, completeBytes);
      const card = document.createElement('article');
      card.className = `lane-card ${side}`;
      card.dataset.revision = String(record.revision);
      card.style.gridColumn = String(visibleIndex + 2);
      card.style.setProperty('--lane-color', `hsl(${(followed.laneOrder.indexOf(record.event.id) * 67) % 360} 62% 62%)`);
      const head = document.createElement('div');
      head.className = 'lane-card-head';
      const meta = document.createElement('small');
      meta.textContent = `r${record.revision} · ${side} · ${formatBytes(bytes.length)}` +
        (bytes.length < completeBytes.length ? ` / ${formatBytes(completeBytes.length)} (trimmed)` : '');
      const preview = document.createElement('pre');
      head.append(meta, l7PayloadMarker(record, wireBytes));
      if (!followed.human && bytes.length > 320) {
        const expand = document.createElement('button');
        expand.type = 'button'; expand.className = 'lane-card-expand';
        expand.onclick = () => {
          const next = Number(expand.dataset.nextLevel || 0);
          followed.cardLevels.set(record.revision, next);
          renderLaneCardPayload(card, bytes, next,
            followed.l7Context && payloadScope === 'l7' ? {record, wireBytes} : null,
            followed.human ? {record, records} : null);
          decorateLaneResponses(stream, records, followed);
        };
        head.append(expand);
      }
      card.append(head);
      if (followed.annotations && !followed.human) appendAnnotationRail(card, record, wireBytes);
      card.append(preview);
      const enriched = attachInlineEnrichments(card, record, records, followed);
      if (enriched) head.append(enriched);
      renderLaneCardPayload(card, bytes, followed.cardLevels.get(record.revision) || 0,
        followed.l7Context && payloadScope === 'l7' ? {record, wireBytes} : null,
        followed.human ? {record, records} : null);
      row.append(card);
    } else if (hiddenIndex >= 0) {
      const tick = document.createElement('button');
      tick.className = 'lane-tick'; tick.style.gridColumn = String(visible.length + hiddenIndex + 2);
      tick.title = `r${record.revision} · ${laneLabel(record.event.id)} · click to expand`;
      tick.style.setProperty('--lane-color', `hsl(${(followed.laneOrder.indexOf(record.event.id) * 67) % 360} 62% 62%)`);
      tick.onclick = () => { followed.visibleLanes.add(record.event.id); renderFlowTab(scopeKey); };
      row.append(tick);
    }
    const allTick = document.createElement('i');
    allTick.className = 'lane-all-tick'; allTick.style.gridColumn = String(visible.length + hidden.length + 2);
    row.append(allTick); stream.append(row);
  }
  const recordsByRevision = new Map(records.map(record => [String(record.revision), record]));
  for (const row of stream.querySelectorAll('.lane-row[data-revision]')) {
    const record = recordsByRevision.get(row.dataset.revision);
    const time = row.querySelector('.lane-time');
    if (!record || !time) continue;
    const timestamp = Number(record.event.spider_received_at_ms);
    time.textContent = laneTimeLabel(timestamp, followed.timeMode, timeOrigin);
    time.title = laneTimeTitle(record, timeOrigin);
  }
  decorateLaneResponses(stream, records, followed);
  if (rebuild) requestAnimationFrame(() => { workspace.scrollTop = previousScroll; });
}

function appendMixedAscii(target, bytes) {
  let text = '', binary = [];
  const flushText = () => {
    if (!text) return;
    target.append(document.createTextNode(text));
    text = '';
  };
  const flushBinary = () => {
    if (!binary.length) return;
    const span = document.createElement('span');
    span.className = 'binary-run';
    span.textContent = `[${binary.map(value => value.toString(16).padStart(2, '0')).join(' ')}]`;
    target.append(span);
    binary = [];
  };
  for (const value of bytes) {
    if ((value >= 32 && value < 127) || value === 9 || value === 10 || value === 13) {
      flushBinary();
      text += String.fromCharCode(value);
    } else {
      flushText();
      binary.push(value);
    }
  }
  flushText();
  flushBinary();
}

function updateFlowRecord(record) {
  const event = record.event;
  const info = event.details?.info || {};
  let flow = flowRecords.get(event.id);
  if (!flow) {
    flow = {id: event.id, label: info.session || event.id, active: true,
            complete: startedConnections.has(event.id),
            evicted: 0,
            lastRevision: record.revision, latest: record,
            L: {count: 0, bytes: 0, l7Bytes: 0, l7Payloads: 0, l7Unknown: 0},
            R: {count: 0, bytes: 0, l7Bytes: 0, l7Payloads: 0, l7Unknown: 0}};
    flowRecords.set(event.id, flow);
  }
  const side = info.side === 'R' ? 'R' : 'L';
  flow[side].count += 1;
  flow[side].bytes += recordPayloadBytes(record).length;
  const l7 = l7PayloadView(record);
  if (l7.state === 'body') {
    flow[side].l7Bytes += l7.bytes.length;
    flow[side].l7Payloads += 1;
  } else if (l7.state !== 'none') {
    flow[side].l7Unknown += 1;
  }
  flow.label = info.session || flow.label;
  flow.lastRevision = record.revision;
  flow.latest = record;
  flow.active = true;
  if (flowRecords.size > 2000) {
    const oldest = [...flowRecords.values()].sort((a, b) => a.lastRevision - b.lastRevision)[0];
    if (oldest) flowRecords.delete(oldest.id);
  }
}

function updateFlowActivity(activeItems) {
  const activeIds = new Set(activeItems.map(item => item.id));
  let changed = false;
  for (const flow of flowRecords.values()) {
    const active = activeIds.has(flow.id);
    changed ||= flow.active !== active;
    flow.active = active;
  }
  return changed;
}

function pulseInspectionMetric(id, value) {
  const target = byId(id);
  if (!target) return;
  const next = String(value);
  if (target.textContent === next) return;
  target.textContent = next;
  target.classList.remove('metric-pulse');
  void target.offsetWidth;
  target.classList.add('metric-pulse');
}

function renderInspectionOverview() {
  const now = Date.now();
  while (inspectionIngress.length && inspectionIngress[0].at < now - 10000) inspectionIngress.shift();
  const active = [...flowRecords.values()].filter(flow => flow.active);
  const pending = payloadRecords.filter(record =>
    record.event.decision?.state === 'pending' && !record.decided).length;
  const recentBytes = inspectionIngress.reduce((total, item) => total + item.bytes, 0);
  pulseInspectionMetric('inspection-received', inspectionPayloadsReceived);
  pulseInspectionMetric('inspection-active-flows', active.length);
  pulseInspectionMetric('inspection-pending', pending);
  pulseInspectionMetric('inspection-rate', `${formatBytes(Math.round(recentBytes / 10))}/s`);
  pulseInspectionMetric('inspection-runs', inspectionRuns.completed);
  pulseInspectionMetric('inspection-errors', inspectionRuns.failed);
  byId('inspection-run-detail').textContent = `${inspectionRuns.running} running · manual + automatic`;
  const lastSeen = byId('inspection-last-seen');
  if (lastSeen) lastSeen.textContent = inspectionLastSeenAt
    ? `last payload ${Math.max(0, Math.floor((now - inspectionLastSeenAt) / 1000))}s ago`
    : 'waiting for traffic';
  const strip = byId('inspection-flow-strip');
  if (!strip) return;
  strip.replaceChildren();
  const hot = [...flowRecords.values()]
    .sort((a, b) => Number(b.active) - Number(a.active) || b.lastRevision - a.lastRevision)
    .slice(0, 6);
  if (!hot.length) {
    strip.className = 'inspection-flow-strip empty';
    strip.textContent = 'No inspected payloads yet.';
    return;
  }
  strip.className = 'inspection-flow-strip';
  for (const flow of hot) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `inspection-flow-chip${flow.active ? ' active' : ''}`;
    const total = flow.L.count + flow.R.count;
    button.innerHTML = `<i></i><span>${escapeHtml(flowListLabel(flow.label || flow.id, false))}</span>` +
      `<b>${total}</b><small>L ${flow.L.count} / R ${flow.R.count}</small>`;
    button.title = flow.label || flow.id;
    button.onclick = () => { if (flow.latest) selectPayload(flow.latest, false); };
    strip.append(button);
  }
}

function selectPayload(record, follow = false) {
  selectedPayload = record;
  followPayload = follow;
  byId('follow-payload').setAttribute('aria-pressed', String(followPayload));
  if (!selectedPayload) {
    byId('workbench-source').textContent = 'no connection-content captured yet';
    byId('workbench-source').className = 'empty';
    byId('workbench-info').textContent = 'waiting for metadata';
    byId('workbench-info').className = 'empty';
    byId('enrichment-viewer').hidden = true;
    return;
  }
  payloadBytes = recordPayloadBytes(selectedPayload);
  replacementBase64 = null;
  byId('replacement-text').value = '';
  if (selectedPayload.inspectOutput) displayScriptResult(selectedPayload.inspectOutput, true);
  renderPayload();
  renderPayloadList();
}

function ingestEvent(record) {
  if (!record || !record.event || record.revision <= revision) return;
  revision = record.revision;
  eventRecords.push(summarizeEvent(record));
  if (record.event.action === 'connection-start' && record.event.id) {
    startedConnections.add(record.event.id);
    const flow = flowRecords.get(record.event.id);
    if (flow) flow.complete = true;
  }
  if (record.event.action === 'hostname-info') ingestHostnameInfo(record.event);
  const sift = record.event.details?.info?.classification?.sift;
  if (Array.isArray(sift) && sift.length) {
    const previous = new Set(liveSiftClassifications.get(record.event.id) || []);
    const current = [...new Set(sift.filter(value => typeof value === 'string' && value.trim()))].sort();
    liveSiftClassifications.set(record.event.id, current);
    for (const classification of current) {
      observeSiftClassification(record.event.id, classification);
      if (!previous.has(classification)) addActivity('sift', 'SIFT',
          `${record.event.id} classified as ${classificationLabel(classification)}`,
          'Classification-based rules become effective from this point onward.');
    }
  }
  if (eventRecords.length > eventRecordLimit) eventRecords.splice(0, eventRecords.length - eventRecordLimit);
  const passed = record.event.decision?.state === 'passed';
  if (record.event.action === 'connection-content' && !passed &&
      (record.binaryPayload instanceof Uint8Array ||
       typeof record.event.details?.info?.content === 'string')) {
    record.cacheBytes = payloadSize(record);
    payloadRecords.push(record);
    const receivedBytes = recordPayloadBytes(record).length;
    inspectionPayloadsReceived += 1;
    inspectionLastSeenAt = Date.now();
    while (inspectionIngress.length && inspectionIngress[0].at < inspectionLastSeenAt - 10000) inspectionIngress.shift();
    const bucket = Math.floor(inspectionLastSeenAt / 1000) * 1000;
    if (inspectionIngress.at(-1)?.at === bucket) inspectionIngress.at(-1).bytes += receivedBytes;
    else inspectionIngress.push({at: bucket, bytes: receivedBytes});
    payloadCacheBytes += record.cacheBytes;
    updateFlowRecord(record);
    if (followPayload || !selectedPayload) selectedPayload = record;
    trimPayloadCache();
    if (record.event.inspection) {
      record.inspectOutput = {...record.event.inspection, replacement: null};
      record.inspectResult = record.event.inspection.ok ? 'backend completed' : 'backend error';
      record.decided = true;
    }
  }
  if (record.event.action === 'connection-stop') {
    const flow = flowRecords.get(record.event.id);
    if (flow) flow.active = false;
  }
  scheduleRender(true, (record.event.action === 'connection-content' && !passed) ||
                       record.event.action === 'connection-stop' ||
                       (record.event.action === 'connection-info' && Array.isArray(sift)));
}

function loadScriptSlot(number) {
  scriptSlot = number;
  byId('script-editor').value = localStorage.getItem(scriptStorageKey(number)) || defaultScript();
  for (const button of document.querySelectorAll('#script-slots button')) {
    button.setAttribute('aria-pressed', String(Number(button.dataset.slot) === number));
  }
}

async function inspectionRequest(path = '', body = undefined) {
  const response = await fetch(baseUrl() + '/api/inspection' + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {...headers(), 'Content-Type': 'application/json'},
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Inspection request failed');
  return result;
}

async function executeScript(record) {
  const bytes = record ? recordPayloadBytes(record) : payloadBytes.slice();
  const event = record?.event || {id: '', details: {info: {}}};
  try {
    return await inspectionRequest('/run', {
      script: byId('script-editor').value,
      event: {...event, details: {...event.details, info: {...event.details?.info, content: encodeBase64(bytes)}}},
      enrichments: (record?.enrichments || []).map(item => ({
        metadata: item.metadata || {}, content: encodeBase64(item.payload || new Uint8Array()),
      })),
    });
  } catch (error) {
    return {ok: false, replacement: null, logs: [], error: error.message};
  } finally {
    refreshBackendInspection();
  }
}

async function refreshBackendInspection() {
  if (inspectionPollInFlight) return;
  inspectionPollInFlight = true;
  try {
    const state = await inspectionRequest();
    inspectionRuns.completed = state.runs;
    inspectionRuns.failed = state.errors;
    inspectionRuns.running = state.running;
    byId('backend-inspection-status').textContent = state.enabled
      ? 'Backend enabled · ' + state.scope + ' · revision ' + state.revision
      : 'Backend stopped · revision ' + state.revision;
    byId('backend-inspection-output').textContent = state.recent.map(run =>
      '[' + run.run_id + ' ' + run.session_id + '] ' + (run.ok ? 'ok' : 'error') + '\n' +
      [...(run.logs || []), ...(run.error ? [run.error] : [])].join('\n')).join('\n\n');
    renderInspectionOverview();
  } catch (error) {
    byId('backend-inspection-status').textContent = error.message;
  } finally {
    inspectionPollInFlight = false;
  }
}

function displayScriptResult(data, automatic = false, replaceOutput = true) {
  const scriptStatus = byId('script-status');
  if (replaceOutput) {
    byId('script-output').textContent = [...(data.logs || []), ...(data.error ? [data.error] : [])].join('\n');
  }
  if (!data.ok) {
    scriptStatus.textContent = automatic ? 'inspect failed · accepted' : 'failed';
    scriptStatus.className = 'error';
    byId('replacement-text').value = '';
    replacementBase64 = null;
    return;
  }
  if (data.replacement === null) {
    scriptStatus.textContent = automatic ? 'inspect · unchanged' : 'unchanged';
    scriptStatus.className = 'ok';
    byId('replacement-text').value = '';
    replacementBase64 = null;
    return;
  }
  const replacement = decodeBase64(data.replacement);
  replacementBase64 = data.replacement;
  scriptStatus.textContent = `${automatic ? 'inspect · ' : ''}replace · ${replacement.length} B`;
  scriptStatus.className = 'ok';
  byId('replacement-text').value = new TextDecoder().decode(replacement);
}

async function runScript() {
  const scriptStatus = byId('script-status');
  scriptStatus.textContent = 'running…';
  scriptStatus.className = '';
  byId('run-script').disabled = true;
  const data = await executeScript(selectedPayload);
  byId('run-script').disabled = false;
  displayScriptResult(data);
  renderPayload();
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

function siftClassifications(item) {
  const direct = item?.classification?.sift;
  const event = item?.last_event?.details?.info?.classification?.sift;
  const values = Array.isArray(direct) ? direct : Array.isArray(event) ? event : [];
  return [...new Set(values.filter(value => typeof value === 'string' && value.trim()))].sort();
}

function classificationLabel(value) {
  const parts = String(value).split('.');
  const category = parts.shift() || 'sift';
  const names = {http1: 'HTTP/1', http2: 'HTTP/2', http3: 'HTTP/3',
    tls: 'TLS', ssh: 'SSH', smb1: 'SMB1', smb2: 'SMB2', smb3: 'SMB3',
    youtube: 'YouTube'};
  const body = parts.map(part => names[part] || part.replaceAll('-', ' ')).join(' · ');
  const prefix = category === 'app' ? 'APP' : category === 'protocol' ? 'L7' : category.toUpperCase();
  return `${prefix} ${body}`.trim();
}

function classificationChips(values) {
  return `<div class="chips classification-chips">${values.map(value => {
    const category = String(value).split('.')[0].replace(/[^a-z0-9_-]/gi, '');
    return `<span class="classification-${category}" title="${escapeHtml(value)}">${escapeHtml(classificationLabel(value))}</span>`;
  }).join('')}</div>`;
}

function renderSessionDetail(detail) {
  selectedSessionDetail = detail;
  const info = detail.last_event?.details?.info || {};
  const tls = info.tls || {};
  const l7 = info.l7 || {};
  const urls = Array.isArray(l7.details) ? l7.details : [];
  const signatures = Array.isArray(l7.signatures) ? l7.signatures : [];
  const ja4h = Array.isArray(l7.ja4h) ? l7.ja4h : [];
  const classifications = siftClassifications(detail);
  const eventTimeline = (detail.events || []).map(event => {
    const timestamp = formatTime(event.spider_received_at_ms);
    return `<details class="timeline-event"><summary><b>${escapeHtml(event.action || 'event')}</b><time>${escapeHtml(timestamp)}</time></summary><pre>${escapeHtml(JSON.stringify(event, null, 2))}</pre></details>`;
  }).join('');
  sessionDetail.innerHTML =
    `<div class="detail-hero"><span class="state ${escapeHtml(detail.state)}">${escapeHtml(detail.state)}</span><strong>${escapeHtml(resolveText(tls.sni || l7.app || detail.label || detail.id))}</strong><small>${escapeHtml(detail.id)}</small></div>` +
    `<dl class="detail-grid">` +
      detailRow('Started', formatTime(detail.started_at_ms)) +
      detailRow('Ended', detail.ended_at_ms ? formatTime(detail.ended_at_ms) : 'active') +
      detailRow('Duration', formatDuration(detail.started_at_ms, detail.ended_at_ms)) +
      detailRow('Events', detail.event_count) +
      detailRow('Connection', resolvedSessionLabel(info.session || detail.label), 'wide') +
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
    (classifications.length ? `<div class="detail-block"><h3>Sift classification</h3>${classificationChips(classifications)}</div>` : '') +
    (ja4h.length ? `<div class="detail-block"><h3>JA4H</h3>${ja4h.map(value => `<code>${escapeHtml(value)}</code>`).join('')}</div>` : '') +
    `<div class="detail-block"><h3>Event timeline</h3>${eventTimeline || '<span class="empty">none</span>'}</div>` +
    `<details class="raw-detail"><summary>Raw JSON</summary><pre>${escapeHtml(JSON.stringify(detail, null, 2))}</pre></details>`;
  sessionDetail.className = 'session-detail-content';
}

function sessionSubtitle(item) {
  const info = item.last_event?.details?.info || {};
  const sni = info.tls?.sni;
  const app = info.l7?.app;
  return [resolvedSessionLabel(item.label || 'unlabelled'), sni, app].filter(Boolean).join(' · ');
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
      (siftClassifications(item).length ? classificationChips(siftClassifications(item)) : '') +
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
  activeTab = tabId;
  for (const panel of document.querySelectorAll('.tab-panel')) panel.hidden = panel.id !== tabId;
  for (const button of document.querySelectorAll('.tabs button')) {
    button.setAttribute('aria-selected', String(button.dataset.tab === tabId));
  }
  if (tabId === 'events-tab') scheduleRender(true, false);
  if (tabId === 'history-tab') renderHistory();
  if (tabId === 'hostnames-tab') renderHostnames();
  if (tabId === 'diagnostics-tab') renderDiagnostics();
  if (tabId === 'workbench-tab') scheduleRender(false, true);
  for (const [sessionId, followed] of followedFlows) {
    if (followed.id === tabId) renderFlowTab(sessionId);
  }
}

function selectSession(id) {
  selectedSessionId = id;
  selectedSessionDetail = null;
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
  ++frontendDiagnostics.wsConnects;
  const socket = new WebSocket(url, protocols);
  socket.binaryType = 'arraybuffer';
  eventSocket = socket;
  socket.onopen = () => {
    ++frontendDiagnostics.wsOpens;
    frontendDiagnostics.lastWsOpenAtMs = Date.now();
    socket.send(JSON.stringify(revision === 0
      ? {type: 'subscribe', tail: true}
      : {type: 'subscribe', after: revision}));
    socket.send(JSON.stringify({type: 'live-edit', enabled: liveEdit}));
    inspectionRequest().then(state => {
      trafficRules = state.traffic_rules.rules.map(rule => ({...rule, value: rule.value || rule.address}));
      bypassAll = state.traffic_rules.bypass_all;
      renderTrafficRules();
      renderEndpointBuilder();
      refreshBackendInspection();
    }).catch(error => { byId('backend-inspection-status').textContent = error.message; });
  };
  socket.onmessage = message => {
    ++frontendDiagnostics.wsMessages;
    frontendDiagnostics.lastWsMessageAtMs = Date.now();
    if (message.data instanceof ArrayBuffer) {
      try {
        const envelopes = SpiderSxbn.decode(message.data);
        const original = envelopes[0];
        if (!original || original.metadata.type !== 'event') {
          throw new Error('SXBN chain does not start with an event envelope');
        }
        ++frontendDiagnostics.wsEvents;
        frontendDiagnostics.lastWsEventAtMs = Date.now();
        ingestEvent({revision: original.metadata.revision,
          event: original.metadata.event,
          binaryPayload: original.payload,
          enrichments: envelopes.slice(1)});
      } catch (error) {
        ++frontendDiagnostics.wsErrors;
        addActivity('system', 'SXBN ERROR', 'Binary event could not be decoded',
          error.message || String(error), 'warn');
      }
      return;
    }
    const data = JSON.parse(message.data);
    if (data.type === 'event') {
      ++frontendDiagnostics.wsEvents;
      frontendDiagnostics.lastWsEventAtMs = Date.now();
      ingestEvent({revision: data.revision, event: data.event});
    }
    if (data.type === 'subscribed') revision = Math.max(revision, Number(data.revision) || 0);
    if (data.type === 'traffic-rules-status') {
      const counts = new Map();
      for (const item of data.rules || []) {
        const parent = String(item.id || '').split('@')[0];
        counts.set(parent, (counts.get(parent) || 0) + (Number(item.matches) || 0));
      }
      for (const rule of trafficRules) rule.matches = counts.get(rule.id) || 0;
      bypassAll = Boolean(data.bypass_all);
      renderTrafficRules();
    }
    if (data.type === 'gap') {
      ++frontendDiagnostics.wsGaps;
      status.textContent = `stream gap · oldest r${data.oldest_available}`;
      status.className = 'error';
      addActivity('system', 'STREAM GAP', `Events before r${data.oldest_available} are unavailable`,
        'Some earlier payloads may be missing from flow views.', 'warn');
    }
  };
  socket.onerror = () => {
    ++frontendDiagnostics.wsErrors;
    socket.close();
  };
  socket.onclose = () => {
    if (eventSocket !== socket) return;
    ++frontendDiagnostics.wsCloses;
    frontendDiagnostics.lastWsCloseAtMs = Date.now();
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
  if (pollInFlight) return;
  pollInFlight = true;
  const pollStarted = performance.now();
  ++frontendDiagnostics.pollAttempts;
  frontendDiagnostics.lastPollStartedAtMs = Date.now();
  try {
    const [statusResponse, sessionResponse, historyResponse, diagnosticsResponse] = await Promise.all([
      fetch(`${baseUrl()}/api/status`, {headers: headers()}),
      fetch(`${baseUrl()}/api/sessions`, {headers: headers()}),
      fetch(`${baseUrl()}/api/session-history`, {headers: headers()}),
      fetch(`${baseUrl()}/api/diagnostics`, {headers: headers()}),
    ]);
    if (!statusResponse.ok) throw new Error(`status HTTP ${statusResponse.status}`);
    if (!sessionResponse.ok) throw new Error(`sessions HTTP ${sessionResponse.status}`);
    if (!historyResponse.ok) throw new Error(`history HTTP ${historyResponse.status}`);
    if (!diagnosticsResponse.ok) throw new Error(`diagnostics HTTP ${diagnosticsResponse.status}`);
    const [current, sessionData, historyData, diagnosticsData] = await Promise.all([
      statusResponse.json(), sessionResponse.json(), historyResponse.json(), diagnosticsResponse.json(),
    ]);
    backendDiagnostics = diagnosticsData;
    ++frontendDiagnostics.pollSuccesses;
    frontendDiagnostics.lastPollSuccessAtMs = Date.now();
    frontendDiagnostics.lastPollDurationMs = performance.now() - pollStarted;
    frontendDiagnostics.lastPollError = '';
    if (Number(current.hostname_revision) !== hostnameRevision) {
      const hostnameResponse = await fetch(`${baseUrl()}/api/hostnames`, {headers: headers()});
      if (!hostnameResponse.ok) throw new Error(`hostnames HTTP ${hostnameResponse.status}`);
      const hostnameData = await hostnameResponse.json();
      reverseHostnames.clear();
      for (const [address, entry] of Object.entries(hostnameData.mappings || {})) {
        reverseHostnames.set(address, entry);
      }
      hostnameRevision = Number(hostnameData.revision) || 0;
      refreshAggregateMembership();
      renderHostnames();
    }
    historyRecords = historyData.sessions.map(item => ({...item,
      last_event: item.last_event ? summarizeEvent({revision: 0, event: item.last_event}).event : item.last_event,
    }));
    activeSessionRecords = sessionData.sessions;
    for (const item of [...historyRecords, ...activeSessionRecords]) {
      for (const classification of siftClassifications(item)) {
        observeSiftClassification(item.id, classification);
      }
    }
    const flowActivityChanged = updateFlowActivity(activeSessionRecords);
    if (flowActivityChanged && activeTab === 'workbench-tab' && payloadListView === 'flows') {
      renderPayloadList();
    }
    updateObservedEndpoints(activeSessionRecords);
    renderEndpointBuilder();
    if (activeTab === 'history-tab') renderHistory();
    const proxy = current.smithproxy || {};
    const connectionState = proxy.state || 'unknown';
    if (connectionState !== lastConnectionActivityState) {
      addActivity('system', connectionState === 'connected' ? 'CONNECTED' : 'CONNECTION',
        `Smithproxy API is ${connectionState}`,
        connectionState === 'connected' ? 'Webhook and classification metadata can flow into Spider.' :
          'Traffic visibility may be incomplete until the connection recovers.',
        connectionState === 'connected' ? 'info' : 'warn');
      lastConnectionActivityState = connectionState;
    }
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
    renderActiveSessions(activeSessionRecords);
    status.textContent = `${eventSocket?.readyState === WebSocket.OPEN ? 'live' : 'connecting'} · r${revision}`;
    status.className = 'ok';
    socketSend({type: 'traffic-rules-status-request'});
    updateCacheStats();
    if (activeTab === 'diagnostics-tab') renderDiagnostics();
  } catch (error) {
    ++frontendDiagnostics.pollErrors;
    frontendDiagnostics.lastPollErrorAtMs = Date.now();
    frontendDiagnostics.lastPollDurationMs = performance.now() - pollStarted;
    frontendDiagnostics.lastPollError = error.message;
    status.textContent = `offline · ${error.message}`;
    status.className = 'error';
  } finally {
    pollInFlight = false;
  }
}

function diagnosticAge(timestamp) {
  if (!timestamp) return 'never';
  const age = Math.max(0, Date.now() - Number(timestamp));
  if (age < 1000) return `${age} ms ago`;
  return `${(age / 1000).toFixed(age < 10000 ? 1 : 0)} s ago`;
}

function renderDiagnostics() {
  const backendRevision = Number(backendDiagnostics?.store?.revision) || 0;
  const lag = Math.max(0, backendRevision - revision);
  const callback = backendDiagnostics?.store?.callbacks || {};
  const ws = backendDiagnostics?.websocket || {};
  const subscribed = Number(ws.clients?.subscribed) || 0;
  let health = 'healthy';
  let healthClass = 'diagnostics-health-ok';
  if (lag > 0 || (subscribed === 0 && frontendDiagnostics.wsOpens > 0)) {
    health = `attention · revision lag ${lag}, subscribed clients ${subscribed}`;
    healthClass = 'diagnostics-health-warn';
  }
  if (frontendDiagnostics.lastPollError || Number(ws.stream?.send_failures) > 0) {
    health = `problem · ${frontendDiagnostics.lastPollError || 'WebSocket send failures'}`;
    healthClass = 'diagnostics-health-error';
  }
  const healthNode = byId('diagnostics-health');
  healthNode.textContent = health;
  healthNode.className = healthClass;
  byId('diagnostics-path').textContent =
    `Smithproxy callbacks  ${callback.received || 0} · last ${diagnosticAge(callback.last_received_at_ms)}\n` +
    `Store revision        r${backendRevision}\n` +
    `WS published          ${ws.stream?.events_published || 0} · last ${diagnosticAge(ws.timestamps?.last_publish_at_ms)}\n` +
    `WS clients            ${ws.clients?.connected || 0} connected · ${subscribed} subscribed\n` +
    `Browser revision      r${revision} · lag ${lag}\n` +
    `Browser last event    ${diagnosticAge(frontendDiagnostics.lastWsEventAtMs)}`;
  byId('diagnostics-browser').textContent =
    `Uptime                ${Math.floor((Date.now() - frontendDiagnostics.startedAtMs) / 1000)} s\n` +
    `Polls                 ${frontendDiagnostics.pollSuccesses}/${frontendDiagnostics.pollAttempts} ok · ${frontendDiagnostics.pollErrors} errors\n` +
    `Last poll             ${frontendDiagnostics.lastPollDurationMs.toFixed(1)} ms · ${diagnosticAge(frontendDiagnostics.lastPollSuccessAtMs)}\n` +
    `WebSocket             ${eventSocket?.readyState === WebSocket.OPEN ? 'open' : 'closed'}\n` +
    `WS lifecycle          ${frontendDiagnostics.wsConnects} connects · ${frontendDiagnostics.wsCloses} closes · ${frontendDiagnostics.wsErrors} errors\n` +
    `WS messages/events    ${frontendDiagnostics.wsMessages}/${frontendDiagnostics.wsEvents} · gaps ${frontendDiagnostics.wsGaps}\n` +
    `Payload cache         ${payloadRecords.length} records · ${payloadCacheBytes} bytes · ${payloadsDropped} evicted`;
  byId('diagnostics-backend').textContent = backendDiagnostics
    ? JSON.stringify(backendDiagnostics, null, 2) : 'waiting for backend';
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
  flowRecords.clear();
  startedConnections.clear();
  liveSiftClassifications.clear();
  payloadCacheBytes = 0;
  payloadsDropped = 0;
  payloadBytesDropped = 0;
  evictionTimes = [];
  selectedPayload = null;
  historyRecords = [];
  selectedSessionId = null;
  selectedSessionDetail = null;
  reverseHostnames.clear();
  hostnameRevision = -1;
  events.textContent = '';
  renderPayloadList();
  updateCacheStats();
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
byId('resolve-hostnames').onchange = event => {
  hostnameResolving = event.target.checked;
  localStorage.setItem('spider-hostname-resolving', String(hostnameResolving));
  refreshResolvedViews();
};
byId('hide-resolved-ips').onchange = event => {
  hideResolvedIps = event.target.checked;
  localStorage.setItem('spider-hide-resolved-ips', String(hideResolvedIps));
  refreshResolvedViews();
};
byId('compact-session-labels').onchange = event => {
  compactSessionLabels = event.target.checked;
  localStorage.setItem('spider-compact-session-labels', String(compactSessionLabels));
  refreshResolvedViews();
};
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
  scheduleRender(true, false);
};
for (const button of document.querySelectorAll('.tabs button')) {
  button.onclick = () => showTab(button.dataset.tab);
}
for (const button of document.querySelectorAll('[data-hostname-sort]')) {
  button.onclick = () => {
    const key = button.dataset.hostnameSort;
    if (hostnameSort.key === key) hostnameSort.direction *= -1;
    else hostnameSort = {key, direction: 1};
    renderHostnames();
  };
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
  if (payloadScope === 'l7') return;
  payloadBytes = new TextEncoder().encode(event.target.value);
  if (payloadMode === 'hex') byId('payload-hex').textContent = encodeHex(payloadBytes);
};
for (const button of document.querySelectorAll('#payload-scope button')) {
  button.onclick = () => setPayloadScope(button.dataset.scope);
}
for (const button of document.querySelectorAll('#payload-modes button')) {
  button.onclick = () => setPayloadMode(button.dataset.mode);
}
for (const button of document.querySelectorAll('#payload-views button')) {
  button.onclick = () => {
    payloadListView = button.dataset.view === 'flows' ? 'flows' : 'payloads';
    localStorage.setItem('spider-payload-list-view', payloadListView);
    renderPayloadList();
  };
}
byId('font-smaller').onclick = () => setCodeSize(codeSize - 1);
byId('font-larger').onclick = () => setCodeSize(codeSize + 1);
const payloadViewDivider = byId('payload-view-divider');
function setPayloadViewSplit(listHeight, viewHeight) {
  const list = Math.max(80, Math.min(500, listHeight));
  const view = Math.max(80, Math.min(700, viewHeight));
  workbenchLayout.style.setProperty('--payload-list-height', `${Math.round(list)}px`);
  workbenchLayout.style.setProperty('--payload-view-height', `${Math.round(view)}px`);
  localStorage.setItem('spider-payload-list-height', String(Math.round(list)));
  localStorage.setItem('spider-payload-view-height', String(Math.round(view)));
}
payloadViewDivider.onpointerdown = event => {
  const startY = event.clientY;
  const startList = byId('payload-list').getBoundingClientRect().height;
  const startView = byId('payload-viewer').open
    ? byId('payload-viewer').querySelector('.payload-view-body').getBoundingClientRect().height : 300;
  payloadViewDivider.setPointerCapture(event.pointerId);
  payloadViewDivider.onpointermove = move => {
    const delta = move.clientY - startY;
    setPayloadViewSplit(startList + delta, startView - delta);
  };
  payloadViewDivider.onpointerup = () => { payloadViewDivider.onpointermove = null; };
};
payloadViewDivider.onkeydown = event => {
  if (!['ArrowUp', 'ArrowDown'].includes(event.key)) return;
  event.preventDefault();
  const delta = event.key === 'ArrowUp' ? -20 : 20;
  setPayloadViewSplit(byId('payload-list').getBoundingClientRect().height + delta,
    byId('payload-viewer').querySelector('.payload-view-body').getBoundingClientRect().height - delta);
};
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
byId('script-editor').oninput = event => localStorage.setItem(scriptStorageKey(), event.target.value);
byId('script-language').onchange = event => {
  scriptLanguage = event.target.value;
  localStorage.setItem('spider-script-language', scriptLanguage);
  loadScriptSlot(scriptSlot);
  byId('script-status').textContent = 'idle';
  byId('script-status').className = 'empty';
};
byId('run-script').onclick = runScript;
byId('reset-script').onclick = () => {
  localStorage.removeItem(scriptStorageKey());
  loadScriptSlot(scriptSlot);
};
byId('clear-traffic-rules').onclick = () => {
  if (trafficRules.length) addActivity('rule', 'RULES CLEARED', `${trafficRules.length} traffic rules removed`,
    'Future traffic will use the default analysis behavior.');
  trafficRules = [];
  syncTrafficRules();
};
byId('bypass-all').onclick = () => {
  bypassAll = !bypassAll;
  addActivity('rule', bypassAll ? 'BYPASS ON' : 'BYPASS OFF',
    bypassAll ? 'Global bypass enabled' : 'Global bypass disabled',
    bypassAll ? 'New payloads will be accepted without entering flow analysis.' :
      'New payloads will again be evaluated by traffic rules and flow analysis.');
  syncTrafficRules();
};
for (const button of document.querySelectorAll('#endpoint-menu button[data-mode]')) {
  button.onclick = () => {
    classifyEndpoint(endpointMenuTarget, button.dataset.mode);
    byId('endpoint-menu').hidden = true;
  };
}
byId('aggregate-hostname').onclick = () => {
  const suggested = suggestedHostnameSuffix(endpointMenuTarget?.value);
  const value = prompt('Hostname suffix to aggregate', suggested);
  if (value !== null) createEndpointAggregate('hostname-suffix', value);
  byId('endpoint-menu').hidden = true;
};
byId('aggregate-network').onclick = () => {
  const suggested = suggestedNetwork(endpointMenuTarget?.value);
  const value = prompt('IPv4 network in CIDR notation', suggested);
  if (value !== null) createEndpointAggregate('cidr', value);
  byId('endpoint-menu').hidden = true;
};
byId('aggregate-sift').onclick = () => {
  const source = String(endpointMenuTarget?.value || '');
  const parts = source.split('.');
  const suggested = parts.length > 1 ? `${parts[0]}.${parts[1].replace(/\d+$/, '')}*` : `${source}*`;
  const value = prompt('Sift label glob to aggregate', suggested);
  if (value !== null) createSiftAggregate(value);
  byId('endpoint-menu').hidden = true;
};
byId('remove-aggregate').onclick = () => {
  const aggregate = endpointMenuTarget;
  if (aggregate?.kind === 'sift-glob') {
    siftAggregates = siftAggregates.filter(value => value !== aggregate.value);
    trafficRules = trafficRules.filter(item => item.id !== aggregate.id);
    localStorage.setItem('spider-sift-aggregates', JSON.stringify(siftAggregates));
    addActivity('rule', 'AGGREGATE REMOVED', ruleLabel(aggregate),
      'Its Sift labels are visible individually again and no longer inherit its rule.');
    syncTrafficRules();
  } else if (aggregate && aggregate.kind !== 'address') {
    endpointAggregates = endpointAggregates.filter(item => item.id !== aggregate.id);
    trafficRules = trafficRules.filter(item => item.id !== aggregate.id);
    aggregateMembers.delete(aggregate.id);
    localStorage.setItem('spider-endpoint-aggregates', JSON.stringify(endpointAggregates));
    addActivity('rule', 'AGGREGATE REMOVED', ruleLabel(aggregate),
      'Its grouped addresses are visible individually again and no longer inherit its rule.');
    syncTrafficRules();
  }
  byId('endpoint-menu').hidden = true;
};
for (const button of document.querySelectorAll('[data-follow-scope]')) {
  button.onclick = () => {
    openFlowTab(flowMenuSession, button.dataset.followScope);
    byId('flow-menu').hidden = true;
  };
}
const activityDrawer = byId('activity-drawer');
activityDrawer.ontoggle = () => {
  if (activityDrawer.open) {
    activityUnread = 0;
    renderActivity();
  }
};
byId('clear-activity').onclick = event => {
  event.preventDefault();
  event.stopPropagation();
  activityRecords = [];
  activityUnread = 0;
  renderActivity();
};
for (const button of document.querySelectorAll('[data-activity-filter]')) {
  button.onclick = event => {
    event.preventDefault();
    const key = button.dataset.activityFilter;
    activityFilters[key] = !activityFilters[key];
    button.setAttribute('aria-pressed', String(activityFilters[key]));
    renderActivity();
  };
}
document.addEventListener('click', event => {
  for (const id of ['endpoint-menu', 'flow-menu']) {
    const menu = byId(id);
    if (!menu.hidden && !menu.contains(event.target)) menu.hidden = true;
  }
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    byId('endpoint-menu').hidden = true;
    byId('flow-menu').hidden = true;
  }
});
for (const button of document.querySelectorAll('[data-copy-target]')) {
  button.onclick = async event => {
    event.preventDefault();
    const target = byId(button.dataset.copyTarget);
    const value = 'value' in target ? target.value : target.textContent;
    try {
      await navigator.clipboard.writeText(value || '');
      const original = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = original; }, 900);
    } catch (_) {
      target.focus?.();
      target.select?.();
    }
  };
}
byId('payload-memory-limit').value = payloadMemoryLimit;
byId('payload-record-limit').value = payloadRecordLimit;
byId('event-record-limit').value = eventRecordLimit;
byId('apply-cache-limits').onclick = () => {
  payloadMemoryLimit = clampInteger(byId('payload-memory-limit').value, 8, 2048, 64);
  payloadRecordLimit = clampInteger(byId('payload-record-limit').value, 10, 10000, 200);
  eventRecordLimit = clampInteger(byId('event-record-limit').value, 100, 20000, 2000);
  byId('payload-memory-limit').value = payloadMemoryLimit;
  byId('payload-record-limit').value = payloadRecordLimit;
  byId('event-record-limit').value = eventRecordLimit;
  localStorage.setItem('spider-payload-memory-mib', String(payloadMemoryLimit));
  localStorage.setItem('spider-payload-record-limit', String(payloadRecordLimit));
  localStorage.setItem('spider-event-record-limit', String(eventRecordLimit));
  if (eventRecords.length > eventRecordLimit) {
    eventRecords.splice(0, eventRecords.length - eventRecordLimit);
  }
  trimPayloadCache();
  scheduleRender(true, true);
};
byId('clear-payloads').onclick = () => {
  payloadRecords = [];
  flowRecords.clear();
  selectedPayload = null;
  payloadBytes = new Uint8Array();
  payloadCacheBytes = 0;
  replacementBase64 = null;
  byId('payload-text').value = '';
  byId('payload-hex').textContent = '';
  byId('workbench-source').textContent = 'no connection-content captured yet';
  byId('workbench-source').className = 'empty';
  byId('workbench-info').textContent = 'waiting for metadata';
  byId('workbench-info').className = 'empty';
  updateCacheStats();
  scheduleRender(false, true);
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
      selectedSessionDetail = null;
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
document.querySelector('.inspection-metrics').insertAdjacentHTML('beforeend',
  '<div class="inspection-metric"><span>Script runs</span><strong id="inspection-runs">0</strong><small id="inspection-run-detail">0 running · manual + automatic</small></div>' +
  '<div class="inspection-metric attention"><span>Script errors</span><strong id="inspection-errors">0</strong><small>failed runs</small></div>');
document.querySelector('.editor-api-hint').textContent = 'Python runs on backend · Run previews · Deploy enables live execution';
byId('script-language').innerHTML = '<option value="python">Python · backend</option>';
const backendTools = document.createElement('div');
backendTools.className = 'workbench-tools';
backendTools.innerHTML = '<select id="inspection-scope" aria-label="Deployment scope"><option value="rules">INSPECT rules</option><option value="all">All non-bypassed content</option></select><button id="deploy-script">Deploy to backend</button><button id="stop-backend-script" class="secondary">Stop backend</button><button id="load-backend-script" class="secondary">Load deployed script</button><span id="backend-inspection-status">Backend not connected</span>';
document.querySelector('.workbench-script').append(backendTools);
const backendOutput = document.createElement('details');
backendOutput.innerHTML = '<summary>Backend run history (latest 20)</summary><pre id="backend-inspection-output"></pre>';
document.querySelector('.workbench-output').append(backendOutput);
byId('deploy-script').onclick = async () => {
  try {
    await inspectionRequest('', {script: byId('script-editor').value, enabled: true, scope: byId('inspection-scope').value});
    await refreshBackendInspection();
  } catch (error) { byId('backend-inspection-status').textContent = error.message; }
};
byId('stop-backend-script').onclick = async () => {
  try {
    const current = await inspectionRequest();
    await inspectionRequest('', {...current, enabled: false});
    await refreshBackendInspection();
  } catch (error) { byId('backend-inspection-status').textContent = error.message; }
};
byId('load-backend-script').onclick = async () => {
  try {
    const current = await inspectionRequest();
    byId('script-editor').value = current.script;
    byId('inspection-scope').value = current.scope;
    localStorage.setItem(scriptStorageKey(), current.script);
  } catch (error) { byId('backend-inspection-status').textContent = error.message; }
};
loadScriptSlot(1);
renderSessionGroupControls();
renderTrafficRules();
renderActivity();
updateCacheStats();
setPayloadMode(localStorage.getItem('spider-payload-mode') === 'hex' ? 'hex' : 'ascii');
showTab('workbench-tab');
setInterval(() => {
  if (activeTab === 'workbench-tab') refreshBackendInspection();
}, 1000);
bootstrapAndConnect();
