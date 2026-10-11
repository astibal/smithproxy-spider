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
let eventSocket = null, reconnectTimer = null, followPayload = true, liveEdit = false;
let lastRuleStatsRequest = 0;
let replacementBase64 = null;
let activeTab = 'events-tab', renderFrame = null, eventsDirty = true, payloadsDirty = true;
let payloadCacheBytes = 0, payloadsDropped = 0, payloadBytesDropped = 0, evictionTimes = [];
let pollInFlight = false;
let payloadMemoryLimit = Number(localStorage.getItem('spider-payload-memory-mib')) || 64;
let payloadRecordLimit = Number(localStorage.getItem('spider-payload-record-limit')) || 200;
let eventRecordLimit = Number(localStorage.getItem('spider-event-record-limit')) || 2000;
let pinnedSession = null;
let endpointFilter = {protocol: null, sourceHost: null, destinationHost: null, destinationPort: null};
let activeSessionRecords = [];
let endpointTtlSeconds = Math.max(10, Math.min(3600,
  Number(localStorage.getItem('spider-endpoint-ttl-seconds')) || 600));
let endpointDisplayLimit = Number(localStorage.getItem('spider-endpoint-display-limit') || 10);
if (![0, 10, 20].includes(endpointDisplayLimit)) endpointDisplayLimit = 10;
const observedSources = new Map(), observedDestinations = new Map(), observedPorts = new Map();
const reverseHostnames = new Map();
let hostnameRevision = -1;
let hostnameResolving = localStorage.getItem('spider-hostname-resolving') !== 'false';
let hideResolvedIps = localStorage.getItem('spider-hide-resolved-ips') === 'true';
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
let autoAcceptRules = [];
try {
  const savedRules = JSON.parse(localStorage.getItem('spider-auto-accept-rules') || '[]');
  if (Array.isArray(savedRules)) autoAcceptRules = savedRules.filter(rule =>
    rule && typeof rule.id === 'string' && typeof rule.filter === 'string');
} catch (_) {}
const eventFilters = {ping: false, sessions: false, status: true, other: false};
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
byId('resolve-hostnames').checked = hostnameResolving;
byId('hide-resolved-ips').checked = hideResolvedIps;
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

function syncAutoAcceptRules() {
  for (const rule of autoAcceptRules) delete rule.error;
  localStorage.setItem('spider-auto-accept-rules', JSON.stringify(autoAcceptRules));
  socketSend({type: 'auto-accept-rules', rules: autoAcceptRules});
}

function renderAutoAcceptRules() {
  const target = byId('auto-accept-rules');
  const invalid = autoAcceptRules.filter(rule => rule.error).length;
  byId('rule-count').textContent = autoAcceptRules.length
    ? `${autoAcceptRules.length}${invalid ? ` · ${invalid} invalid` : ''}` : 'none';
  target.replaceChildren();
  if (!autoAcceptRules.length) {
    target.textContent = 'none';
    target.className = 'auto-accept-rules empty';
    return;
  }
  target.className = 'auto-accept-rules';
  for (const rule of autoAcceptRules) {
    const row = document.createElement('div');
    row.className = `auto-rule${rule.enabled === false ? ' disabled' : ''}${rule.error ? ' error' : ''}`;
    if (rule.error) row.title = rule.error;
    const enabled = document.createElement('input');
    enabled.type = 'checkbox';
    enabled.checked = rule.enabled !== false;
    enabled.title = 'Enable auto-accept filter';
    enabled.onchange = () => {
      rule.enabled = enabled.checked;
      renderAutoAcceptRules();
      syncAutoAcceptRules();
    };
    const expression = document.createElement('code');
    expression.textContent = rule.filter;
    expression.title = rule.filter;
    const matches = document.createElement('small');
    matches.className = 'auto-rule-stats';
    matches.textContent = rule.enabled === false
      ? 'paused'
      : `${Number(rule.matches || 0).toLocaleString()} accepted`;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'danger-subtle';
    remove.textContent = '×';
    remove.title = 'Remove auto-accept filter';
    remove.onclick = () => {
      autoAcceptRules = autoAcceptRules.filter(item => item !== rule);
      renderAutoAcceptRules();
      syncAutoAcceptRules();
    };
    row.append(enabled, expression, matches, remove);
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
      row.textContent = item.id;
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
  updateEndpointFilterDraft();
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
      updateEndpointFilterDraft();
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
      updateEndpointFilterDraft();
    };
    controls.append(button);
  }
}

function suggestedFilter(item) {
  const connection = parseSessionLabel(item.label || item.last_event?.details?.info?.session);
  if (!connection) return '';
  const protocol = ['udp', 'quic'].includes(connection.sourceProtocol) ? 'udp' : 'tcp';
  const clauses = {
    src: `src host ${connection.sourceHost}`,
    dst: `dst host ${connection.destinationHost}`,
    dport: `dst port ${connection.destinationPort}`,
  };
  return [protocol, ...sessionGroupOrder
    .filter(key => sessionGroupsEnabled.has(key))
    .map(key => clauses[key])].join(' and ');
}

function endpointFilterExpression() {
  const parts = [endpointFilter.protocol || 'tcp'];
  const clauses = {
    src: endpointFilter.sourceHost ? `src host ${endpointFilter.sourceHost}` : null,
    dst: endpointFilter.destinationHost ? `dst host ${endpointFilter.destinationHost}` : null,
    dport: endpointFilter.destinationPort !== null ? `dst port ${endpointFilter.destinationPort}` : null,
  };
  for (const key of sessionGroupOrder) {
    if (sessionGroupsEnabled.has(key) && clauses[key]) parts.push(clauses[key]);
  }
  return parts.length > 1 ? parts.join(' and ') : '';
}

function updateEndpointFilterDraft() {
  const expression = endpointFilterExpression();
  const draft = byId('endpoint-filter-draft');
  draft.textContent = expression || 'select an endpoint';
  draft.className = `filter-draft${expression ? '' : ' empty'}`;
  byId('open-filter-draft').disabled = !expression;
  if (expression) {
    byId('rule-filter').value = expression;
    byId('pinned-session').textContent = 'Draft from observed endpoints';
    byId('pinned-session').className = 'pinned-session';
  }
}

function selectEndpoint(part, value, protocol = null) {
  endpointFilter[part] = endpointFilter[part] === value ? null : value;
  if (protocol && endpointFilter[part] !== null) endpointFilter.protocol = protocol;
  updateEndpointFilterDraft();
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

function normalizeHostname(value) {
  return value.toLowerCase().replace(/\.+$/, '');
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
  const entries = [...reverseHostnames.entries()].sort((a, b) =>
    a[0].localeCompare(b[0], undefined, {numeric: true}));
  byId('hostname-count').textContent = `${entries.length}`;
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
    button.setAttribute('aria-pressed', String(endpointFilter.destinationPort === port));
    const number = document.createElement('span'); number.textContent = String(port);
    const count = document.createElement('small'); count.textContent = String(data.count);
    button.append(number, count);
    button.onclick = () => {
      selectEndpoint('destinationPort', port, data.protocol);
      renderEndpointBuilder();
    };
    portTarget.append(button);
  }
  attachEndpointScrollHint(portTarget);

  const sourceTarget = byId('observed-sources');
  sourceTarget.replaceChildren();
  sourceTarget.className = `endpoint-list${observedSources.size ? '' : ' empty'}`;
  if (!observedSources.size) sourceTarget.textContent = 'none';
  for (const [host, data] of limitedEndpoints([...observedSources]
      .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0])))) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'endpoint-choice';
    button.setAttribute('aria-pressed', String(endpointFilter.sourceHost === host));
    const address = document.createElement('span'); address.textContent = endpointDisplay(host);
    const count = document.createElement('small'); count.textContent = `${data.protocol} · ${data.count}`;
    button.append(address, count);
    decorateExpiringEndpoint(button, data, now);
    button.onclick = () => { selectEndpoint('sourceHost', host, data.protocol); renderEndpointBuilder(); };
    sourceTarget.append(button);
  }
  attachEndpointScrollHint(sourceTarget);

  const destinationTarget = byId('observed-destinations');
  destinationTarget.replaceChildren();
  destinationTarget.className = `endpoint-list${observedDestinations.size ? '' : ' empty'}`;
  if (!observedDestinations.size) destinationTarget.textContent = 'none';
  for (const [host, data] of limitedEndpoints([...observedDestinations]
      .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0])))) {
    const hostButton = document.createElement('button');
    hostButton.type = 'button'; hostButton.className = 'endpoint-choice';
    hostButton.setAttribute('aria-pressed', String(endpointFilter.destinationHost === host));
    const address = document.createElement('span'); address.textContent = endpointDisplay(host);
    const count = document.createElement('small'); count.textContent = String(data.count);
    hostButton.append(address, count);
    decorateExpiringEndpoint(hostButton, data, now);
    hostButton.onclick = () => { selectEndpoint('destinationHost', host, data.protocol); renderEndpointBuilder(); };
    destinationTarget.append(hostButton);
  }
  attachEndpointScrollHint(destinationTarget);
}

function pinSession(item, focus = true) {
  const event = item.event || item.last_event || {};
  const session = {
    id: item.id || event.id || 'unknown',
    label: item.label || event.details?.info?.session || item.id || event.id || 'unlabelled',
  };
  pinnedSession = session;
  byId('pinned-session').textContent = `${session.id} · ${resolvedSessionLabel(session.label)}`;
  byId('pinned-session').className = 'pinned-session';
  byId('rule-filter').value = suggestedFilter(session);
  byId('rule-compose').hidden = false;
  showTab('workbench-tab');
  if (focus) byId('rule-filter').focus();
}

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
  const content = record.event.details?.info?.content;
  if (typeof content !== 'string') return 0;
  // A JS string may occupy two bytes per character. Include a small object overhead.
  return content.length * 2 + 1024;
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
      content: `<payload ${decodedPayloadSize(info.content)} B; retained in workbench cache>`,
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
    payloadBytesDropped += bytes;
    evictionTimes.push(Date.now());
    if (selectedPayload === removed) selectedPayload = null;
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
        payloadBytes = decodeBase64(selectedPayload.event.details?.info?.content);
        replacementBase64 = null;
        renderPayload();
      }
      renderPayloadList();
      payloadsDirty = false;
    }
  });
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
  if (payloadMode === 'hex') byId('payload-hex').textContent = encodeHex(payloadBytes);
  else byId('payload-text').value = new TextDecoder().decode(payloadBytes);
  const info = selectedPayload?.event?.details?.info || {};
  byId('workbench-source').textContent = selectedPayload
    ? `r${selectedPayload.revision} · ${info.side || '?'} · ${payloadBytes.length} B · ${resolvedSessionLabel(info.session || selectedPayload.event.id)}`
    : `${payloadBytes.length} B sample`;
  byId('workbench-source').className = '';
  const pending = selectedPayload?.event?.decision?.state === 'pending' && !selectedPayload.decided;
  byId('accept-payload').disabled = !pending;
  byId('accept-session').disabled = !pending;
  byId('discard-payload').disabled = !pending;
  byId('replace-payload').disabled = !pending || replacementBase64 === null;
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
  for (let index = payloadRecords.length - 1; index >= 0; --index) {
    const record = payloadRecords[index];
    const info = record.event.details?.info || {};
    const size = Math.floor((info.content?.length || 0) * 3 / 4);
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `payload-row${record === selectedPayload ? ' selected' : ''}` +
      `${record.event.decision?.state === 'pending' && !record.decided ? ' pending' : ''}` +
      `${record.decided ? ' decided' : ''}`;
    row.innerHTML = `<span>r${record.revision}</span><b>${escapeHtml(info.side || '?')}</b>` +
      `<span>${escapeHtml(formatBytes(size) || `${size} B`)}</span>` +
      `<span>${escapeHtml(resolvedSessionLabel(info.session || record.event.id || 'unlabelled'))}</span>`;
    row.onclick = () => {
      selectPayload(record, false);
      pinSession(record, false);
    };
    list.append(row);
  }
  if (followPayload) list.scrollTop = 0;
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
  eventRecords.push(summarizeEvent(record));
  if (record.event.action === 'hostname-info') ingestHostnameInfo(record.event);
  if (eventRecords.length > eventRecordLimit) eventRecords.splice(0, eventRecords.length - eventRecordLimit);
  if (record.event.action === 'connection-content' &&
      typeof record.event.details?.info?.content === 'string') {
    record.cacheBytes = payloadSize(record);
    payloadRecords.push(record);
    payloadCacheBytes += record.cacheBytes;
    if (followPayload || !selectedPayload) selectedPayload = record;
    trimPayloadCache();
  }
  scheduleRender(true, record.event.action === 'connection-content');
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
  selectedSessionDetail = detail;
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
  if (tabId === 'workbench-tab') scheduleRender(false, true);
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
  const socket = new WebSocket(url, protocols);
  eventSocket = socket;
  socket.onopen = () => {
    socket.send(JSON.stringify(revision === 0
      ? {type: 'subscribe', tail: true}
      : {type: 'subscribe', after: revision}));
    socket.send(JSON.stringify({type: 'live-edit', enabled: liveEdit}));
    socket.send(JSON.stringify({type: 'auto-accept-rules', rules: autoAcceptRules}));
  };
  socket.onmessage = message => {
    const data = JSON.parse(message.data);
    if (data.type === 'event') ingestEvent({revision: data.revision, event: data.event});
    if (data.type === 'subscribed') revision = Math.max(revision, Number(data.revision) || 0);
    if (data.type === 'auto-accept-rules-status') {
      const errors = new Map((data.errors || []).map(item => [item.id, item.error]));
      const counts = new Map((data.counts || []).map(item => [item.id, Number(item.matches) || 0]));
      for (const rule of autoAcceptRules) {
        rule.error = errors.get(rule.id) || null;
        rule.matches = counts.get(rule.id) || 0;
      }
      renderAutoAcceptRules();
    }
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
  if (pollInFlight) return;
  pollInFlight = true;
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
    if (Number(current.hostname_revision) !== hostnameRevision) {
      const hostnameResponse = await fetch(`${baseUrl()}/api/hostnames`, {headers: headers()});
      if (!hostnameResponse.ok) throw new Error(`hostnames HTTP ${hostnameResponse.status}`);
      const hostnameData = await hostnameResponse.json();
      reverseHostnames.clear();
      for (const [address, entry] of Object.entries(hostnameData.mappings || {})) {
        reverseHostnames.set(address, entry);
      }
      hostnameRevision = Number(hostnameData.revision) || 0;
      renderHostnames();
    }
    historyRecords = historyData.sessions.map(item => ({...item,
      last_event: item.last_event ? summarizeEvent({revision: 0, event: item.last_event}).event : item.last_event,
    }));
    activeSessionRecords = sessionData.sessions;
    updateObservedEndpoints(activeSessionRecords);
    renderEndpointBuilder();
    if (activeTab === 'history-tab') renderHistory();
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
    renderActiveSessions(activeSessionRecords);
    status.textContent = `${eventSocket?.readyState === WebSocket.OPEN ? 'live' : 'connecting'} · r${revision}`;
    status.className = 'ok';
    if (Date.now() - lastRuleStatsRequest >= 5000 &&
        socketSend({type: 'auto-accept-rules-status-request'})) {
      lastRuleStatsRequest = Date.now();
    }
    updateCacheStats();
  } catch (error) {
    status.textContent = `offline · ${error.message}`;
    status.className = 'error';
  } finally {
    pollInFlight = false;
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
  if (payloadMode === 'hex') byId('payload-hex').textContent = encodeHex(payloadBytes);
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
function addAutoAcceptRule() {
  const expression = byId('rule-filter').value.trim();
  if (!expression) return;
  autoAcceptRules.push({id: `rule-${Date.now()}-${Math.random().toString(16).slice(2)}`,
                        filter: expression, enabled: true});
  renderAutoAcceptRules();
  syncAutoAcceptRules();
  byId('rule-filter').select();
  if (payloadRecords.length) {
    selectPayload(payloadRecords[payloadRecords.length - 1], true);
  } else {
    followPayload = true;
    byId('follow-payload').setAttribute('aria-pressed', 'true');
  }
}
byId('add-rule').onclick = addAutoAcceptRule;
byId('rule-filter').onkeydown = event => {
  if (event.key !== 'Enter') return;
  event.preventDefault();
  addAutoAcceptRule();
};
byId('clear-endpoint-filter').onclick = () => {
  const previous = endpointFilterExpression();
  endpointFilter = {protocol: null, sourceHost: null, destinationHost: null, destinationPort: null};
  updateEndpointFilterDraft();
  if (byId('rule-filter').value === previous) byId('rule-filter').value = '';
  byId('pinned-session').textContent = 'Build a draft from observed endpoints or enter a filter directly.';
  byId('pinned-session').className = 'pinned-session empty';
  renderEndpointBuilder(activeSessionRecords);
};
byId('open-filter-draft').onclick = () => {
  const expression = endpointFilterExpression();
  if (!expression) return;
  byId('rule-filter').value = expression;
  showTab('workbench-tab');
  byId('rule-filter').focus();
};
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
  selectedPayload = null;
  payloadBytes = new Uint8Array();
  payloadCacheBytes = 0;
  replacementBase64 = null;
  byId('payload-text').value = '';
  byId('payload-hex').textContent = '';
  byId('workbench-source').textContent = 'no connection-content captured yet';
  byId('workbench-source').className = 'empty';
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
loadScriptSlot(1);
renderSessionGroupControls();
renderAutoAcceptRules();
updateCacheStats();
setPayloadMode(localStorage.getItem('spider-payload-mode') === 'hex' ? 'hex' : 'ascii');
connect();
