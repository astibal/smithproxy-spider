/* The local library and the backend chain deliberately have separate lifecycles. */
(() => {
  const heavy = document.createElement('details');
  heavy.className = 'heavy-traffic-settings';
  heavy.innerHTML = '<summary><label><input id="heavy-enabled" type="checkbox" disabled> Ignore heavy traffic</label></summary>' +
    '<label>Grace (s) <input id="heavy-grace" type="number" min="5" max="300" value="5"></label>' +
    '<label>Messages/s <input id="heavy-messages" type="number" min="1" value="200"></label>' +
    '<label>Bytes/s <input id="heavy-bytes" type="number" min="1" value="1048576"></label>' +
    '<label>Sustained (s) <input id="heavy-sustain" type="number" min="1" max="60" value="3"></label>' +
    '<label><input id="heavy-managed" type="checkbox"> Also cut Collection / script traffic</label>' +
    '<button id="heavy-apply" type="button">Apply limits</button><small id="heavy-status">Backend settings unavailable</small>';
  document.querySelector('.sidebar-tabs').after(heavy);
  let heavyConfig = null, heavyBusy = false;
  const heavyFields = {grace_seconds: 'grace', messages_per_second: 'messages', bytes_per_second: 'bytes', sustain_seconds: 'sustain'};
  async function saveHeavy(settings) {
    if (heavyBusy || !heavyConfig) return;
    heavyBusy = true; byId('heavy-enabled').disabled = true;
    try {
      heavyConfig = await inspectionRequest('/heavy-traffic', settings);
      byId('heavy-status').textContent = 'Backend confirmed. Settings last until backend restart.';
    } catch (error) { byId('heavy-status').textContent = error.message; }
    finally { heavyBusy = false; byId('heavy-enabled').disabled = false; byId('heavy-enabled').checked = !!heavyConfig.enabled; }
  }
  byId('heavy-enabled').onclick = event => event.stopPropagation();
  byId('heavy-enabled').onchange = () => saveHeavy({enabled: byId('heavy-enabled').checked});
  byId('heavy-apply').onclick = () => saveHeavy({...Object.fromEntries(Object.entries(heavyFields).map(([name, suffix]) =>
    [name, Number(byId('heavy-' + suffix).value)])), include_managed: byId('heavy-managed').checked});
  window.addEventListener('inspection-state', event => {
    const config = event.detail.heavy_traffic;
    if (!config || heavyBusy) return;
    const changed = JSON.stringify(config) !== JSON.stringify(heavyConfig);
    heavyConfig = config;
    byId('heavy-enabled').disabled = false; byId('heavy-enabled').checked = config.enabled;
    heavy.title = `First ${config.grace_seconds} seconds are always captured. Then >${config.messages_per_second} messages/s OR >${config.bytes_per_second} bytes/s for ${config.sustain_seconds} seconds stops capture, not the transfer. Already stopped sessions cannot be resumed. With active scripts, all traffic is exempt unless explicitly enabled here.`;
    if (changed && !heavy.contains(document.activeElement)) {
      for (const [name, suffix] of Object.entries(heavyFields)) byId('heavy-' + suffix).value = config[name];
      byId('heavy-managed').checked = config.include_managed;
    }
    byId('heavy-status').textContent = config.enabled ? 'Protection enabled on backend' : 'Protection disabled on backend';
  });
  window.addEventListener('inspection-unavailable', () => { byId('heavy-enabled').disabled = true; byId('heavy-status').textContent = 'Backend unavailable — state unverified'; });
  const editor = byId('script-editor');
  const key = 'spider-script-library-v1';
  let library;
  try { library = JSON.parse(localStorage.getItem(key)); } catch (_) {}
  if (!Array.isArray(library) || !library.length) {
    library = [1, 2, 3, 4].map(slot => ({
      id: `imported-${slot}`, name: `Script ${slot}`, revision: 1,
      source: localStorage.getItem(`spider-python-script-${slot}`) || defaultScript(),
    }));
  }
  let selected = library[0], state = null, stagedOrder = null, stagedRevision = null, busy = false;
  const seenNotifications = new Set();
  const persist = () => localStorage.setItem(key, JSON.stringify(library));
  const button = (label, action) => {
    const result = document.createElement('button');
    result.className = 'secondary';
    result.type = 'button'; result.textContent = label; result.onclick = action;
    return result;
  };
  const workspace = document.createElement('div');
  workspace.className = 'inspection-workspace';
  const sidebar = document.createElement('aside');
  sidebar.className = 'inspection-sidebar';
  sidebar.innerHTML = '<h3>Script library · this browser</h3><div id="library-list"></div>' +
    '<button id="library-new">+ New script</button><hr>' +
    '<h3>Backend chain ↓</h3><p id="chain-connection">Not connected</p>' +
    '<small id="chain-sandbox" hidden title="Scripts require Linux Landlock and seccomp. No network or subprocesses; files are limited to read-only Python runtime and shared storage. If isolation cannot be activated, execution is refused.">Kernel sandbox required · no network / subprocesses</small>' +
    '<div id="chain-list"></div><button id="chain-apply-order" hidden>Apply order</button>' +
    '<p id="chain-message" role="status"></p><hr><h3>Collection · backend</h3><p id="collection-status"></p>';
  const layout = byId('inspection-layout');
  layout.before(workspace); workspace.append(sidebar, layout);
  byId('script-slots').hidden = true;
  byId('reset-script').hidden = true;
  backendTools.hidden = true;
  const toolbar = document.createElement('div');
  toolbar.className = 'library-toolbar';
  toolbar.innerHTML = '<label>Name <input id="library-name" maxlength="200"></label>' +
    '<button id="library-save">Save to library</button><button id="library-export">Export script</button>' +
    '<span id="library-version"></span>' +
    '<label>Deploy target <select id="chain-target"><option value="">New disabled item</option></select></label>' +
    '<label>Scope <select id="chain-scope"><option value="rules">INSPECT traffic</option><option value="all">All non-bypassed traffic</option></select></label>' +
    '<label>Session filter <input id="chain-filter" placeholder="Optional: dst port 443"></label>' +
    '<label>Instance <select id="chain-instancing"><option value="message">Per message</option><option value="flow">Per flow · both directions</option><option value="endpoint">Per endpoint</option></select></label>' +
    '<label>Endpoint key <select id="chain-endpoint" disabled><option value="destination">Destination protocol / IP / port</option><option value="source">Source IP · all ports</option></select></label>' +
    '<details id="chain-runtime-settings"><summary>Runtime limits · timeout, suspension, state retention</summary><div class="chain-runtime-fields">' +
    '<label>Time budget (ms) <input id="chain-timeout" type="number" min="50" max="3000" value="1000"></label>' +
    '<label>Errors before suspend <input id="chain-error-limit" type="number" min="1" max="100" value="3"></label>' +
    '<label>Max instances <input id="chain-max-instances" type="number" min="1" max="1024" value="128"></label>' +
    '<label>Idle expiry (s) <input id="chain-idle" type="number" min="1" max="86400" value="1800"></label>' +
    '<small>Five consecutive slow runs (≥80% budget) suspend deployment. api.state resets on deploy/disable/resume.</small></div></details>' +
    '<small class="storage-preview-note">api.storage is persistent and shared — Run on selected writes there too.</small>' +
    '<button id="library-deploy">Deploy saved version…</button>';
  document.querySelector('.workbench-script .editor-frame').before(toolbar);
  byId('chain-instancing').onchange = () => {
    byId('chain-endpoint').disabled = byId('chain-instancing').value !== 'endpoint';
    byId('chain-max-instances').disabled = byId('chain-idle').disabled = byId('chain-instancing').value === 'message';
  };
  byId('chain-instancing').onchange();

  function renderVersion() {
    const dirty = editor.value !== selected.source || byId('library-name').value !== selected.name;
    const deployed = state?.chain?.find(item => item.id === byId('chain-target').value);
    byId('library-version').textContent = `Saved v${selected.revision}` +
      (dirty ? ' · draft changed (not deployed)' : ' · saved') +
      (deployed ? ` · backend v${deployed.version}${deployed.script !== selected.source ? ' · different source' : ''}` : '');
    byId('library-deploy').disabled = dirty || busy || !state;
  }
  function renderLibrary() {
    const list = byId('library-list'); list.replaceChildren();
    for (const item of library) {
      const row = button(item.name, () => select(item));
      row.setAttribute('aria-pressed', String(item === selected));
      list.append(row);
    }
  }
  function select(item) {
    selected = item;
    editor.value = item.draft ?? item.source;
    byId('library-name').value = item.draftName ?? item.name;
    byId('chain-target').value = item.deployment?.backend === baseUrl() ? item.deployment.id : '';
    byId('chain-target').onchange?.();
    renderLibrary(); renderVersion();
    editor.dispatchEvent(new Event('input', {bubbles: true}));
  }
  editor.oninput = () => {
    selected.draft = editor.value; persist(); renderVersion();
  };
  byId('library-name').oninput = () => {
    selected.draftName = byId('library-name').value; persist(); renderVersion();
  };
  byId('library-save').onclick = () => {
    if (!byId('library-name').value.trim()) return;
    selected.source = editor.value; selected.name = byId('library-name').value.trim();
    selected.revision++; delete selected.draft; delete selected.draftName;
    persist(); renderLibrary(); renderVersion();
  };
  byId('library-new').onclick = () => {
    const item = {id: crypto.randomUUID(), name: 'New script', revision: 1, source: 'return None\n'};
    library.push(item); persist(); select(item);
    byId('chain-target').value = ''; renderVersion();
  };
  byId('library-export').onclick = () => {
    const url = URL.createObjectURL(new Blob([editor.value], {type: 'text/x-python'}));
    const anchor = document.createElement('a'); anchor.href = url;
    anchor.download = (selected.name.replace(/[^a-z0-9_-]/gi, '_') || 'script') + '.py';
    anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  async function change(request, revision = state?.revision) {
    if (busy || revision === undefined) return;
    const deploying = selected;
    busy = true; renderVersion();
    byId('chain-message').textContent = 'Waiting for backend…';
    try {
      const next = await inspectionRequest('', {...request, revision});
      stagedOrder = null; state = next; renderBackend();
      if (request.operation === 'deploy') {
        const deployed = request.id || next.chain.at(-1)?.id;
        deploying.deployment = {backend: baseUrl(), id: deployed};
        persist();
        if (selected === deploying) byId('chain-target').value = deployed;
      }
      byId('chain-message').textContent = 'Backend confirmed.';
    } catch (error) {
      byId('chain-message').textContent = error.message;
    } finally { busy = false; renderVersion(); }
  }
  byId('library-deploy').onclick = () => {
    const id = byId('chain-target').value;
    if (!confirm(id ? 'Replace this backend version? If enabled, the new version will process live traffic.' :
      'Validate and deploy a new DISABLED backend item?')) return;
    change({operation: 'deploy', id, name: selected.name, script: selected.source,
      scope: byId('chain-scope').value, filter: byId('chain-filter').value,
      instancing: byId('chain-instancing').value, endpoint: byId('chain-endpoint').value,
      timeout_ms: Number(byId('chain-timeout').value), error_limit: Number(byId('chain-error-limit').value),
      max_instances: Number(byId('chain-max-instances').value), idle_seconds: Number(byId('chain-idle').value)});
  };
  byId('chain-target').onchange = () => {
    const target = state?.chain?.find(item => item.id === byId('chain-target').value);
    if (target) { byId('chain-scope').value = target.scope; byId('chain-filter').value = target.filter; }
    byId('chain-instancing').value = target?.instancing || 'message';
    byId('chain-endpoint').value = target?.endpoint || 'destination';
    byId('chain-timeout').value = target?.timeout_ms || 1000;
    byId('chain-error-limit').value = target?.error_limit || 3;
    byId('chain-max-instances').value = target?.max_instances || 128;
    byId('chain-idle').value = target?.idle_seconds || 1800;
    byId('chain-instancing').onchange();
    renderVersion();
  };
  byId('chain-apply-order').onclick = () => change({operation: 'reorder', ids: stagedOrder}, stagedRevision);
  function renderBackend() {
    const chain = state.chain || [];
    const active = chain.filter(item => item.enabled).length;
    byId('chain-connection').textContent = `${baseUrl()} · ${active} enabled · ${state.running} executing`;
    byId('chain-sandbox').hidden = !state.sandbox?.required;
    const target = byId('chain-target'), oldTarget = target.value;
    target.replaceChildren(new Option('New disabled item', ''));
    for (const item of chain) target.add(new Option(`${item.name} · v${item.version}`, item.id));
    target.value = chain.some(item => item.id === oldTarget) ? oldTarget : '';
    if (stagedOrder && stagedRevision !== state.revision) {
      stagedOrder = null; byId('chain-message').textContent = 'Backend changed; staged order discarded.';
    }
    const ordered = stagedOrder ? stagedOrder.map(id => chain.find(item => item.id === id)) : chain;
    const list = byId('chain-list'); list.replaceChildren();
    if (!chain.length) list.textContent = state.script
      ? `Legacy deployment: ${state.enabled ? 'enabled' : 'disabled'} — preserved on first deploy.`
      : 'No deployed scripts.';
    ordered.forEach((item, index) => {
      const row = document.createElement('div'); row.className = 'chain-item';
      const title = document.createElement('strong');
      title.textContent = `${index + 1}. ${item.suspended ? '⚠ Suspended ·' : item.enabled ? '●' : '○'} ${item.name} · v${item.version}`;
      row.classList.toggle('chain-suspended', !!item.suspended);
      const stats = document.createElement('small');
      stats.textContent = `${item.enabled ? 'Enabled' : 'Disabled'} · ${item.runs} runs · ${item.errors} errors\n` +
        `Traffic: ${item.scope} ${item.filter || ''}\nLast run: ${item.last_run_ms ? new Date(item.last_run_ms).toLocaleString() : 'never'}`;
      if (item.workers) stats.textContent += `\nWorkers: ${item.workers.idle || 0} ready · ${item.workers.busy || 0} busy · ${item.workers.starting || 0} starting / ${item.workers.capacity} · ${item.workers.restarts || 0} restarts`;
      stats.textContent += `\nInstance: ${item.instancing || 'message'}${item.instancing === 'endpoint' ? ' / ' + item.endpoint : ''} · ${item.instances || 0} retained · ${item.state_bytes || 0} B` +
        `\n${item.executing || 0} executing · ${item.waiting || 0} waiting · ${item.rejected || 0} rejected` +
        `\nLast duration: ${item.last_duration_ms ?? '—'} ms · budget ${item.timeout_ms || 1000} ms` +
        (item.suspended ? `\n${item.suspension_reason}` : '');
      const toggle = button(item.enabled ? 'Disable' : item.suspended ? 'Resume (fresh state)' : 'Enable', () => {
        if (!item.enabled && !confirm(`Enable "${item.name}" on live backend traffic?`)) return;
        change({operation: 'enable', id: item.id, enabled: !item.enabled});
      });
      const edit = button('Copy to library', () => {
        const copy = {id: crypto.randomUUID(), name: item.name, source: item.script, revision: 1};
        library.push(copy); persist(); select(copy);
        target.value = item.id; target.onchange();
      });
      const move = delta => {
        stagedOrder = ordered.map(entry => entry.id); stagedRevision = state.revision;
        [stagedOrder[index], stagedOrder[index + delta]] = [stagedOrder[index + delta], stagedOrder[index]];
        renderBackend();
      };
      const up = button('↑', () => move(-1)); up.disabled = index === 0;
      const down = button('↓', () => move(1)); down.disabled = index === ordered.length - 1;
      const remove = button('Remove', () => {
        if (confirm(`Remove "${item.name}" from the backend chain?`)) change({operation: 'remove', id: item.id});
      });
      const output = button('Output', () => {
        const result = item.last_result;
        byId('script-output').textContent = result
          ? [`${item.name} · v${item.version}`, ...(result.logs || []), result.error || ''].join('\n')
          : 'This deployment has not run yet.';
        byId('script-output').scrollIntoView({block: 'nearest'});
      });
      row.append(title, stats, toggle, edit, output, up, down, remove); list.append(row);
    });
    byId('chain-apply-order').hidden = !stagedOrder;
    const collection = state.collection;
    byId('collection-status').textContent = collection
      ? `${collection.saved} samples saved this run · ${collection.bytes.toLocaleString()} / ${collection.limit_bytes.toLocaleString()} bytes\n` +
        `${collection.directory}\n${collection.errors} write failures${collection.last_error ? ': ' + collection.last_error : ''}`
      : 'Collection unavailable on this backend.';
    renderVersion();
  }
  window.addEventListener('inspection-state', event => {
    state = event.detail;
    for (const notice of state.notifications || []) {
      const key = `${baseUrl()}:${notice.id}`;
      if (seenNotifications.has(key)) continue;
      seenNotifications.add(key);
      if (seenNotifications.size > 100) seenNotifications.delete(seenNotifications.values().next().value);
      addActivity('system', 'SCRIPT SUSPENDED', notice.name, notice.reason, 'error');
      byId('chain-message').textContent = `${notice.name}: ${notice.reason}`;
    }
    const collected = (state.traffic_rules?.rules || []).filter(rule => rule.mode === 'collect')
      .map(rule => ({...rule, value: rule.value || rule.address}));
    const old = trafficRules.filter(rule => rule.mode === 'collect');
    if (JSON.stringify(old) !== JSON.stringify(collected)) {
      trafficRules = [...trafficRules.filter(rule => rule.mode !== 'collect'), ...collected];
      renderTrafficRules(); renderEndpointBuilder();
    }
    // Keep keyboard focus stable while operating the chain.
    if (!byId('inspection-tab').hidden && !sidebar.contains(document.activeElement)) renderBackend();
  });
  window.addEventListener('inspection-unavailable', event => {
    state = null;
    byId('chain-connection').textContent = 'Backend unavailable — displayed state is unverified';
    byId('chain-sandbox').hidden = true;
    byId('chain-message').textContent = event.detail;
    renderVersion();
  });
  const collect = button('▣ Toggle Collection', async () => {
    const target = endpointMenuTarget; byId('endpoint-menu').hidden = true;
    if (!target) return;
    if (target.kind === 'cidr') {
      alert('Collection currently supports individual addresses, hostname groups and Sift labels. Select one of these endpoints.');
      return;
    }
    const existing = trafficRules.filter(rule => rule.mode === 'collect' &&
      rule.kind === (target.kind || 'address') && rule.value === target.value);
    const before = trafficRules.slice();
    trafficRules = trafficRules.filter(rule => !existing.includes(rule));
    if (!existing.length) trafficRules.push({id: `collect:${target.kind}:${target.value}`,
      kind: target.kind || 'address', value: target.value, mode: 'collect'});
    try {
      const response = await inspectionRequest('/rules', {bypass_all: bypassAll, rules: expandedTrafficRules()});
      if (response.errors?.length) throw new Error(JSON.stringify(response.errors));
      localStorage.setItem('spider-traffic-rules', JSON.stringify(trafficRules));
      renderTrafficRules(); renderEndpointBuilder(); await refreshBackendInspection();
    } catch (error) {
      trafficRules = before; byId('chain-message').textContent = error.message;
      alert('Collection change failed: ' + error.message);
    }
  });
  byId('endpoint-menu').prepend(collect);
  persist(); select(selected);
})();
