/* The local library and the backend chain deliberately have separate lifecycles. */
(() => {
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
    '<button id="library-deploy">Deploy saved version…</button>';
  document.querySelector('.workbench-script .editor-frame').before(toolbar);

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
      scope: byId('chain-scope').value, filter: byId('chain-filter').value});
  };
  byId('chain-target').onchange = () => {
    const target = state?.chain?.find(item => item.id === byId('chain-target').value);
    if (target) { byId('chain-scope').value = target.scope; byId('chain-filter').value = target.filter; }
    renderVersion();
  };
  byId('chain-apply-order').onclick = () => change({operation: 'reorder', ids: stagedOrder}, stagedRevision);
  function renderBackend() {
    const chain = state.chain || [];
    const active = chain.filter(item => item.enabled).length;
    byId('chain-connection').textContent = `${baseUrl()} · ${active} enabled · ${state.running} executing`;
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
      title.textContent = `${index + 1}. ${item.enabled ? '●' : '○'} ${item.name} · v${item.version}`;
      const stats = document.createElement('small');
      stats.textContent = `${item.enabled ? 'Enabled' : 'Disabled'} · ${item.runs} runs · ${item.errors} errors\n` +
        `Traffic: ${item.scope} ${item.filter || ''}\nLast run: ${item.last_run_ms ? new Date(item.last_run_ms).toLocaleString() : 'never'}`;
      const toggle = button(item.enabled ? 'Disable' : 'Enable', () => {
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
    const collected = (state.traffic_rules?.rules || []).filter(rule => rule.mode === 'collect')
      .map(rule => ({...rule, value: rule.value || rule.address}));
    const old = trafficRules.filter(rule => rule.mode === 'collect');
    if (JSON.stringify(old) !== JSON.stringify(collected)) {
      trafficRules = [...trafficRules.filter(rule => rule.mode !== 'collect'), ...collected];
      renderTrafficRules(); renderEndpointBuilder();
    }
    // Keep keyboard focus stable while operating the chain.
    if (!sidebar.contains(document.activeElement)) renderBackend();
  });
  window.addEventListener('inspection-unavailable', event => {
    state = null;
    byId('chain-connection').textContent = 'Backend unavailable — displayed state is unverified';
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
