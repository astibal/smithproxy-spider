/* One backend capture library: samples and flows differ in size, not navigation. */
async function captureLibrarySaveDialog(name) {
  const dialog = document.createElement('dialog'); dialog.className = 'capture-save';
  dialog.innerHTML = '<form><h2>Save to library</h2><label>Name<input name="name" required maxlength="200"></label>' +
    '<label>Folder<select name="folder"><option value="">Unfiled</option></select></label>' +
    '<label>Notes<textarea name="notes" maxlength="2000" rows="3"></textarea></label>' +
    '<p role="status"></p><footer><button type="button" data-cancel>Cancel</button><button type="submit" disabled>Save snapshot</button></footer></form>';
  document.body.append(dialog); dialog.querySelector('[name=name]').value = name;
  dialog.setAttribute('aria-label', 'Save capture to library');
  dialog.querySelector('[role=status]').textContent = 'Loading folders…';
  dialog.showModal();
  return new Promise(resolve => {
    const finish = value => { dialog.close(); dialog.remove(); resolve(value); };
    dialog.querySelector('[data-cancel]').onclick = () => finish(null);
    dialog.oncancel = event => { event.preventDefault(); finish(null); };
    dialog.querySelector('form').onsubmit = event => {
      event.preventDefault();
      const values = Object.fromEntries(new FormData(event.target));
      values.name = values.name.trim(); if (values.name) finish(values);
    };
    inspectionRequest('/library').then(result => {
      if (!dialog.isConnected) return;
      if (!Array.isArray(result.folders)) throw new Error('Capture library requires an updated backend.');
      for (const folder of result.folders) dialog.querySelector('[name=folder]').add(new Option(folder.name, folder.id));
      dialog.querySelector('[type=submit]').disabled = false;
      dialog.querySelector('[role=status]').textContent = '';
    }).catch(error => { if (dialog.isConnected) dialog.querySelector('[role=status]').textContent = error.message; });
  });
}

async function openCaptureLibrary() {
  if (document.querySelector('.capture-library')) return;
  const backend = baseUrl(), stateKey = 'spider-capture-library:' + backend;
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(stateKey)) || {}; } catch (_) {}
  let folder = typeof saved.folder === 'string' ? saved.folder : '*';
  let query = typeof saved.query === 'string' ? saved.query : '';
  let offset = Number.isSafeInteger(saved.offset) && saved.offset >= 0 ? saved.offset : 0;
  let selectedKey = saved.selected || '', selected = null, data = null, next = null, revision = null;
  let folders = [], generation = 0, selecting = 0, dirty = false, mutating = false, opening = false, loaded = null;
  const dialog = document.createElement('dialog'); dialog.className = 'capture-library';
  dialog.setAttribute('aria-label', 'Capture Library');
  dialog.innerHTML = '<header><h2>Capture Library</h2><button data-close class="secondary">Close</button></header>' +
    '<form class="capture-search"><input data-search aria-label="Search captures" placeholder="Name, notes, endpoint, HTTP path, status…"><button>Search</button><button data-refresh type="button" class="secondary">Refresh</button><button data-live type="button" class="secondary">Live traffic</button></form>' +
    '<div class="capture-browser"><nav aria-label="Capture folders"><div data-folders></div><button data-new-folder class="secondary">+ Folder</button><button data-rename-folder class="secondary" disabled>Rename folder</button>' +
    '<form data-folder-form hidden><label>Folder name<input data-folder-name required maxlength="50"></label><button>Save folder</button><button type="button" data-folder-cancel class="secondary">Cancel</button></form></nav>' +
    '<section class="capture-results"><div class="capture-columns"><span>Capture / endpoint</span><span>Size · time</span></div><div data-list role="list" aria-label="Captures"></div><footer><button data-prev class="secondary">Previous</button><span data-count></span><button data-next class="secondary">Next</button></footer></section>' +
    '<section class="capture-detail"><p data-empty>Select a capture to see its details.</p><div data-detail hidden>' +
    '<label>Name<input data-name maxlength="200"></label><label>Folder<select data-folder></select></label><label>Notes<textarea data-notes rows="4" maxlength="2000" placeholder="What is interesting about this capture?"></textarea></label>' +
    '<button data-save class="secondary" disabled>Save details</button><p data-summary></p><pre data-preview></pre>' +
    '<label data-message-label hidden>Message for Inspection<select data-message></select></label>' +
    '<footer><button data-open>Open in Follow</button><button data-use>Use in Inspection</button></footer></div></section></div><p data-status role="status"></p>';
  const el = selector => dialog.querySelector(selector);
  document.body.append(dialog); el('[data-search]').value = query;
  const remember = () => {
    try { localStorage.setItem(stateKey, JSON.stringify({folder, query, offset, selected: selectedKey, scroll: el('[data-list]').scrollTop})); } catch (_) {}
  };
  const discard = () => !dirty || confirm('Discard unsaved capture details?');
  const close = () => { if (mutating || opening || !discard()) return; remember(); ++generation; ++selecting; dialog.close(); dialog.remove(); };
  el('[data-close]').onclick = close;
  dialog.oncancel = event => { event.preventDefault(); close(); };
  el('[data-live]').onclick = () => { if (!discard()) return; dirty = false; close(); showTab('workbench-tab'); };
  const status = text => { el('[data-status]').textContent = text; };
  function showFolders() {
    const nav = el('[data-folders]'); nav.replaceChildren();
    for (const item of [{id: '*', name: 'All captures'}, {id: '', name: 'Unfiled'}, ...folders]) {
      const button = document.createElement('button'); button.className = 'capture-folder'; button.textContent = item.name;
      button.setAttribute('aria-pressed', String(item.id === folder));
      button.onclick = () => { if (!discard()) return; dirty = false; folder = item.id; offset = 0; selectedKey = ''; load(); };
      nav.append(button);
    }
    el('[data-rename-folder]').disabled = !folder || folder === '*';
    const select = el('[data-folder]'); select.replaceChildren(new Option('Unfiled', ''));
    for (const item of folders) select.add(new Option(item.name, item.id));
  }
  function select(item) {
    ++selecting; selected = item; selectedKey = item.key; loaded = null; dirty = false;
    el('[data-empty]').hidden = true; el('[data-detail]').hidden = false;
    el('[data-name]').value = item.name; el('[data-folder]').value = item.folder || ''; el('[data-notes]').value = item.notes || '';
    el('[data-save]').disabled = true;
    el('[data-open]').disabled = el('[data-use]').disabled = !!item.error;
    el('[data-use]').textContent = item.kind === 'flow' ? 'Choose message for Inspection…' : 'Use in Inspection';
    el('[data-message-label]').hidden = true;
    el('[data-summary]').textContent = [item.kind === 'flow' ? 'Flow' : 'Sample', `${item.records} message(s)`,
      formatBytes(item.bytes || 0), item.time_ms ? new Date(item.time_ms).toLocaleString() : '', item.error].filter(Boolean).join(' · ');
    el('[data-preview]').textContent = [
      item.authority && `Host: ${item.authority}`, item.endpoint && `Collected endpoint: ${item.endpoint}`,
      (item.description || item.session || item.session_id) && `Connection: ${item.description || item.session || item.session_id}`,
      item.protocols?.length && `Protocols: ${item.protocols.join(', ')}`,
      item.content_types?.length && `Content: ${item.content_types.join(', ')}`,
      item.encodings?.length && `Encoding: ${item.encodings.join(', ')}`,
      item.operations?.length && `Enrichment: ${item.operations.join(', ')}`,
      item.stream_ids?.length && `H2 streams: ${item.stream_ids.join(', ')}`,
      `Capture ID: ${item.id}`,
    ].filter(Boolean).join('\n').slice(0, 12000);
    for (const button of el('[data-list]').querySelectorAll('button')) button.setAttribute('aria-pressed', String(button.dataset.key === item.key));
    remember();
  }
  for (const field of ['name', 'folder', 'notes']) el(`[data-${field}]`).oninput = () => { dirty = true; el('[data-save]').disabled = false; };
  async function load(restore = false) {
    const token = ++generation; ++selecting; selected = null; loaded = null;
    el('[data-detail]').hidden = true; el('[data-empty]').hidden = false;
    el('[data-list]').replaceChildren(); el('[data-prev]').disabled = el('[data-next]').disabled = true;
    status('Loading capture index…');
    try {
      const result = await inspectionRequest(`/library?offset=${offset}&q=${encodeURIComponent(query)}&folder=${encodeURIComponent(folder)}`);
      if (token !== generation || !dialog.isConnected) return;
      if (!Array.isArray(result.items) || !Array.isArray(result.folders)) throw new Error('Capture library requires an updated backend.');
      data = result; revision = result.revision; folders = result.folders; next = result.next;
      if (folder && folder !== '*' && !folders.some(item => item.id === folder)) { folder = '*'; offset = 0; return load(); }
      if (!result.items.length && offset > 0) { offset = 0; return load(); }
      showFolders();
      el('[data-count]').textContent = `${result.total} capture(s)`;
      el('[data-prev]').disabled = offset === 0; el('[data-next]').disabled = next === null;
      const list = el('[data-list]');
      for (const item of result.items) {
        const row = document.createElement('button'); row.className = 'capture-row'; row.dataset.key = item.key;
        row.setAttribute('aria-pressed', 'false');
        const description = document.createElement('span'), title = document.createElement('strong'), detail = document.createElement('small'), metrics = document.createElement('small');
        title.textContent = item.name;
        detail.textContent = [item.kind === 'flow' ? `Flow · ${item.records} messages` : 'Sample', item.authority || item.description || item.endpoint, item.notes].filter(Boolean).join(' · ');
        metrics.textContent = `${formatBytes(item.bytes || 0)} · ${item.time_ms ? new Date(item.time_ms).toLocaleDateString() : '—'}`;
        description.append(title, detail); row.append(description, metrics);
        row.onclick = () => { if (discard()) select(item); }; list.append(row);
      }
      if (!result.items.length) list.textContent = 'No captures here. Try another folder or search.';
      const previous = result.items.find(item => item.key === selectedKey); if (previous) select(previous);
      if (restore) list.scrollTop = saved.scroll || 0;
      status(result.warning || 'Select a capture. Payloads load only when opened or used.'); remember();
    } catch (error) { if (token === generation) status(error.message); }
  }
  async function mutate(request) {
    if (mutating || revision === null) return false;
    mutating = true; status('Saving…');
    el('.capture-browser').inert = el('.capture-search').inert = true;
    try {
      const result = await inspectionRequest('/library', {...request, revision});
      revision = result.revision; return true;
    } catch (error) { status(error.message + ' Your edits remain here; refresh to reload backend state.'); return false; }
    finally { mutating = false; el('.capture-browser').inert = el('.capture-search').inert = false; }
  }
  el('[data-save]').onclick = async () => {
    if (!selected) return;
    const request = {operation: 'item', key: selected.key, name: el('[data-name]').value.trim(), folder: el('[data-folder]').value, notes: el('[data-notes]').value};
    if (!request.name) { status('A name is required.'); return; }
    if (await mutate(request)) {
      const id = selected.kind === 'sample' ? 'sample:' + selected.id : selected.id;
      for (const flow of followedFlows.values()) if (flow.savedId === id) {
        flow.title = request.name;
        const title = document.querySelector(`[data-tab="${flow.id}"] span`); if (title) title.textContent = request.name;
        const heading = byId(flow.id)?.querySelector('.flow-follow-head h2'); if (heading) heading.textContent = request.name;
      }
      saveFollowTabs(); dirty = false; await load();
    }
  };
  let editingFolder = '';
  function editFolder(rename) {
    if (!discard()) return;
    editingFolder = rename ? folder : '';
    el('[data-folder-form]').hidden = false;
    el('[data-folder-name]').value = rename ? folders.find(item => item.id === folder)?.name || '' : '';
    el('[data-folder-name]').focus();
  }
  el('[data-folder-cancel]').onclick = () => { el('[data-folder-form]').hidden = true; };
  el('[data-folder-form]').onsubmit = async event => {
    event.preventDefault();
    const name = el('[data-folder-name]').value.trim();
    if (!name) return;
    if (await mutate({operation: 'folder', name, ...(editingFolder ? {id: editingFolder} : {})})) {
      el('[data-folder-form]').hidden = true; dirty = false; await load();
    }
  };
  el('[data-new-folder]').onclick = () => editFolder(false);
  el('[data-rename-folder]').onclick = () => editFolder(true);
  el('.capture-search').onsubmit = event => { event.preventDefault(); if (!discard()) return; dirty = false; query = el('[data-search]').value.trim(); offset = 0; load(); };
  el('[data-refresh]').onclick = () => { if (discard()) { dirty = false; load(); } };
  el('[data-prev]').onclick = () => { if (discard()) { dirty = false; offset = Math.max(0, offset - 100); load(); } };
  el('[data-next]').onclick = () => { if (next !== null && discard()) { dirty = false; offset = next; load(); } };
  el('[data-open]').onclick = async () => {
    if (!selected || !discard()) return;
    const token = ++selecting, item = selected;
    opening = true; el('[data-close]').disabled = true;
    el('.capture-browser').inert = el('.capture-search').inert = true;
    el('[data-open]').disabled = true; status('Opening capture…');
    try {
      await openSavedFlow(item.kind === 'sample' ? 'sample:' + item.id : item.id);
      if (token === selecting && dialog.isConnected) { opening = false; dirty = false; close(); }
    } catch (error) { if (token === selecting) { status(error.message); el('[data-open]').disabled = false; } }
    finally { opening = false; el('[data-close]').disabled = false; el('.capture-browser').inert = el('.capture-search').inert = false; }
  };
  el('[data-use]').onclick = async () => {
    if (!selected || !discard()) return;
    const token = ++selecting, item = selected;
    el('[data-use]').disabled = true;
    try {
      if (!loaded) {
        status('Loading capture for Inspection…');
        const snapshot = await inspectionRequest(item.kind === 'sample' ? `/sample?id=${encodeURIComponent(item.id)}` : `/saved-flow?id=${encodeURIComponent(item.id)}`);
        if (token !== selecting || !dialog.isConnected) return;
        loaded = item.kind === 'sample' ? [{event: snapshot.event, session_context: snapshot.session_context, enrichments: snapshot.enrichments}] : snapshot.records;
        if (!Array.isArray(loaded) || !loaded.length) throw new Error('Capture contains no messages.');
        if (item.kind === 'flow') {
          const picker = el('[data-message]'); picker.replaceChildren(new Option('Select a message explicitly…', ''));
          loaded.forEach((record, i) => {
            const info = record.event?.details?.info || {};
            picker.add(new Option(`${i + 1}. ${info.side || '?'} · ${decodedPayloadSize(info.content)} B · ${info.session || record.event?.id || ''}`, String(i)));
          });
          el('[data-message-label]').hidden = false; el('[data-use]').textContent = 'Use selected message';
          status('Choose which message to use. Nothing has been sent to the script.'); return;
        }
      }
      const index = item.kind === 'sample' ? 0 : el('[data-message]').value;
      if (index === '') return;
      const record = loaded[Number(index)];
      selectPayload({event: record.event, revision: 'library:' + item.key + ':' + index, decided: true, collectedSample: true,
        sessionContext: record.session_context, enrichments: (record.enrichments || []).map(e => ({metadata: e.metadata, payload: decodeBase64(e.content || '')}))}, false);
      dirty = false; close(); showTab('inspection-tab');
    } catch (error) { if (token === selecting) { status(error.message); el('[data-use]').disabled = false; loaded = null; } }
  };
  el('[data-message]').onchange = () => { el('[data-use]').disabled = el('[data-message]').value === ''; };
  dialog.showModal(); await load(true);
}
openSamplePicker = openCaptureLibrary;
openSavedFlows = openCaptureLibrary;
byId('inspection-select-input').textContent = 'Choose input…';
byId('inspection-select-input').onclick = openCaptureLibrary;
byId('open-saved-sessions').textContent = 'Capture Library';
byId('open-saved-sessions').onclick = openCaptureLibrary;
// A stable entry in the Payloads heading, not among per-payload actions.
document.querySelector('#workbench-tab .inspection-title .font-controls').prepend(byId('open-saved-sessions'));
