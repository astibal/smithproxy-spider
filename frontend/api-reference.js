/* Runtime schema is shared by reference, examples and editor completion. */
(() => {
  const tabButton = document.createElement('button');
  tabButton.type = 'button';
  tabButton.dataset.tab = 'api-reference-tab';
  tabButton.textContent = 'API Reference';
  document.querySelector('.tabs').append(tabButton);
  const panel = document.createElement('div');
  panel.id = 'api-reference-tab';
  panel.className = 'tab-panel';
  panel.hidden = true;
  panel.innerHTML = '<h2>Inspector API Reference</h2><p id="api-reference-state">Connect to a backend to load its API.</p><input id="api-search" aria-label="Search API" placeholder="Search fields and descriptions"><div id="api-reference-content"></div>';
  document.querySelector('.workspace').append(panel);
  const completion = document.createElement('div');
  completion.className = 'api-completion';
  completion.hidden = true;
  completion.setAttribute('aria-label', 'API suggestions');
  document.querySelector('.editor-frame').after(completion);
  const editor = document.getElementById('script-editor');
  let schema = null, schemaBackend = '', loading = false;
  let candidates = [], cursor = 0, prefix = '';
  const items = () => {
    const rows = [];
    function walk(type, path, depth) {
      if (depth > 4) return;
      for (const field of schema.types[type]?.fields || []) {
        const name = path + '.' + field.name;
        rows.push({...field, path: name, owner: type});
        if (schema.types[field.type]) walk(field.type, name, depth + 1);
      }
    }
    walk(schema.root, 'api', 0);
    return rows;
  };
  function renderReference() {
    const target = document.getElementById('api-reference-content');
    target.replaceChildren();
    if (!schema) return;
    const query = document.getElementById('api-search').value.toLowerCase();
    for (const [type, definition] of Object.entries(schema.types)) {
      const matching = definition.fields.filter(f =>
        (type + ' ' + f.name + ' ' + f.description).toLowerCase().includes(query));
      if (!matching.length) continue;
      const section = document.createElement('section');
      const heading = document.createElement('h3'); heading.textContent = type;
      const description = document.createElement('p'); description.textContent = definition.description;
      section.append(heading, description);
      for (const field of matching) {
        const row = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = field.name + ': ' + field.type;
        const desc = document.createElement('p');
        desc.textContent = field.description + ' ' + field.availability + ' Access: ' + field.access + '.';
        const example = document.createElement('pre'); example.textContent = field.example;
        const insert = document.createElement('button'); insert.textContent = 'Insert example into editor';
        insert.onclick = () => {
          const at = editor.selectionStart;
          editor.setRangeText(field.example + '\n', at, editor.selectionEnd, 'end');
          editor.dispatchEvent(new Event('input', {bubbles: true}));
          showTab('workbench-tab'); editor.focus();
        };
        row.append(summary, desc, example, insert); section.append(row);
      }
      target.append(section);
    }
  }
  async function load() {
    const address = baseUrl();
    if (loading) return;
    if (schemaBackend !== address) { schema = null; completion.hidden = true; }
    loading = true;
    try {
      const response = await fetch(address + '/api/inspection/schema', {headers: headers()});
      if (!response.ok) throw new Error('API schema HTTP ' + response.status);
      const result = await response.json();
      if (baseUrl() !== address) return;
      schema = result; schemaBackend = address;
      document.getElementById('api-reference-state').textContent =
        'API ' + schema.version + ' · generated from backend Python definitions. Typed preview; existing flat helpers remain available.';
      renderReference();
    } catch (error) {
      schema = null; completion.hidden = true; renderReference();
      document.getElementById('api-reference-state').textContent = error.message;
    } finally { loading = false; }
  }
  function choose(index) {
    const item = candidates[index];
    if (!item || !editor.value.slice(0, editor.selectionStart).endsWith(prefix)) {
      completion.hidden = true; return;
    }
    editor.setRangeText(item.path.slice(prefix.length), editor.selectionStart, editor.selectionEnd, 'end');
    editor.dispatchEvent(new Event('input', {bubbles: true}));
    completion.hidden = true; editor.focus();
  }
  function suggest() {
    completion.replaceChildren();
    const match = editor.value.slice(0, editor.selectionStart).match(/\bapi(?:\.[A-Za-z_][A-Za-z_0-9]*)*\.[A-Za-z_0-9]*$/);
    if (!schema || schemaBackend !== baseUrl() || !match) { completion.hidden = true; return; }
    prefix = match[0]; cursor = 0;
    candidates = items().filter(item => item.path !== prefix && item.path.startsWith(prefix) &&
      !item.path.slice(prefix.lastIndexOf('.') + 1).includes('.'));
    completion.hidden = !candidates.length;
    candidates.forEach((item, index) => {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = item.path + ': ' + item.type;
      button.title = item.description + ' ' + item.availability;
      button.onclick = () => choose(index);
      button.classList.toggle('selected', index === cursor);
      completion.append(button);
    });
  }
  let debounce;
  editor.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(suggest, 250); });
  editor.addEventListener('keydown', event => {
    if (event.ctrlKey && event.code === 'Space') { event.preventDefault(); suggest(); return; }
    if (event.key === 'Escape') { clearTimeout(debounce); completion.hidden = true; return; }
    if (completion.hidden || !['ArrowDown', 'ArrowUp', 'Tab'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Tab') { choose(cursor); return; }
    cursor = (cursor + (event.key === 'ArrowDown' ? 1 : -1) + candidates.length) % candidates.length;
    [...completion.children].forEach((child, i) => child.classList.toggle('selected', i === cursor));
  });
  tabButton.onclick = () => { showTab(panel.id); load(); };
  document.getElementById('api-search').oninput = renderReference;
  document.getElementById('connect').addEventListener('click', load);
  editor.addEventListener('focus', () => { if (!schema || schemaBackend !== baseUrl()) load(); });
  load();
})();
