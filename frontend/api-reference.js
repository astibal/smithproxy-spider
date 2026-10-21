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
  const editor = document.getElementById('script-editor');
  let schema = null, schemaBackend = '', loading = false;
  function renderReference() {
    const target = document.getElementById('api-reference-content');
    target.replaceChildren();
    if (!schema) return;
    const query = document.getElementById('api-search').value.toLowerCase();
    for (const [type, definition] of Object.entries(schema.types)) {
      const matching = [...definition.fields, ...(definition.methods || [])].filter(f =>
        (type + ' ' + f.name + ' ' + f.description).toLowerCase().includes(query));
      if (!matching.length) continue;
      const section = document.createElement('section');
      const heading = document.createElement('h3'); heading.textContent = type;
      const description = document.createElement('p'); description.textContent = definition.description;
      section.append(heading, description);
      for (const field of matching) {
        const row = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = field.name + (field.parameters !== undefined ? '(' + field.parameters + ')' : '') + ': ' + field.type;
        const desc = document.createElement('p');
        desc.textContent = field.description + ' ' + field.availability + ' Access: ' + field.access + '.';
        const example = document.createElement('pre'); example.textContent = field.example;
        const insert = document.createElement('button'); insert.textContent = 'Insert example into editor';
        insert.onclick = () => {
          const at = editor.selectionStart;
          editor.setRangeText(field.example + '\n', at, editor.selectionEnd, 'end');
          editor.dispatchEvent(new Event('input', {bubbles: true}));
          showTab('inspection-tab'); editor.focus();
        };
        row.append(summary, desc, example, insert); section.append(row);
      }
      target.append(section);
    }
  }
  async function load() {
    const address = baseUrl();
    if (loading) return;
    if (schemaBackend !== address) { schema = null; window.spiderEditor?.setSchema(null, address); }
    loading = true;
    try {
      const response = await fetch(address + '/api/inspection/schema', {headers: headers()});
      if (!response.ok) throw new Error('API schema HTTP ' + response.status);
      const result = await response.json();
      if (baseUrl() !== address) return;
      schema = result; schemaBackend = address;
      window.spiderEditor?.setSchema(schema, address);
      document.getElementById('api-reference-state').textContent =
        'API ' + schema.version + ' · generated from backend Python definitions. Typed preview; existing flat helpers remain available.';
      renderReference();
    } catch (error) {
      schema = null; window.spiderEditor?.setSchema(null, address); renderReference();
      document.getElementById('api-reference-state').textContent = error.message;
    } finally { loading = false; }
  }
  tabButton.onclick = () => { showTab(panel.id); load(); };
  document.getElementById('api-search').oninput = renderReference;
  document.getElementById('connect').addEventListener('click', load);
  editor.addEventListener('focus', () => { if (!schema || schemaBackend !== baseUrl()) load(); });
  load();
})();
