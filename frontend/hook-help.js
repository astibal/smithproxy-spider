/* Addon help is separate from the native api.* schema and completion. */
(() => {
  const editor = document.getElementById('script-editor');
  const help = document.createElement('details');
  const heading = document.createElement('summary');
  heading.textContent = 'Addon hook examples and deployment requirements';
  help.append(heading);

  const note = document.createElement('p');
  note.textContent = 'These are complete mitmproxy addon scripts. Copy one into a new script. ' +
    'TLS/QUIC start subscriptions must currently be set through the deployment API; ' +
    'defining a callback alone does not enable them. Live SSL objects and certificate replacement are unsupported.';
  help.append(note);

  // Show complete sources without overwriting an unsaved editor draft.
  for (const example of window.spiderHookExamples || []) {
    const item = document.createElement('details');
    const title = document.createElement('summary');
    title.textContent = example.title;
    const deployment = document.createElement('p');
    deployment.textContent = 'Deployment: ' + example.deployment;
    const source = document.createElement('pre');
    source.textContent = example.source;
    item.append(title, deployment, source);
    help.append(item);
  }

  editor.closest('.editor-frame').before(help);
})();
