import {basicSetup} from 'codemirror';
import {EditorState, Prec} from '@codemirror/state';
import {EditorView, keymap} from '@codemirror/view';
import {indentWithTab} from '@codemirror/commands';
import {python} from '@codemirror/lang-python';
import {indentUnit, syntaxTree, syntaxHighlighting, HighlightStyle} from '@codemirror/language';
import {autocompletion, acceptCompletion} from '@codemirror/autocomplete';
import {tags} from '@lezer/highlight';

const textarea = document.getElementById('script-editor');
const setNativeValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
let schema = null, schemaBackend = '', view;
const currentBackend = () => document.getElementById('backend').value.replace(/\/$/, '');
function completeApi(context) {
  if (!schema || schemaBackend !== currentBackend()) return null;
  const node = syntaxTree(context.state).resolveInner(context.pos, -1);
  if (/Comment|String/.test(node.name)) return null;
  const match = context.matchBefore(/\bapi(?:\.[A-Za-z_]\w*(?:\[\d+\])?)*\.\w*/);
  if (!match) return null;
  const parts = match.text.split('.');
  const prefix = parts.pop();
  let type = schema.root;
  for (const part of parts.slice(1)) {
    const field = schema.types[type]?.fields.find(field => field.name === part.replace(/\[\d+\]$/, ''));
    if (!field) return null;
    type = field.type;
    if (/\[\d+\]$/.test(part)) type = /^(?:tuple|list)\[([^,\]]+)/.exec(type)?.[1];
  }
  const fields = schema.types[type]?.fields;
  if (!fields) return null;
  return {
    from: context.pos - prefix.length,
    options: fields.map(field => ({
      label: field.name, type: 'property', detail: field.type,
      info: [field.description, field.availability, field.access].filter(Boolean).join('\n\n'),
    })),
    validFor: /^\w*$/,
  };
}
const theme = EditorView.theme({
  '&': {width: '100%', minWidth: '0', color: '#c5d5e6', backgroundColor: '#0e1620', fontSize: 'var(--code-size, 13px)'},
  '.cm-scroller': {fontFamily: 'monospace', overflow: 'auto', lineHeight: '1.55', maxHeight: '70vh'},
  '.cm-content': {minHeight: '50vh', padding: '12px 0', caretColor: '#8ee6b4'},
  '.cm-gutters': {backgroundColor: '#111c27', color: '#60788f', borderRight: '1px solid #263747'},
  '.cm-activeLine, .cm-activeLineGutter': {backgroundColor: '#1a2a3866'},
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': {backgroundColor: '#31516b !important'},
  '.cm-cursor': {borderLeftColor: '#8ee6b4'},
  '.cm-tooltip': {backgroundColor: '#192735', color: '#c5d5e6', border: '1px solid #405a6e'},
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': {backgroundColor: '#244d40', color: '#d6fae8'},
  '.cm-completionInfo': {whiteSpace: 'pre-wrap', maxWidth: '360px'},
  '.cm-search': {backgroundColor: '#192735'},
}, {dark: true});
const colors = HighlightStyle.define([
  {tag: tags.keyword, color: '#c99bed'},
  {tag: [tags.string, tags.special(tags.string)], color: '#9bd3ac'},
  {tag: tags.comment, color: '#748b9c', fontStyle: 'italic'},
  {tag: [tags.number, tags.bool, tags.null], color: '#e4b779'},
  {tag: tags.function(tags.variableName), color: '#86c9ec'},
  {tag: tags.operator, color: '#a6bfd1'},
]);
function state(doc) {
  return EditorState.create({doc, extensions: [
    basicSetup, python(), indentUnit.of('    '), theme, syntaxHighlighting(colors),
    EditorView.lineWrapping,
    Prec.high(keymap.of([{key: 'Tab', run: acceptCompletion}, indentWithTab])),
    autocompletion({override: [completeApi], activateOnTyping: true, activateOnTypingDelay: 250}),
    EditorView.contentAttributes.of({'aria-label': 'Inspection script editor', spellcheck: 'false'}),
    EditorView.updateListener.of(update => {
      if (update.docChanged) {
        setNativeValue.call(textarea, update.state.doc.toString());
        textarea.dispatchEvent(new Event('input', {bubbles: true}));
      }
    }),
  ]});
}
view = new EditorView({state: state(textarea.value), parent: textarea.parentElement});
// Compatibility bridge: existing save/deploy/run paths keep one source of truth.
// No Python runtime is loaded into the browser.
Object.defineProperties(textarea, {
  value: {
    get: () => view.state.doc.toString(),
    set: value => {
      setNativeValue.call(textarea, String(value));
      if (String(value) !== view.state.doc.toString()) view.setState(state(String(value)));
    },
  },
  selectionStart: {get: () => view.state.selection.main.from},
  selectionEnd: {get: () => view.state.selection.main.to},
});
textarea.setRangeText = (text, from, to) => view.dispatch({
  changes: {from, to, insert: text}, selection: {anchor: from + text.length},
});
textarea.focus = () => view.focus();
textarea.hidden = true;
const help = document.createElement('small');
help.className = 'editor-shortcuts';
help.textContent = 'Ctrl+Space: API · Enter / Tab: accept suggestion · Tab / Shift+Tab: indent · Ctrl+F: find · Esc then Tab: leave editor';
textarea.parentElement.after(help);
window.spiderEditor = {
  setSchema(value, backend) { schema = value; schemaBackend = backend; },
  focus: () => view.focus(),
};
view.contentDOM.addEventListener('focus', () => textarea.dispatchEvent(new Event('focus')));
