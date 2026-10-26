import {basicSetup} from 'codemirror';
import {EditorState, Prec} from '@codemirror/state';
import {EditorView, keymap, hoverTooltip} from '@codemirror/view';
import {linter} from '@codemirror/lint';
import {indentWithTab} from '@codemirror/commands';
import {python} from '@codemirror/lang-python';
import {indentUnit, syntaxTree, syntaxHighlighting, HighlightStyle} from '@codemirror/language';
import {autocompletion, acceptCompletion} from '@codemirror/autocomplete';
import {tags} from '@lezer/highlight';

const textarea = document.getElementById('script-editor');
const setNativeValue = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
let schema = null, schemaBackend = '', view;
const currentBackend = () => document.getElementById('backend').value.replace(/\/$/, '');
let languageQueue = Promise.resolve();
const languageStatus = document.createElement('small');
languageStatus.className = 'editor-language-status';
languageStatus.textContent = 'Python help: API schema';
textarea.parentElement.after(languageStatus);
function queryLanguage(action, state, pos) {
  const backend = currentBackend(), doc = state.doc;
  // Serialize editor analysis; stale queued requests never reach the backend.
  const job = async () => {
    if (document.hidden || view.dom.closest('.tab-panel')?.hidden || view.state.doc !== doc || currentBackend() !== backend ||
        !window.spiderLanguageRequest) return null;
    const line = doc.lineAt(pos);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    try {
      const result = await window.spiderLanguageRequest({language_action: action,
        script: doc.toString(), line: line.number,
        column: [...doc.sliceString(line.from, pos)].length}, controller.signal);
      if (view.state.doc !== doc || currentBackend() !== backend) return null;
      if (!result.ok) throw new Error(result.error || 'Language service unavailable');
      languageStatus.textContent = 'Python help: backend Jedi · static analysis';
      languageStatus.title = 'Script is analyzed, never executed. Diagnostics cover syntax, not full type checking.';
      return result;
    } catch (error) {
      if (view.state.doc === doc && currentBackend() === backend) {
        languageStatus.textContent = 'Python help: API schema fallback';
        languageStatus.title = error.message;
      }
      return null;
    } finally { clearTimeout(timer); }
  };
  const result = languageQueue.then(job, job);
  languageQueue = result.catch(() => null);
  return result;
}
async function completePython(context) {
  const node = syntaxTree(context.state).resolveInner(context.pos, -1);
  if (/Comment|String/.test(node.name)) return null;
  const direct = completeApi(context);
  if (direct) return direct;
  const word = context.matchBefore(/\w*/);
  if (!context.explicit && !context.matchBefore(/\.\w*$/)) return null;
  const result = await queryLanguage('complete', context.state, context.pos);
  if (!result || context.aborted) return null;
  const kinds = {function: 'function', class: 'class', module: 'namespace', property: 'property'};
  return {from: word?.from ?? context.pos, options: (result.items || []).map(item => ({
    label: item.label, type: kinds[item.type] || 'variable', detail: item.detail, info: item.info,
  })), validFor: /^\w*$/};
}
const pythonHover = hoverTooltip(async (editor, pos) => {
  const state = editor.state;
  const result = await queryLanguage('hover', state, pos);
  if (!result?.items?.length || editor.state.doc !== state.doc) return null;
  return {pos, create() {
    const dom = document.createElement('pre');
    dom.style.cssText = 'white-space:pre-wrap;max-width:480px;max-height:320px;overflow:auto;padding:8px';
    dom.textContent = result.items.map(item => `${item.detail}\n${item.info}`).join('\n\n');
    return {dom};
  }};
}, {hoverTime: 500});
async function signatureHelp(editor) {
  const result = await queryLanguage('signature', editor.state, editor.state.selection.main.head);
  if (result) {
    languageStatus.textContent = result.items?.length
      ? result.items.map(item => `${item.label}${item.index === null ? '' : ` · parameter ${item.index + 1}`}`).join(' | ')
      : 'No function call at cursor';
    languageStatus.title = (result.items || []).map(item => item.info).join('\n\n');
  }
}
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
    const definition = schema.types[type];
    const field = [...(definition?.fields || []), ...(definition?.methods || [])].find(field => field.name === part.replace(/\[\d+\]$/, ''));
    if (!field) return null;
    type = field.type;
    if (/\[\d+\]$/.test(part)) type = /^(?:tuple|list)\[([^,\]]+)/.exec(type)?.[1];
  }
  const definition = schema.types[type];
  if (!definition) return null;
  const fields = [...definition.fields, ...(definition.methods || [])];
  return {
    from: context.pos - prefix.length,
    options: fields.map(field => ({
      label: field.name, type: field.parameters === undefined ? 'property' : 'method',
      detail: field.parameters === undefined ? field.type : `(${field.parameters}) → ${field.type}`,
      info: [field.description, field.availability, field.access,
        field.easy ? `Easy: ${field.easy}` : '', field.expert ? `Expert: ${field.expert}` : '',
        field.example ? `Example:\n${field.example}` : ''].filter(Boolean).join('\n\n'),
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
    Prec.high(keymap.of([{key: 'Tab', run: acceptCompletion},
      {key: 'Mod-Shift-Space', run: editor => { signatureHelp(editor); return true; }}, indentWithTab])),
    autocompletion({override: [completePython], activateOnTyping: true, activateOnTypingDelay: 350}),
    pythonHover,
    linter(async editor => {
      const state = editor.state;
      if (!editor.hasFocus || document.hidden) return [];
      const result = await queryLanguage('diagnostics', state, state.selection.main.head);
      if (!result || editor.state.doc !== state.doc) return [];
      return (result.diagnostics || []).filter(item => item.line >= 1 && item.line <= state.doc.lines).map(item => {
        const line = state.doc.line(item.line);
        const column = [...line.text].slice(0, item.column).join('').length;
        const from = Math.min(line.to, line.from + column);
        return {from, to: Math.min(line.to, from + 1), severity: 'error', message: item.message};
      });
    }, {delay: 900}),
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
help.textContent = 'Ctrl+Space: completion · Ctrl+Shift+Space: parameters · Hover: type/help · Enter / Tab: accept · Ctrl+F: find';
textarea.parentElement.after(help);
window.spiderEditor = {
  setSchema(value, backend) { schema = value; schemaBackend = backend; },
  focus: () => view.focus(),
};
view.contentDOM.addEventListener('focus', () => textarea.dispatchEvent(new Event('focus')));
