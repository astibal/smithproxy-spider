import {build} from 'esbuild';
import {readFile, readdir, writeFile} from 'node:fs/promises';
await build({
  entryPoints: ['editor.js'], bundle: true, minify: true, format: 'iife',
  target: 'es2020', outfile: '../../frontend/vendor/inspection-editor.js', legalComments: 'linked',
});
const notices = [];
async function licenses(path) {
  for (const entry of await readdir(path, {withFileTypes: true})) {
    if (!entry.isDirectory()) continue;
    const directory = `${path}/${entry.name}`;
    if (entry.name.startsWith('@')) { await licenses(directory); continue; }
    const files = await readdir(directory);
    const license = files.find(name => /^licen[sc]e(?:\.txt|\.md)?$/i.test(name));
    if (!license) continue;
    const pkg = JSON.parse(await readFile(`${directory}/package.json`, 'utf8'));
    notices.push(`${pkg.name} ${pkg.version}\n${await readFile(`${directory}/${license}`, 'utf8')}`);
  }
}
await licenses('node_modules');
await writeFile('../../frontend/vendor/editor-LICENSES.txt', notices.join('\n\n---\n\n'));
