import { build } from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
await build({ entryPoints: ['src/python.ts'], outfile: 'dist/python.js', bundle: true, platform: 'node', format: 'esm', target: 'node20', sourcemap: true });
const licenses = ['@lezer/python', '@lezer/common', '@lezer/lr', '@lezer/highlight'].map(name => {
  const entry = require.resolve(name, { paths: [path.dirname(require.resolve('@lezer/python'))] });
  return `${name}\n${fs.readFileSync(path.resolve(path.dirname(entry), '../LICENSE'), 'utf8')}`;
});
fs.writeFileSync('dist/PYTHON-PARSER-LICENSES.txt', licenses.join('\n\n'));
