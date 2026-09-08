#!/usr/bin/env node
/** Reproducible, local-only evaluation wrapper. Never clones, downloads, or executes target code. */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const targetArg = argv.find(a => !a.startsWith('--')) ?? '.';
const outArg = argv.find((a,i) => a === '--output' ? argv[i+1] : false);
const outBase = outArg ? argv[argv.indexOf('--output') + 1] : path.join(process.cwd(), 'evaluation-report');
const target = path.resolve(targetArg);
if (!fs.existsSync(target)) { console.error(`Target does not exist: ${target}`); process.exit(2); }
const cli = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist/cli.js');
const command = `node ${cli} scan ${target} --format json`;
const run = spawnSync(process.execPath, [cli, 'scan', target, '--format', 'json'], { encoding: 'utf8', windowsHide: true });
if (run.error) { console.error(run.error.message); process.exit(2); }
let result;
try { result = JSON.parse(run.stdout); } catch { console.error(run.stderr || 'CLI did not return JSON'); process.exit(run.status || 2); }
const redact = value => typeof value === 'string' ? value.replaceAll(target, '<TARGET>').replaceAll(process.cwd(), '<WORKSPACE>') : value;
const scrub = value => Array.isArray(value) ? value.map(scrub) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k,v]) => [k, scrub(v)])) : redact(value);
const git = spawnSync('git', ['-C', target, 'rev-parse', 'HEAD'], { encoding:'utf8' });
const report = { command, target: '<TARGET>', gitCommit: git.status === 0 ? git.stdout.trim() : null, counts: { findings: result.findings?.length ?? 0, capabilities: result.capabilities?.length ?? 0, analysisLimited: result.analysisLimited?.length ?? 0 }, findingIds: [...new Set((result.findings ?? []).map(f => f.id))], analysisLimited: result.analysisLimited ?? [], findings: scrub(result.findings ?? []), limitations: ['Local filesystem only; no network access or repository fetching.', 'Static analysis does not prove runtime behavior.', ...(result.analysisLimited?.length ? ['Some files could not be fully analyzed.'] : [])] };
fs.mkdirSync(path.dirname(path.resolve(outBase)), {recursive:true});
const jsonPath = outBase.endsWith('.json') ? outBase : `${outBase}.json`;
const mdPath = outBase.endsWith('.md') ? outBase : `${outBase}.md`;
fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2) + '\n');
const md = `# CapFence local evaluation\n\n- Command: \`${command}\`\n- Git commit: \`${report.gitCommit ?? 'unavailable'}\`\n- Findings: ${report.counts.findings}; capabilities: ${report.counts.capabilities}; analysis limited: ${report.counts.analysisLimited}\n- Finding IDs: ${report.findingIds.join(', ') || 'none'}\n\n## Limitations\n${report.limitations.map(x => `- ${x}`).join('\n')}\n`;
fs.writeFileSync(mdPath, md);
console.log(`Wrote ${jsonPath} and ${mdPath}`);
process.exitCode = run.status === 0 ? 0 : run.status;
