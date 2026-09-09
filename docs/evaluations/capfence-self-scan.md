# CapFence self-scan evaluation

This is a reproducible self-scan of the CapFence checkout, not an independent external-repository evaluation. The repository intentionally contains risky fixtures and demo configurations, so findings are expected and are not claims about a production deployment.

- Target: CapFence checkout
- Scope: repository root at scan time
- Tool: local built `dist/cli.js`
- Evidence: synthetic fixtures only; no secrets included

## Command

```bash
node scripts/evaluate.mjs . --output .capfence/self-evaluation
```

## Interpretation

The report should be reviewed against the current commit before publication. Expected findings include the deliberately dangerous MCP demo and test fixtures. Mark fixture findings as expected test coverage rather than vulnerabilities. Any real public-repository evaluation should follow [`../real-repository-evaluation.md`](../real-repository-evaluation.md), obtain consent where appropriate, pin a commit, and publish only redacted, manually verified results.

## Known limitations

- A self-scan is not an independent accuracy benchmark.
- Static findings do not prove exploitability or runtime behavior.
- Unsupported formats, unresolved data flow, and `analysisLimited` diagnostics must be recorded rather than treated as clean results.
