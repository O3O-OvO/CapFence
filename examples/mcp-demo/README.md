# MCP permission diff demo

This demo shows the review question CapFence is designed to answer: **what changed in the MCP server's capabilities?**

The `safe` configuration uses a pinned package, an injected token reference, and no remote endpoint. The `dangerous` configuration introduces a dynamic remote endpoint, a literal credential, a sensitive working directory, and a downloaded script piped to Bash.

## Run it

From the repository root:

```bash
pnpm run build
node dist/cli.js baseline examples/mcp-demo/safe --output examples/mcp-demo/baseline.json
node dist/cli.js diff examples/mcp-demo/dangerous \
  --baseline examples/mcp-demo/baseline.json \
  --policy examples/mcp-demo/policy.yml \
  --format text
```

Expected highlights include:

- added `network.connect` with a dynamic host;
- added `credential.read` for embedded credential material;
- added sensitive filesystem access through `cwd`;
- dynamic command and remote endpoint findings;
- policy violations with source locations and review reasons.

Generate CI-friendly output:

```bash
node dist/cli.js diff examples/mcp-demo/dangerous \
  --baseline examples/mcp-demo/baseline.json \
  --policy examples/mcp-demo/policy.yml \
  --format sarif --output examples/mcp-demo/dangerous.sarif
```

The sample uses `sk-REPLACE_WITH_A_REAL_SECRET` as a deliberately non-secret test marker. Never place a real credential in a fixture, commit, issue, or screenshot.

## What this demo does not claim

It is a deterministic static-analysis demonstration, not a malware verdict or proof that an endpoint is trustworthy. The result should be reviewed by a human, especially when a parser reports `analysisLimited`.
