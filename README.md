# CapFence

[English](README.md) | [简体中文](README.zh-CN.md)

Capability-diff security for AI agent skills and MCP servers.

CapFence statically inspects a repository and answers a practical review question: **what can this agent, skill, server, or build hook do, and did that capability change?** It never executes commands from the scanned tree.

The first release is intentionally small and deterministic. It extracts a capability manifest, reports high-signal risky patterns with source locations, and compares the result with a checked-in baseline so a pull request can be reviewed as a permission diff.

## What it detects

| Capability | Examples |
| --- | --- |
| `process.execute` | shell launchers, child-process APIs, elevated commands |
| `filesystem.read` | sensitive paths, external working directories, environment files |
| `filesystem.write` | downloaded artifacts written before execution |
| `network.connect` | MCP URLs, runtime fetches, downloaded scripts |
| `credential.read` | injected secret environment variables, literal tokens |
| `dynamic.execute` | `eval`, templated shell input, encoded commands |
| `package.lifecycle` | `npx`/`uvx` runtime package resolution, npm lifecycle hooks |

Findings are separate from capabilities. A normal `npx package@1.2.3` launch is recorded as a capability; an unpinned package, downloaded script piped to a shell, embedded token, remote plain-HTTP MCP endpoint, or privilege escalation also receives a finding.

Current deterministic finding rules include:

- `CF-EXEC-001`: dynamic process or interpreter input
- `CF-EXEC-002`: remote content piped directly to an interpreter
- `CF-EXEC-003`: downloaded file later executed
- `CF-DYN-001`: decoded or encoded content executed
- `CF-CRED-001`: sensitive file combined with an outbound upload
- `CF-CRED-002`: credential material embedded in active content or MCP configuration
- `CF-PKG-001`: unpinned runtime package execution
- `CF-PRIV-001`: elevated process or weakened container privilege boundary
- `CF-MCP-001`: dynamic MCP command, dynamic endpoint, or remote plain HTTP

## Install and run

Requires Node.js 20 or newer.

```bash
corepack enable
pnpm install
pnpm run build

# Scan a skill, MCP configuration, or repository
node dist/cli.js scan .

# Machine-readable output
node dist/cli.js scan . --format json
node dist/cli.js scan . --format sarif --output capfence.sarif

# GitHub workflow annotations
node dist/cli.js scan . --format github
```

The npm package has not been published yet. Use the local built CLI above; after npm publication, the same commands can be shortened to `npx capfence`.

```bash
node dist/cli.js scan path/to/project --format text
```

Supported input files are Markdown skill/instruction files, JSON/JSONC, YAML, JavaScript/TypeScript, Python, shell/PowerShell/Command scripts, `package.json`, and Dockerfiles. Markdown is only inspected inside explicitly labelled shell or PowerShell fences. Files over 2 MiB and common dependency/build directories are skipped. TOML and `.env` files are intentionally not claimed as supported until they have a structured, location-aware analyzer.

## Capability baselines

Create a reviewable baseline and commit it with the repository:

```bash
node dist/cli.js baseline . --output capfence.baseline.json
```

Compare future changes:

```bash
node dist/cli.js diff . --baseline capfence.baseline.json
```

Capability identity is the normalized `kind + scope`, not the source location. Moving the same launcher does not create a permission change. A new host is shown as `added` and the old host as `removed`; a static host becoming `dynamic` is shown as `widened`. By default, `diff` and any scan supplied with `--baseline` fail when capabilities are added or widened. Use `--allow-changes` when a workflow wants reporting without blocking.

Baselines also retain stable finding identities. With `--fail-on`, findings already present in a baseline do not fail a later scan unless `--fail-existing` is supplied.

## Policy

Use a small YAML policy to deny capabilities introduced by a change and to restrict network hosts:

```yaml
deny:
  - capability: dynamic.execute
    severity: critical
    reason: Dynamic execution requires explicit review.
  - capability: filesystem.read
    scope: sensitive-path
    severity: high
network:
  allow:
    - api.github.com
    - example.com
```

Evaluate it with a baseline:

```bash
node dist/cli.js diff . \
  --baseline capfence.baseline.json \
  --policy examples/policy.yml \
  --format github \
  --fail-on high
```

Policy checks apply to `added` and `widened` capabilities. Removed capabilities are included in the diff but cannot create a policy violation.

## GitHub Actions

CapFence ships as a reusable composite action. It provisions Node.js 20 for its own build and scan steps. Pin the repository to a commit in production workflows:

```yaml
name: CapFence

on:
  pull_request:

permissions:
  contents: read

jobs:
  capfence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: O3O-OvO/CapFence@main
        with:
          baseline: capfence.baseline.json
          policy: examples/policy.yml
          format: github
          fail-on: high
```

For SARIF upload, set `format: sarif` and `output: capfence.sarif`, then pass that file to `github/codeql-action/upload-sarif` in a following step.

Exit codes:

- `0`: scan completed and no configured threshold, policy violation, or capability-change failure was hit
- `1`: a finding met `--fail-on`, a policy violation was found, or an added/widened capability was detected without `--allow-changes`
- `2`: invalid CLI arguments, policy, baseline, or an unreadable target

## Design boundaries

CapFence is a static review signal, not a sandbox, malware verdict, or runtime monitor. It does not resolve variables, follow arbitrary package scripts across repositories, make network requests, read secret stores, or prove that a fixed host is trustworthy. Parse failures are reported in `analysisLimited` and do not silently fall back to a broad text scan. Evidence is clipped and redacted before it is emitted in text, JSON, SARIF, or GitHub annotations.

## Development

```bash
corepack enable
pnpm install
pnpm run check
pnpm test
pnpm run build
```

The project is TypeScript/ESM with no network access required during a scan. Add a focused fixture under `tests/fixtures` for every new rule and verify both its finding and its safe counterpart.

## License

Apache-2.0. See [LICENSE](LICENSE).
