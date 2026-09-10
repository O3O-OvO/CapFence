# CapFence

[English](README.md) | [简体中文](README.zh-CN.md)

Capability-diff security for AI agent skills and MCP servers.

**Watch the bilingual animated demo:** [CapFence Evaluation Demo](https://github.com/O3O-OvO/CapFence/releases/download/v0.1.0-demo/capfence-evaluation.mp4)

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

## See a complete permission diff

Run the end-to-end MCP example to compare a pinned, secret-reference configuration with a deliberately dangerous change:

```bash
pnpm run build
pnpm run demo
```

The example is at [`examples/mcp-demo`](examples/mcp-demo). It uses synthetic placeholders only; never put a real token in a fixture or issue. For a structured evaluation of public repositories, use [`docs/evaluation-template.md`](docs/evaluation-template.md) and the local-only evaluator (`pnpm run evaluate -- path/to/checkout --output .capfence/evaluation`). For a first-user pilot and pinned Action template, see [`docs/first-users.md`](docs/first-users.md). A Remotion showcase video can be previewed with `pnpm run video:preview` and rendered with `pnpm run video:render`; use [`docs/release-checklist.md`](docs/release-checklist.md) before publishing.

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

Published package: `@brian12138/capfence@0.1.0`. Install with `npx @brian12138/capfence@0.1.0` or `npm install --save-dev @brian12138/capfence`. Pin the version in production automation; do not use an unreviewed floating version.

```bash
node dist/cli.js scan path/to/project --format text
```

Supported input files are Markdown skill/instruction files, JSON/JSONC, YAML, JavaScript/TypeScript, Python, shell/PowerShell/Command scripts, `package.json`, and Dockerfiles. Markdown is only inspected inside explicitly labelled shell or PowerShell fences. JavaScript/TypeScript analysis uses the TypeScript compiler AST to recognize supported imported API aliases and multiline calls; it is not whole-program analysis. TOML and `.env` files are not supported.

Python uses the Lezer syntax parser with limited import/client binding tracking for requests, httpx and urllib calls. It does not resolve arbitrary data flow or all Python binding semantics; invalid or unsupported syntax produces analysis-limited diagnostics. JavaScript/TypeScript filesystem APIs record literal paths or `dynamic` scopes for unresolved paths, including common read, write, directory and rename operations. Unknown process arguments remain review signals, but a fixed executable without shell options is not labelled as a dynamic shell. Docker command rules inspect executable instructions rather than image names or labels. These changes can add capabilities to existing baselines; review diffs before regenerating them.

Files are discovered and analyzed incrementally rather than loading the entire tree into memory. Skipped symbolic links, read/traversal failures, parse failures, and supported files over 2 MiB produce `analysisLimited` diagnostics. Intentionally ignored dependency/build directories are outside the scan scope and do not by themselves make analysis incomplete.

All report formats expose incomplete-analysis diagnostics: JSON includes `analysisLimited`, text and Markdown show warnings, GitHub emits warning annotations, and SARIF records tool execution notifications with `executionSuccessful: false`. Permission summaries include diagnostics and `scannedFiles`; without a baseline they do not claim that permission changes are clean. CLI failure on incomplete analysis is opt-in with `--fail-on-incomplete`, for example:

```bash
node dist/cli.js scan . --fail-on-incomplete
```

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

Scan results retain multiple occurrences of the same capability at different source locations. Summary entries expose these as a `locations` array, while baseline identity remains `kind + scope`.

Normalization preserves case in executable names, filesystem paths, and environment-variable names; network hosts are case-insensitive. Older baselines that lowercased every scope have lost the original case: regenerate them from the source and review the diff before committing the replacement. Do not assume that lowercased executable/path/environment scopes are equivalent.

Baselines also retain stable finding identities. With `--fail-on`, findings already present in a baseline do not fail a later scan unless `--fail-existing` is supplied.

Export a stable JSON graph for visualizations and PR summaries:

```bash
node dist/cli.js graph . --output capfence.graph.json
# Add --baseline to annotate capability nodes as added, removed, or widened.
node dist/cli.js graph . --baseline capfence.baseline.json --output capfence.graph.json
```

Export a PR-friendly permission summary:

```bash
node dist/cli.js summary . --baseline capfence.baseline.json --policy capfence-policy.yml --output capfence-summary.md
node dist/cli.js summary . --baseline capfence.baseline.json --format json
```

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

Policy checks apply to `added` and `widened` capabilities. Removed capabilities are included in the diff but cannot create a policy violation. An explicit `network: { allow: [] }` denies all added/widened network capabilities; omitting `network.allow` leaves network access unrestricted by the allowlist (explicit deny rules still apply). GitHub and SARIF include concrete capability-change and policy annotations with matching source locations; policy annotations include the reason.

## GitHub Actions

CapFence ships as a reusable composite action. It provisions Node.js 20 for its own build and scan steps. Unlike the CLI default, the Action input `fail-on-incomplete` defaults to `true`; set it to `false` explicitly to permit incomplete scans. Pin the repository to a commit in production workflows:

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
- `1`: a finding met `--fail-on`, a policy violation was found, an added/widened capability was detected without `--allow-changes`, or analysis was incomplete with `--fail-on-incomplete`
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
pnpm run test:package
pnpm run benchmark -- 1000
```

CI covers Node.js 20, 22, and 24 on Linux and Windows. `test:package` smoke-tests the packed package; the benchmark generates a 1,000-file input to exercise incremental scanning.

The project is TypeScript/ESM with no network access required during a scan. Add a focused fixture under `tests/fixtures` for every new rule and verify both its finding and its safe counterpart.

## License

Apache-2.0. See [LICENSE](LICENSE).
