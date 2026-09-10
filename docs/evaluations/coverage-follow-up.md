# Coverage follow-up (2026-09-10)

Target: modelcontextprotocol/servers at d73f99efbfd40c3aa1b61e88728b3d49fb52608f. Static local reading only; target dependencies and code were not executed. These are analyzer quality observations, not vulnerability claims.

## Filesystem review

The scoped scan records 204 capability occurrences: 171 in tests, 32 in production TypeScript and one package lifecycle. Counts are not unique permissions. Manual spot checks covered readFile, writeFile, rename, unlink, chmod, open, mkdir and readdir. Reported kinds and locations matched those operations. Unresolved paths remain dynamic; allowed-directory validation is not inferred. Two unknown rename endpoints collapse to one same-location dynamic capability; the graph does not distinguish argument roles.

The test helper's unresolved process arguments remain a review signal. Its fixed node executable is retained, and the finding no longer asserts shell execution. This is not a confirmed injection vulnerability.

## Python parser repair

Lezer Python 1.1.19 accepts only VariableName after with/as. A pinned pnpm patch adds parenthesized tuple binding targets. No source rewriting or diagnostic suppression is used. Invalid tuple targets retain parser diagnostics. The Python analyzer is bundled into dist with dependency licenses so npm consumers receive the corrected grammar without relying on pnpm patch support.

To reproduce the dependency build: apply the grammar change in the tracked patch, run lezer-generator on src/python.grammar, bundle src/parser.js to dist/index.js (ESM) and dist/index.cjs (CJS) with esbuild, then pnpm patch-commit. Tool versions are pinned in devDependencies.

## Release notes (unreleased)

- Add common JS/TS filesystem capabilities for literal and unresolved paths.
- Parse Python calls instead of treating Python source lines as shell commands; recognize supported httpx, requests and urllib bindings.
- Ignore Docker image/label text in command analysis.
- Distinguish unresolved process arguments from dynamic shell input.
- Support async context-manager tuple bindings, including in installed packages.

Review baseline changes before regeneration. These are partial syntax and API analyses, not whole-program data flow or proof of safety. Raw local reports are intentionally excluded from version control.
