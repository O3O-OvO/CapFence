# Evaluating a real repository locally

CapFence evaluation is deliberately local and reproducible. Obtain the repository through an approved process, then pass its filesystem path; this workflow never clones, fetches, browses, or scans remote repositories automatically.

## Consent and ethics

- Get owner/maintainer consent before testing non-owned code, and respect licenses and access controls.
- Use a disposable copy, avoid executing target code, and protect secrets and personal data.
- Report only actionable findings, privately to maintainers first, with reproduction steps, impact, and a reasonable response window. Coordinate disclosure and credit preferences.

## Commands

From this checkout, after `pnpm run build`:

```sh
node scripts/evaluate.mjs /absolute/path/to/repository
node scripts/evaluate.mjs /absolute/path/to/repository --output ./reports/repo
```

The script invokes the existing built CLI in scan/json mode and writes redacted `<output>.json` and `<output>.md` reports. Reports include the exact command, local Git commit when available, counts, finding IDs, `analysisLimited`, and limitations. Paths are replaced with `<TARGET>`/`<WORKSPACE>`; review reports before sharing.

No dependencies are installed and no package metadata is changed. A non-zero exit from the scanner is preserved; malformed output or an inaccessible target exits with status 2.

## Public report policy

Publish only aggregate counts, redacted evidence, and reproducible synthetic examples unless the owner has approved more detail. A detected pattern is not automatically a vulnerability: mark each item as confirmed, false positive, or not manually reviewed. Do not publish real tokens, private paths, exploit payloads, or an unpatched issue before coordinated disclosure.
