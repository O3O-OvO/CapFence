# Contributing

## Development setup

Use Node.js 20 or newer:

```bash
corepack enable
pnpm install
pnpm run check
pnpm test
pnpm run build
```

## Adding a rule

Keep detection deterministic and location-aware. Add a small safe fixture and a risky fixture under `tests/fixtures`, assert the capability and finding contract, and make sure emitted evidence is redacted. A rule should not execute a command, fetch a URL, expand a variable, or read a secret store.

Prefer a new capability or finding ID over changing the meaning of an existing ID. If a parser cannot produce reliable locations, report an `analysisLimited` entry rather than falling back to an unbounded text search.

## Pull requests

Explain the threat model, false-positive tradeoff, and compatibility impact in the pull request description. Run `pnpm run check`, `pnpm test`, and `pnpm run build` before submitting.
