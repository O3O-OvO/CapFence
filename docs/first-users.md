# First-user pilot

The goal of the pilot is retained use in real pull requests, not star count.

## 15-minute trial

1. Install Node.js 20+ and run `npx capfence@0.1.0 scan . --format text` after npm publication, or build locally with `pnpm install && pnpm run build`.
2. Review the capabilities and `analysisLimited` diagnostics.
3. Create a baseline for the intended Skill/MCP directory:
   `npx capfence baseline path/to/target --output capfence.baseline.json`.
4. Add the pinned Action template in `.github/workflows/capfence.yml`.
5. Open a harmless test PR that adds a new host or dynamic command.
6. Decide whether the report is useful enough to keep enabled.

## Pinned Action template

Use the reviewed current commit SHA `449f59fa48ca4245a89c99d0d7d20f6d73e6480e` instead of a floating branch reference:

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
      - uses: O3O-OvO/CapFence@449f59fa48ca4245a89c99d0d7d20f6d73e6480e
        with:
          path: path/to/skill-or-mcp
          baseline: capfence.baseline.json
          policy: capfence-policy.yml
          format: github
          fail-on: high
          fail-on-incomplete: "true"
```

## Feedback form

- Repository type (Skill, MCP server, agent, other):
- Did setup take under 15 minutes? Why/why not?
- Was the first capability diff understandable?
- Which finding was useful?
- Which finding was noisy or missing?
- Did you keep the Action enabled after the trial?
- What would make you remove it?
- May we quote your feedback anonymously?

Never include secrets or undisclosed vulnerability details in feedback. Use a private security channel for sensitive reports.
