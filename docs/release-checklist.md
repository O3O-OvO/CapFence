# Public release checklist

Before publishing CapFence or announcing an evaluation:

- [ ] `pnpm run check`, `pnpm test`, and `pnpm run test:package` pass.
- [ ] `pnpm run demo` produces only synthetic placeholder evidence.
- [ ] `node scripts/evaluate.mjs <local-checkout>` records repository commit and scan scope.
- [ ] Every reported finding is manually marked confirmed, false positive, or unreviewed.
- [ ] No token, private path, private source, exploit payload, or undisclosed vulnerability appears in reports, screenshots, video, or issues.
- [ ] npm package metadata, README install commands, and `files` allowlist are correct.
- [ ] Production GitHub Action examples use a reviewed commit SHA, not a floating branch.
- [ ] The release tag and package version match.
- [ ] Remotion preview and render succeed; the MP4 is reviewed for redaction and readable text.
- [ ] The video identifies CapFence as static analysis and does not claim to prove exploitability.
- [ ] Evaluation scope, target commit, CapFence commit, and limitations are published.
- [ ] Maintainers are contacted privately before discussing a possible real vulnerability.
