# External repository evaluation: Model Context Protocol servers

This evaluation uses the public [Model Context Protocol `servers` repository](https://github.com/modelcontextprotocol/servers) at commit `d73f99efbfd40c3aa1b61e88728b3d49fb52608f`.

## Scope and consent

This was a read-only local checkout of a public repository. CapFence did not execute code from the target repository, install its dependencies, or attempt exploitation. This report is an independent static-analysis experiment, not a vulnerability disclosure or a claim about the maintainers' security posture.

## Reproduce

```powershell
# From the CapFence repository, after checking out the pinned commit locally:
node scripts/evaluate.mjs path/to/servers --output reports/model-context-protocol-servers
```

## Result

- Findings: **11**
- Capabilities: **56**
- Analysis limited: **0**
- Finding IDs: `CF-PKG-001`, `CF-EXEC-001`
- Evaluated commit: `d73f99efbfd40c3aa1b61e88728b3d49fb52608f`

The findings are static indicators requiring maintainer review. The report includes source locations and evidence; they do not establish exploitability or malicious behavior. For example, an unpinned package runner may be intentional documentation or development tooling, but it is still a supply-chain review item.

## Limitations

- The scan is local-only and does not fetch or run target code.
- Results cover the repository snapshot, not runtime behavior or deployment configuration.
- No manual maintainer confirmation was obtained for individual findings; contact maintainers through the repository's normal channel before publishing any security-specific claim.
