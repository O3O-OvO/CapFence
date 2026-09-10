# Explicit scan scope

Use repeatable literal relative paths (not glob patterns):

```sh
node dist/cli.js scan project --exclude tests --exclude examples
node dist/cli.js baseline project --exclude tests --output baseline.json
node dist/cli.js diff project --exclude tests --baseline baseline.json
```

Paths are relative to the scan directory (or a single target file's parent). Matching is case-sensitive, uses whole path segments, and excludes a directory's descendants. Absolute paths, parent traversal and wildcard syntax are rejected. Missing paths are allowed and still reported. Explicit exclusions do not trigger analysisLimited. Tests and examples are not excluded by default.

JSON, text, SARIF, GitHub annotations, graph and permission-summary outputs expose configured excludedPaths. Baselines retain those paths; comparison refuses a different exclusion list. Old baselines imply no explicit exclusions. Review before regenerating baselines, since exclusions intentionally reduce coverage.

The composite Action accepts an `exclude` input with one relative path per line.

# Process severity

Unresolved arguments to a fixed ordinary executable are medium-severity CF-EXEC-001 review signals. Unknown executables, shells and recognized interpreters remain high severity. This changes finding severity, not capability identity, and does not prove that any ordinary executable is safe. Python calls without a resolved executable remain conservatively high severity. `--fail-on high` no longer fails solely for medium findings; `--fail-on medium` still does.
