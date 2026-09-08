# CapFence evaluation record

Use this template when evaluating a public repository. Do not publish credentials, private source, undisclosed vulnerability details, or exploit instructions.

## Repository

- URL:
- Commit SHA/tag:
- Date (UTC):
- Scope scanned:
- CapFence version/commit:
- Command:

## Results

| Category | Count | Manually reviewed | Correct | Incorrect | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Capabilities |  |  |  |  |  |
| Findings |  |  |  |  |  |
| Analysis-limited diagnostics |  |  |  |  |  |

## Confirmed useful detections

For each item, record the file and line, but redact secrets and sensitive infrastructure details.

- Rule/capability:
- Evidence summary:
- Why it matters:
- Reviewer disposition:

## False positives

- Rule:
- Redacted evidence:
- Why it is safe:
- Proposed rule/test improvement:

## False negatives or limitations

- Expected behavior that was not detected:
- Why it was missed (unsupported format, alias, data flow, parser, etc.):
- Safe reproduction using synthetic placeholders:
- Follow-up issue:

## Responsible disclosure checklist

- [ ] No real credentials or tokens included.
- [ ] No private repository content included.
- [ ] No unpatched vulnerability details published.
- [ ] Maintainer contacted privately where appropriate.
- [ ] Public report uses a synthetic reproduction or waits for a fix.
- [ ] Scope and commit are reproducible.
