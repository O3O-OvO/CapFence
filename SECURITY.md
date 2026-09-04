# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability in CapFence.

Use GitHub's private security advisory flow for this repository, or contact the maintainers through the private contact listed on the repository profile. Include the affected version, a minimal reproduction, impact, and any suggested mitigation. Do not include live credentials in a report; redact them before sharing.

We will acknowledge a report when we can, reproduce the issue, and coordinate a fix and disclosure timeline with the reporter. CapFence is a static analyzer, so reports about a missed detection should include the scanned input and the expected capability or finding, while reports about command execution should explain how the analyzer caused execution rather than merely detecting text.

## Supported versions

Only the latest release on the default branch is guaranteed to receive fixes while the project is in its 0.x development phase.
