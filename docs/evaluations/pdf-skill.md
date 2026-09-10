# PDF Skill evaluation

Target: anthropics/skills, commit 41bbe19d1a1a7eaab5e7bb9050a417e5c6cffc8f, scope skills/pdf. Date: 2026-09-10. Static local checkout only; no target dependencies installed or target scripts executed.

11 supported files were scanned. Initial result: 8 file-read occurrences, no findings, no analysis-limited diagnostics. Manual review identified four write-mode open calls incorrectly classified as reads. After the mode fix, the same eight occurrences consist of four reads and four writes, with no findings or diagnostics.

This is not complete coverage: Image.open/save, pdfplumber.open and PDF writer/library internals are not resolved. Markdown Python examples are outside the explicitly supported shell-fence analysis. No vulnerabilities are claimed; zero findings does not establish safety.

The synthetic PR contract exercises the composite Action against a changed network host, requires the expected failure, checks added/removed JSON changes, and writes a job summary. External sample contents and raw local paths are not included in the PR.
