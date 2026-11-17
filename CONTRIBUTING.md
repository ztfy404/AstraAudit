# Contributing to AstraAudit

Thanks for helping make Linux audits safer and more accessible.

1. Keep all checks **read-only** and work without network access.
2. Do not add shell commands executed through `shell=True`, or code that prints sensitive raw configuration contents.
3. Return `SKIP` for missing capabilities and `INFO` for unverifiable configuration; never label missing tooling as a successful security check.
4. Every new check requires a unique identifier, a documented rationale and unit tests.
5. Run `python3 -m unittest discover -s tests -v` before a pull request.
6. Describe which Astra Linux edition/version you have tested; do not claim broad compatibility from a single machine.

For new checks, use `@register("CAT-XX", "category", "Check title")` in `astraudit/checks.py`.