# Changelog

## 0.1.1 (2026-11-17)

- Fix startup `SyntaxError` on Astra Linux installations with Python 3.5.
- Replace Python 3.7+ dataclasses, f-strings, future annotations, and subprocess options.
- Add a syntax compatibility regression test for Python 3.5.
- No changes to read-only audit behavior or the 47 checks.

## 0.1.0 (2026-11-17)

- Initial baseline with 47 local read-only checks across ten categories.
- JSON, Markdown, and standalone HTML report export.
- Python standard library only, Python 3.7-compatible grammar.
- Unit tests, CI workflow, strict exit status for automation.
- Explicit handling for absent features in Astra Linux CE/SE.