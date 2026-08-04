# Contributing Guide

Thank you for contributing to **RACON**! Please read this guide before
opening a pull request.

## Scope

RACON is a **defensive reconnaissance and auditing** framework. Contributions
must not introduce exploit capabilities, credential attacks, brute-forcing, or
any functionality intended to gain unauthorized access. If in doubt, ask.

## Getting started

1. Fork the repository.
2. Create a feature branch from `main`.
3. Install development dependencies:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   pip install pytest
   ```

## Development workflow

- Write or modify a module under `modules/`.
- Follow the existing patterns: subclass `BaseModule`, implement `execute`,
  populate `result.data` and `result.findings`.
- Add unit/integration tests under `tests/`.
- Run the full suite before committing:
  ```bash
  python -m pytest tests/ -v
  ```

## Code style

- **Python 3.10+** with modern typing (`from __future__ import annotations`).
- PEP 8 conventions; 79-column lines are preferred.
- Include docstrings on public classes/methods.
- Keep modules dependency-aware: optional heavy dependencies (e.g. `geoip2`,
  `nmap`) should fail gracefully when unavailable.

## Adding a module

1. Create `modules/your_module.py` with a `YourModule(BaseModule)` class.
2. Register it in `modules/__init__.py` (`MODULES` list).
3. Add a config toggle under `modules:` in `config.yaml`.
4. Document it in `docs/MODULES.md` and `docs/FEATURES.md`.
5. Add tests and update the README module table.

## Commit & pull request

- Use clear, conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`).
- Reference any related issue.
- Ensure tests pass and there are no leftover debug statements.

## Reporting issues

Include:
- Python version and OS
- Steps to reproduce
- Expected vs. actual behaviour
- Any relevant log output (sanitize sensitive data)

---

Thanks for helping keep RACON safe, professional, and high quality. 🛰️
