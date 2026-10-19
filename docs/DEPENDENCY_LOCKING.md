# Dependency locking notes

## Current practice

- Runtime pins: `requirements.txt` (exact versions preferred for CI reproducibility).
- Dev pins: `requirements-dev.txt` includes `-r requirements.txt` plus test/lint tools.
- Container SBOM: CI generates CycloneDX from `requirements.txt` (`cyclonedx-py`).
- Vulnerability gate: `pip-audit` against `requirements.txt` with explicit ignores in
  `security/pip-audit-ignore.txt` (blocking; no `|| true`).

## What is NOT present

- No Poetry/Pipenv lockfile. Adding one is optional; pins in requirements files are
  the lock surrogate today.
- No mypy/pyright gate in CI. Type checking is deferred; ruff + architecture fitness
  rules are the static gates that fail the build.

## Operator action

When bumping dependencies: update both requirements files, run `pip-audit`, run the
full `tests_arch/` suite on SQLite and PostgreSQL parametrisation, regenerate SBOM
artifact in CI.
