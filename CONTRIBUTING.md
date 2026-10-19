# Contributing

## Branching

- Default branch: `main`
- Feature work: short-lived branches (`feat/…`, `fix/…`)
- Prefer pull requests; do not force-push `main`
- See `.github/branch-protection.md` for operator `gh api` protection setup
  (remote enforcement may be UNVERIFIED until applied)

## Local checks before PR

```bash
ruff check sentinel tests_arch
python scripts/check_empty_modules.py
pytest -q
python evaluation/metrics.py --json evaluation/metrics.json
```

## Architecture

Dependency rule and fitness tests live in `tests_arch/test_architecture_rules.py`.
Do not add ambient `os.getenv` outside `sentinel.composition.settings`.
Remediation side effects must go through `ProtectedToolRunner` /
`POST /v1/tools/execute`.
