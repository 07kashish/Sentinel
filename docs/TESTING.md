# Testing

## Suites

| Suite | Command | Purpose |
|---|---|---|
| Architecture fitness | `pytest -q tests_arch/test_architecture_rules.py` | Dependency rule, fences, size, protect allowlist |
| Domain / execution | `pytest -q tests_arch/test_domain_incident.py tests_arch/test_execution_*.py` | Lifecycle, chaos, concurrency, properties, model, mutation |
| Security | `pytest -q tests_arch/test_security_*.py` | Edge, outbound, bounds, MFA, passkeys, throttle |
| SQL / RLS | `pytest -q tests_arch/test_sql_infrastructure.py` | Both engines via pgserver |
| Protect / tools | `pytest -q tests_arch/test_protect_gate.py tests_arch/test_tool_runner.py tests_arch/test_gated_remediation.py` | F-11 |
| VCS integrity | `pytest -q tests_arch/test_vcs_integrity.py` | Empty-module script + pre-commit wiring |
| Detection gate | `python evaluation/metrics.py` | Fails on unmarked misses |

## Engines

`tests_arch/conftest.py` parametrises SQL/chaos/concurrency over SQLite and
embedded PostgreSQL as a non-superuser so FORCE RLS binds.

## Mutation

Hand probes + AST campaign (`test_execution_mutation*.py`). F-12 remains PARTIAL:
not every invariant is mutated.

## What CI runs

See `.github/workflows/ci.yml`: lint, empty-module gate, full pytest, metrics,
Postgres-focused job, verification (properties/model/mutation/architecture),
gitleaks, bandit, pip-audit, docker smoke, helm/kubeconform, schemathesis DAST.
