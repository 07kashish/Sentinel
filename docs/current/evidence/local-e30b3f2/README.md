# Local evidence for commit e30b3f2 (2026-09-20, third pass)

One development machine, macOS arm64. Not CI, not production, not independent.

- `run.json`: the full suite bound to the release inputs. 4,396 tests, 0 failures, 0 errors, 39 skipped; 617 PostgreSQL-parametrised cases. Local PostgreSQL 17 and a disposable kind cluster (Kubernetes 1.37), so the live journey and contract tests executed. The JUnit file is retained outside the repository; its sha256 is in `run.json`.
- `deployed-journey.json`: `scripts/run_deployed_journey.py`, PASSED, on the image built from this tree. As the second pass, plus TLS between the agent pod and Sentinel verified against a private CA. One node, synthetic credentials.

Not established here: a CI run (RISK R-019); any request to real AWS or GitHub (RISK R-021); a cloud cluster or another CNI; mutual TLS; a customer identity provider; a customer-run witness; an independent failure domain; a published or signed image; any customer.
