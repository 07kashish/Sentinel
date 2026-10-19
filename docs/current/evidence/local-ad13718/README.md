# Evidence for commit ad13718 (2026-09-20, owner decisions)

One development machine. Not CI, not production, not independent.

- `run.json`: the full suite bound to the release inputs. 4,470 tests, 0 failures, 0 errors, 39 skipped; 638 cases whose name carries the PostgreSQL parameter, none of them skipped. Local PostgreSQL 17 and a disposable kind cluster (Kubernetes 1.37). The JUnit file is retained outside the repository; its sha256 is in `run.json`.
- New since 765c0e6: containment activation requires a reason and a bounded expiry (84891fe); guarded incremental MCP streaming, off by default (19d02d2), 29 cases in `tests_arch/test_mcp_streaming.py`.
- The cloud proof in `../local-765c0e6/cloud-proof.json` was NOT rerun. Neither change is on the journey's path with default settings, but that is an argument, not a run.
- AWS account checked read-only after the proof: the one instance tagged `Project=sentinel-cloud-proof` is terminated; no tagged security group, key pair or volume remains. Nothing untagged was touched.

Not established: a CI run (RISK R-019); streaming against any third-party MCP server or under concurrent load (RISK R-022); the declared AWS topology (RISK R-004); any request to the real AWS STS, CloudTrail or GitHub App APIs (RISK R-021); an independent assessment; any customer.
