# Local evidence for commit 77c1303 (2026-09-20, second pass)

One development machine, macOS arm64. Not CI, not production, not independent.

- `run.json`: the full suite bound to the release inputs. 4,372 tests, 0 failures, 0 errors, 39 skipped; 616 PostgreSQL-parametrised cases. Run with a local PostgreSQL 17 and a disposable kind cluster (Kubernetes 1.37), so the live journey and contract tests executed. The JUnit file is retained outside the repository; its sha256 is in `run.json`.
- `deployed-journey.json`: `scripts/run_deployed_journey.py`, PASSED. Two Sentinel pods in production mode with PostgreSQL and Redis; an agent pod identified by its kubelet-issued pod-bound token; the API server refusing the agent's direct write and the executor's unstamped write; kindnet blocking the agent pod from the API server; approval through one pod and execution through the Service; the change applied under a minted credential and attributed in managedFields; replay refused across pods; the receipt committed and the bundle verified offline. It ran against the image built from the tree two commits earlier than this one for the runtime code it exercises; later commits changed adapters, identity key rotation and tests, not the journey's path. One node, synthetic credentials.
- `workflow-loadtest.json`: `scripts/run_workflow_loadtest.py`. A regression baseline on one shared machine. Read its `limitations` before repeating any figure.

Not established here: a CI run (RISK R-019), a cloud cluster or another CNI, TLS between agent and Sentinel, a customer identity provider, a customer-run witness, an independent failure domain, a published or signed image, any customer.
