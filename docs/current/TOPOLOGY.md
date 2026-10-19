# Supported topology

This is a candidate pilot topology, not a production-supported deployment. Authorization currently covers local and GitHub only. The cloud account, region, operators and deployment evidence have not been established.

## Candidate shape to validate

| Component | What | Why this and not another |
|---|---|---|
| Service | the container image built by `Dockerfile` (Python 3.12, `gunicorn` with `uvicorn` workers, entrypoint `docker-entrypoint.sh`), deployed by the Helm chart in `deploy/helm/sentinel` | The image is what CI builds, scans, signs (opt-in) and smoke-tests on kind. A pip-installed server is exercised by `scripts/smoke_clean_install.py` for packaging correctness only. |
| Database | PostgreSQL 16 or later, one primary, `FORCE ROW LEVEL SECURITY` on every tenant table, the service connecting as a non-superuser role | Row-level security is the tenant boundary; it does not bind for a superuser. SQLite is a development and test engine and is refused in production by `Settings`. |
| Shared state | Redis, reachable from every replica | The rate limiter and the readiness cache are per-process without it; `sentinel/interface/asgi.py` refuses to start more than one process in production without a Redis URL. Budget and circuit-breaker state live in PostgreSQL (`protect_control_state`) and need nothing else. |
| Object storage | S3-compatible bucket for WAL archive (`deploy/wal-archive/wal_s3.py`) and, optionally, transparency-root publication | Point-in-time recovery needs an archive outside the database host. |
| Workers | the same image with the worker entrypoint, sharded by `SENTINEL_WORKER_SHARD`/`SENTINEL_WORKER_SHARD_COUNT` | Outbox delivery, retention, stale-operation reaping and root publication run here; the API process does not depend on them to decide. |
| Ingress | TLS terminated in front of the service; `SENTINEL_TRUSTED_PROXY_HOPS` set to the number of proxies | Client addresses feed the per-address limiter; a wrong hop count either throttles the proxy or trusts a spoofed header. |
| Identity | tenant-scoped API keys for runtimes (`SENTINEL_API_KEYS`), OIDC for console users where configured | The first workflow authenticates runtimes with keys; workload identity is a later binding (see `FIRST_WORKFLOW.md`). |

Replica count is not certified. Two local database pools exercise selected shared controls; that does not prove two pods, all middleware, telemetry aggregation, or cluster egress. Start validation with two API pods and one process per pod, a shared PostgreSQL primary and Redis, then explicitly fault-test each promised deployment-wide control. PostgreSQL 16/17 and Python 3.12/3.13 test results do not certify every newer version.

## Configuration alignment

`scripts/check_config_alignment.py` reports zero unmatched names for the checked-in surfaces. It examines exact literals and dynamic parser schemas; runtime reachability is not established by a source scan. Raw-manifest and real Helm-rendering tests feed environment values into `Settings`, and chart schema rejects disabled binding or fail-open limiting.

The chart/raw deployment now supplies shared Redis from a secret reference, permits its same-namespace network path, sets enforcement and binding, and runs one API worker per pod. The collector endpoint must use HTTPS with a trusted certificate. Unused signer and proxy environment settings were removed. Configure and verify actual target-system network paths before enabling an adapter. Two independently spawned local processes now test shared Redis limits and durable nonce claims, with tenant isolation; this still does not establish a pod, mesh or CNI topology.

GitHub Actions remains deferred until 2026-10-02. The future kind smoke deploys real Redis; it has not been run for this candidate. R-009 remains mitigated locally, not closed by deployed evidence.

## Not supported

- More than one API process without Redis (refused at startup).
- SQLite in production (refused at startup).
- A single-region PostgreSQL with no WAL archive as the only copy of the
  evidence chain.
- Running the soft prompt classifier from a pip install: the artifact is a
  repository and image asset (RISK R-010).

## Portable local database verification

On macOS, install PostgreSQL tools separately and set `SENTINEL_TEST_PG_BIN` to their absolute bin directory. Use the same major version for initdb, pg_ctl, pg_basebackup and psql. Set `SENTINEL_TEST_POSTGRES_DSN` to an isolated loopback test administrator database; the fixture creates a separate non-superuser role for RLS tests. Never point the test suite at customer data. Backup/archive tests create their own temporary clusters; these local recovery drills do not establish independent failure-domain recovery. Linux/Windows retain the pgserver fallback. A wrong explicit binary path must fail verification rather than be treated as a passing recovery check.

## Protected changes in the customer's cluster (2026-09-20)

The first workflow adds three identities and one admission policy to the TARGET cluster, shipped in `deploy/protected-changes/`:

| Identity | Holds | Why |
|---|---|---|
| `sentinel-broker` (what Sentinel presents) | `create` on `serviceaccounts/token` for `sentinel-executor`, nothing else | The credential that lives in a long-running process can change nothing |
| `sentinel-executor` (never runs as a pod) | The named resource kinds in each protected namespace | The blast radius of one in-flight operation for ten minutes |
| Agent service accounts | Read-only | Agents read; they do not write |

The `ValidatingAdmissionPolicy` refuses, in namespaces labelled `sentinel.io/protected-changes=true`, any write by an agent service account and any executor write without the operation stamp. Requires Kubernetes 1.30 or later. Order of rollout: RBAC, then Sentinel's executor settings, then the policy, then the namespace label. Network egress restriction for agent pods is `deploy/agent-egress/` and depends on an enforcing CNI, which no test here exercises.

