# Security and recovery evidence

Updated 2026-09-19. Authorized environments remain local and GitHub only. The first workflow is a human-approved Kubernetes infrastructure change for midmarket SaaS/fintech infrastructure teams. No customer or cloud account was used.

## Accepted local checkpoint

Commit `e025799f495747cce4d9b84a678668d166021d3d` passed the complete suite from a clean detached checkout: **4,228 passed, 22 skipped, including 592 passed PostgreSQL cases**. Execution ran from 13:15:15 to 13:21:12 UTC on 2026-09-19 with Python 3.13.14 on macOS arm64, local PostgreSQL 17.11 (UTF-8, non-superuser application role), Redis 8.10.1, real local MinIO, Helm 3.16.3 and a local Kubernetes API. The release-input SHA-256 is `92dc648f18063788a8bbae7f7ab88a65ad89ae4e329acf39e1bda5a8e5f2d823`. Inputs did not change during the run.

[Retained report snapshot](evidence/local-e025799/README.md) includes the module outcomes, local provenance, package smoke results, image gate, runtime binding, cluster smoke and skip inventory. Full artifacts are retained in the sibling `sentinel_program_evidence/2026-09-19-e025799` directory. RELEASE_STATUS binds their digests. These unsigned local reports are neither independent attestations nor CI or production observations.

Fourteen skips concern PostgreSQL-only behavior on SQLite. The other eight are one live traced-detonation test, one absent real `.env` check, five missing soak artifacts and one missing independent-English benchmark artifact. Real credentials were not read to fill the `.env` skip. Missing artifacts grant no acceptance tier. The earlier local services were stopped when this session resumed; the Docker build failure is retained, services were restored and the accepted complete test run contains no failures.

## Execution and live infrastructure

Kubernetes mutations require approval-bound object preconditions: updates carry the exact UID, nonzero resourceVersion, name and namespace; deletes carry UID and resourceVersion preconditions. The adapter sends these values unchanged to the API and refuses non-2xx outcomes without leaking response bodies or retrying. Live API tests cover approved mutations, parameter substitution, replay, concurrent updates and object replacement on both database backends. A returned conflict after invocation is conservatively recorded as `unknown_after_effect`, requiring reconciliation; API acknowledgement is not controller convergence. The HTTP harness uses synthetic identity/attestation and is not a deployed customer identity proof.

The final Linux arm64/Python 3.12 container also passed a separate two-pod kind smoke test using PostgreSQL 16 with NOSUPERUSER/NOBYPASSRLS and Redis 7.4.2. It exercised schema migration, the chart archive-settings hook, cross-pod authorization redemption, replay, unbound execution and cross-tenant refusal. One harmless echo operation was durably recorded. Both pods returned HTTP 429 during Redis outage, and Redis was restored. Runtime manifest inspection confirmed the pods resolve to the built image's configuration and uncompressed filesystem layer identity.

This local shape has two replicas on one node, no service mesh, and explicitly skips the production chart schema for that shape. NetworkPolicy objects exist; CNI enforcement is unverified. The deployed echo smoke and real Kubernetes mutation harness are distinct tests, not one fully deployed consequential-action workflow.

Counted-effect HTTP tests also exercise expiry, policy change, revocation, containment and post-effect storage uncertainty. Durable intent survives when outcome recording fails. Local multi-process tests cover tenant-scoped shared controls. Bounded OTLP queues, redaction, loss metrics, protobuf delivery and shutdown cleanup are tested; collector TLS, long-duration memory behavior and production interoperability remain unverified. Unknown-path metrics tests do not establish a production soak.

## Packaging and vulnerability gate

Two builds with setuptools 84.0.0 and SOURCE_DATE_EPOCH=1789603200 produced identical wheel SHA-256 `d4c7eb1c82f357689adada8ee94624dfe1b6880bb3bd69b0ff6a290165e6794c`. The exact wheel passed clean thin-SDK and server installation, migrations, health probes, shipped console assets, policy evaluation and unbound-execution refusal. Allowlist/pattern checks covered 241 wheel members, 246 source-distribution members and 887 tracked files with no configured findings. This establishes local wheel reproducibility; container OS package resolution and source tarball bytes are not claimed reproducible.

Final image: `sha256:6f6e89534e2ff02ad28613d8979b1dcf007623b488f77aec81ae6eb1f7a70072`. Trivy reported **44 HIGH package findings across eight CVEs**, all without a fixed version in this scan, and no secret or misconfiguration findings. The corrected local gate blocks all 44 findings; the configured CI gate has the same policy but has not run. No automatic unfixed exception, suppression or executive waiver is accepted. The image SBOM and vulnerability inventory are retained. R-015 remains open and blocks release.

A separate scan examined all 17 saved image layers, including deleted historical file versions: 13,580 regular file versions and 579,151,104 bytes. Two private-key-header pattern hits were traced to the public cryptography SSH parser delimiter and its compiled module; no key body was detected. Exact-file hashes and triage are retained alongside the original failed pattern-scan result. This is not proof against every unknown or encoded credential. Docker contexts use a default-deny literal file manifest and are checked inside the build before copying into the runtime image.

Ruff and the configured Bandit medium/high gate passed, with the existing B608 exclusion. The unchanged dependency lock retains the 2026-09-17 audit of 41 components with no known vulnerabilities reported at that time; it is not a new audit query. Nine components lack SPDX expressions and need license review. Local inventory is not legal clearance. Artifacts remain unsigned by a verified release identity.

## Recovery and historical evidence

The earlier `57b6f66` local WAL/PITR drill measured experimental RPO 1.0511 seconds and RTO 0.8045 seconds for four batches of 200 synthetic rows. Those measurements belong to that earlier checkpoint. Both database instances shared one machine/storage failure domain; this is not independent-domain or cloud recovery evidence. Current functional recovery tests do not replace that missing deployment exercise.

Checkpoint `129a86e` had 4,216 passes and a different image. Checkpoint `57b6f66` had 4,175 passes and a different wheel. Earlier failures and artifacts remain historical and are not relabelled as final evidence. The user's original SQLite drill modification remains unstaged.

## Unverified production gates

GitHub Actions remains held until 2026-10-02 at the owner's request. No release-identity signature verification, enforced CNI/egress proof, real workload identity and constrained-credential integration, independently controlled WORM evidence sink, independent-domain restore, external security assessment, production-like soak, 30-day SLO window or completed paid design-partner workflow exists for this candidate. The high-severity image findings remain unresolved. Production readiness and universal competitor superiority are not established.

## 2026-09-20: evidence that can leave the environment

Execution receipts are now committed to the tenant transparency log (migration 37) and `GET /v1/evidence/export` returns them with inclusion proofs. `standard/execution-passport-v1/verify_evidence_bundle.py` verifies a bundle with the Python standard library only; `tests_arch/test_evidence_commitments.py` shows it rejecting an altered receipt, a receipt that was never logged and a log that moved past a trusted root.

What this proves: a customer holding a bundle and a root can check the receipts without Sentinel. What it does not prove: that any root is held outside the environment. Before this date nothing appended to the log at all, so earlier roots describe an empty tree. Independent recovery (RISK R-003) and external anchoring (RISK R-018) are unchanged: no drill has destroyed a primary, restored elsewhere and verified old evidence against a separately held root.

