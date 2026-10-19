# Release governance

Scope approved on 2026-09-17: local development and GitHub only. GitHub Actions is on hold at the owner's request until 2026-10-02 after the service refused jobs for an account billing/spending-limit issue. Do not rerun or treat those jobs as executed before the hold is lifted. This is not permission to relax a gate or deploy a customer workflow.

## Release admission

A release candidate needs an exact commit, release-input digest, artifact digests, executed test reports, vulnerability and license results, SBOM, artifact provenance, and signature verification tied to the delivered bytes. Local unsigned reports remain local evidence. A second byte-identical wheel build supports reproducibility only for the recorded environment and build inputs.

Authorization, policy, schema and verifier changes need an explicit compatibility rule, rollout sequence, rollback plan and review by accountable owners. Role names in the risk register are assignments to fill, not signatures by real executives. No risk acceptance or fail-open exception is inferred from missing infrastructure or a deadline.

## Rollout and rollback

For the v2 policy binding, pause admission, settle or reconcile in-flight operations, deploy consistently, invalidate stale approvals and require fresh evaluation/approval before resuming. Preserve receipts, audit and operation records. Reverting a binary does not reverse a remote effect. The exact changes and rollback restrictions are in RELEASE_CHANGES.md.

Until independent security, fault-tested topology, recovery, observation and paid-pilot gates are met, use developer-preview status for the declared workflow. A successful unit or integration test is never a substitute for those gates. Existing evidence schemas must remain verifiable; any incompatible schema requires a separately versioned verifier and migration tooling before release.

## Operating cadence to establish

Weekly vulnerability and incident review; monthly release review with migrations and rollback; quarterly independent adversarial assessment and customer win/loss review; semiannual integration and failure-domain review; annual segment, pricing, licensing and operating-model review. These are proposed responsibilities, not scheduled jobs or meetings that have occurred. No automation or external outreach was created.
