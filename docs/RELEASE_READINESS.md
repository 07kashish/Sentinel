# Release readiness



- commit: `879e29f38351a2f4aa2b522d611b1cd04a2fa64a`
- generated: 2026-09-02T10:58:03.006685+00:00

## The four states

| State | Means |
|---|---|
| `PASSED` | evidence exists, is bound to this build, records success |
| `FAILED` | evidence exists, is bound to this build, records failure |
| `UNVERIFIED` | no evidence, or evidence belonging to another build |
| `NOT APPLICABLE` | a build is the wrong kind of thing to satisfy this |

`UNVERIFIED` is never assurance. It is the absence of it.

---

## A. Engineering readiness

**21 passed · 0 failed · 1 unverified of 22** — INCOMPLETE

Reachable through reproducible work. Every row here is something this repository can move.

| Category | State | Blocking | Unverified inputs |
|---|---|---|---|
| Core architecture | PASSED | none | — |
| Security engineering | PASSED | none | — |
| Code/test discipline | PASSED | none | — |
| Runtime enforcement | PASSED | none | — |
| MCP security | PASSED | none | — |
| A2A security | PASSED | none | — |
| Identity | PASSED | none | — |
| Discovery | PASSED | none | — |
| Skill security | PASSED | none | — |
| Evidence/attestation | PASSED | none | — |
| Integrations | PASSED | none | — |
| Tenant isolation | PASSED | none | — |
| Performance | PASSED | none | — |
| HA/DR machinery | PASSED | none | — |
| UX | PASSED | none | — |
| Compliance tooling | PASSED | none | — |
| Release assurance | UNVERIFIED | blocking | `artifact_signing` |

A category is `PASSED` only when every gate feeding it passed. There is no partial credit: a category with one unverified input is not finished, and rounding it up is the thing section 25 forbids.

---

## B. External assurance

**0 of 4, and not reachable from this repository.**

Every row here is NOT APPLICABLE to a build and UNVERIFIED as assurance. Nothing in this repository can change that.

### `design_partner_validation`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A real organisation running this against real traffic under a real agreement, completing the agreed validation. A commercial fact, not a technical one.
- **Already prepared:** docs/DESIGN_PARTNER_RUNBOOK.md defines the staged rollout the specification asks for: OBSERVE, SIMULATE, WARN, REQUIRE_APPROVAL, ENFORCE_LOW_RISK, ENFORCE_HIGH_RISK -- so a partner can start without enforcement touching their traffic
- **Owner:** founders / commercial
- **Elapsed time:** one pilot cycle
- **Cost shape:** a signed pilot agreement

### `disaster_recovery_proof`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A recovery executed across an INDEPENDENT failure domain -- a second region or account -- with measured RPO and RTO. The domain has to exist before crossing it proves anything.
- **Already prepared:** PITR drills exist and measured RPO ~57s with archive_timeout set. Their own artifact states the limitation plainly: the WAL archive sits on the SAME HOST AND DISK as pgdata, which is why this gate reads fail rather than pass. The Helm chart refuses to render until an operator confirms continuous archiving is configured
- **Owner:** SRE + cloud account owner
- **Elapsed time:** 1-2 weeks to stand up the second domain, then a drill day
- **Cost shape:** a second region's infrastructure

### `independent_pentest`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A scoped engagement by a firm with no stake in the result, followed by a remediation cycle and a RETEST of the findings. The retest is the part people skip and the part that matters: a report with open criticals is a to-do list, not assurance.
- **Already prepared:** docs/SECURITY.md, docs/attack_surface.json (47 routes with the capability each declares), docs/SECURITY.md, and a reproducible test deployment
- **Owner:** security leadership + external firm
- **Elapsed time:** 4-8 weeks including remediation and retest
- **Cost shape:** fixed-fee engagement

### `production_soak`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A continuous run against production-like traffic for the declared period, tracking event loss, memory growth, queue backlog and ledger integrity. THE ELAPSED TIME IS THE EVIDENCE. A harness that runs for an hour measures something else, and no amount of engineering compresses a thirty-day observation into an afternoon.
- **Already prepared:** scripts/run_observability_soak.py runs continuously and rewrites its report every interval, so a run stopped early still leaves a truthful record of the window it covered. A 7-minute production-shaped run on PostgreSQL measured ingest p95 71.6ms against a 500ms target
- **Owner:** SRE
- **Elapsed time:** 30 days minimum for a 99.9%/30d SLO
- **Cost shape:** one production-like environment, running

---

Engineering readiness: 21/22 (INCOMPLETE). External assurance: 0/4, and not reachable from a repository. The two are reported separately because combining them understates finished engineering and overstates commercial readiness at the same time.
