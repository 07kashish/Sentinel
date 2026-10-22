# Architecture Baseline (Phase 0)

**Status:** pre-production engineering baseline. Not a production-readiness claim.

Eighth Review F-numbers (review archived at archive/pre-cleanup) are tracked here and in
docs/REMEDIATION_MATRIX.md. Do not conflate them with docs/THREAT_MODEL.md F-numbers.

## Current architecture (verified against tree)

Hexagonal / clean architecture under sentinel/ (~68 modules), enforced by
tests_arch/test_architecture_rules.py:

    interface -> composition -> infrastructure -> application -> domain

Layers:
- domain/: lifecycle, fences, errors, authorization, protect decisions
- application/: commands, queries, saga engine, ports
- infrastructure/: SQL, attestation HTTP, detection policy, evidence
- composition/: sole wiring site
- interface/: HTTP/ASGI, worker, CLI

Deleted legacy tree: api/, app/, agents/, dashboard/ -- do not document as current.

## Target architecture (near-term)

Preserve the hexagonal core. Close Eighth Review F-1..F-12 with automated evidence.
Honest protect evaluate. Ungamed detection metrics gate. VCS + integrity discipline.
No fabricated AUC. No production-ready claim.

## Dependency graph (summary)

- Domain imports only stdlib + itself.
- Application depends on domain + Protocol ports.
- Infrastructure satisfies ports structurally; does not import handlers.
- Composition is the only package that may import every layer.
- Interface builds from a Container; importing a module starts nothing.

## Domain / state machine

- Pivot at attest (irreversible external anchor).
- COMPLETED_ATTESTED requires anchored outcome.
- COMPLETED_UNATTESTED for NOT_ANCHORABLE.
- ATTESTATION_UNAVAILABLE is non-terminal and resumable.
- Every mutator requires a Fence (no defaults).
- Resume hydrates evidence/report/approvals before any step handler.

## Actual API surface

- POST /v1/events (ingest_event)
- POST /v1/protect/evaluate (evaluate_protect)
- GET /v1/incidents ... (read_*)
- POST /v1/approvals/{id} (decide_approval)
- GET /health/live, /health/ready (unauthenticated, opaque)
- GET /health/diagnostics (read_diagnostics)

No HTML UI. No /ingest/*. No /simulation/start.

## Risks accepted at Phase 0

1. Detection efficacy: English independent soft path CLOSED (F-10); multilingual not claimed.
2. Protect enforced=true is a configured contractual gate, not packet interception.
3. Human passkey identity schema may still be WIP; directory SCIM Users + org
   HTTP APIs are behind `MANAGE_USERS` (agent enrolment remains CLI-only).
4. Not a SOC replacement; not multi-region HA.

## Strong components to preserve

Fail-closed attestation dispositions; Merkle/evidence with redaction tombstones;
required Fence; sharded SqlWorkQueue; FORCE RLS; LLM advisory-only; architecture
fitness tests; chaos/concurrency/mutation suites.

## Related docs

- sentinel/ARCHITECTURE.md -- enforced dependency rules
- docs/REMEDIATION_MATRIX.md -- F-1..F-12 status
- docs/THREAT_MODEL.md -- different F-numbering
- docs/ARCHITECTURE_DECISIONS.md
