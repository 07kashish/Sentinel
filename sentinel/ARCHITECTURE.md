# Sentinel — Architecture

Hexagonal / Clean Architecture with DDD, CQRS, an event-driven core and explicit
constructor injection. Every rule below is enforced by
`tests_arch/test_architecture_rules.py`, which fails the build. None of it is a
convention.

## The dependency rule

```
                    ┌──────────────────────────────┐
                    │   interface  (layer 4)        │  http.py · worker.py · cli.py
                    │   delivery mechanisms         │
                    └───────────────┬──────────────┘
                                    │ consumes a wired container
                    ┌───────────────▼──────────────┐
                    │  composition  (layer 3)       │  container.py · settings.py
                    │  the ONLY place that wires    │
                    └───────────────┬──────────────┘
                                    │ constructs
        ┌───────────────────────────▼──────────────────────────┐
        │  infrastructure  (layer 2)                            │
        │  sql/ · attestation · identity · detection · evidence │
        │  implements ports structurally — imports no handler   │
        └───────────────────────────┬──────────────────────────┘
                                    │ satisfies
        ┌───────────────────────────▼──────────────────────────┐
        │  application  (layer 1)                               │
        │  ports (Protocols) · commands · queries · buses       │
        └───────────────────────────┬──────────────────────────┘
                                    │ orchestrates
        ┌───────────────────────────▼──────────────────────────┐
        │  domain  (layer 0)                                    │
        │  Incident aggregate · lifecycle · value objects       │
        │  stdlib only — no framework, no I/O, no clock         │
        └───────────────────────────────────────────────────────┘
```

A module may import its own layer and every layer below it. Importing outward is
a build failure. Nothing below the edge imports `sentinel.interface`, so changing
the transport is a local change.

## Enforced properties

| Requirement | Rule that enforces it |
|---|---|
| Every dependency points inward | `test_every_dependency_points_inward` |
| Business logic cannot depend on frameworks | `test_business_logic_never_imports_a_framework` |
| Domain is pure | `test_the_domain_imports_nothing_but_itself_and_the_standard_library` |
| No cyclic dependency | `test_there_are_no_cyclic_dependencies` |
| No global state | `test_there_is_no_mutable_module_level_state` |
| No hidden singleton | `test_no_module_declares_a_global_statement` |
| No static mutable state | `test_no_class_carries_mutable_class_level_state` |
| Every dependency injected | `test_every_application_collaborator_is_injected_through_the_constructor` |
| Every service replaceable | `test_every_port_is_a_protocol_not_a_base_class` |
| Independently testable | `test_every_module_is_importable_in_isolation` |
| No import-time side effects | `test_importing_any_module_has_no_side_effects` |
| One config parser | `test_only_the_settings_module_reads_the_environment` |
| No delivery coupling | `test_nothing_depends_on_the_delivery_mechanism` |

## Domain invariants with executable guards

These correspond one-to-one with Critical findings from the architecture review.
Each was previously asserted in a docstring and enforced by nothing.

| Invariant | Guard |
|---|---|
| No mutator can write unfenced | `test_no_incident_mutator_has_a_defaulted_fence` |
| A skippable stage must declare hydration | `test_no_skippable_pipeline_stage_can_omit_its_hydration` |
| `COMPLETED` requires a real anchor | `test_completed_states_require_a_matching_attestation_outcome` |
| A transient outage cannot complete | `test_attestation_unavailable_is_not_terminal` |
| No connection without a tenant | `test_the_unit_of_work_cannot_be_opened_without_a_tenant` |

## Ports

Every outbound capability is a `Protocol` in `application/ports.py`. Adapters
satisfy them structurally — nothing inherits, so infrastructure never imports the
application's handlers, which is what makes the dependency rule hold.

`Clock` · `IdGenerator` · `Logger` · `IncidentRepository` · `LedgerRepository` ·
`ApprovalRepository` · `OutboxRepository` · `UnitOfWork` · `UnitOfWorkFactory` ·
`ReadModel` · `WorkQueue` · `AttestationGateway` · `ModelAdvisor` ·
`IdentityVerifier` · `ReplayGuard` · `DetectionPolicy` · `EvidenceBuilder` ·
`ReportRenderer` · `RemediationPlanner` · `RemediationExecutor` ·
`AgentRegistry` · `EventPublisher`

## CQRS

**Commands** mutate through a unit of work and an aggregate; they return an
acknowledgement, never a projection. `AdmitEvent` · `ProcessIncident` ·
`DecideApproval` · `DispatchOutbox`

**Queries** never load an aggregate and take no locks; they read projections
through `ReadModel` with keyset pagination. `GetIncident` · `ListIncidents` ·
`GetIncidentHistory` · `GetReport` · `TenantDashboard`

## Event flow

The aggregate *collects* events; it never publishes. `UnitOfWork.commit()` writes
them to `domain_events` and the audit trail **inside the committing transaction**,
then publishes after the commit succeeds. An event describing a rolled-back change
cannot exist; a committed change cannot fail to produce its event.

The outbox has a real, separate dispatcher (`DispatchOutbox`, driven by
`MaintenanceLoop`), which reaps expired leases before claiming — so a deliverer
killed mid-flight returns its record to the queue instead of stranding it.

## Running

```bash
python -m sentinel.interface.cli migrate      # one-shot, never at startup
python -m sentinel.interface.cli verify       # O(1), safe at startup
python -m pytest tests_arch/ -q               # 109 tests, ~4s
python -m ruff check sentinel tests_arch
```

Serving requires building a container and handing it to a delivery mechanism:

```python
from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.interface.http import create_app
from sentinel.interface.worker import MaintenanceLoop, WorkerPool

container = build_container(Settings.from_environment())
app = create_app(container)
WorkerPool(container, size=4).start()
```

There is no module-level `app`. Importing any module starts nothing.

## Phase 0 baseline

See `docs/ARCHITECTURE.md` and `docs/REMEDIATION_MATRIX.md` for the Eighth Review F-1..F-12 status against this tree. Do not conflate with `docs/THREAT_MODEL.md` F-numbers.

## Protect gate (F-11)

`ProtectGate` (`application/protect_gate.py`) is the synchronous enforcement
helper agents can call before a tool side effect. The HTTP route
`POST /v1/protect/evaluate` uses the same object from the container.
`enforced=true` only when `SENTINEL_PROTECT_ENFORCE` is set and the decision
stops the action; `run_if_allowed` then skips the callback. This is not an
inline interceptor -- see `docs/REMEDIATION_MATRIX.md`.

## Protected tool runner (F-11)

In-process agents should call container.tool_runner.execute(...) before any
tool side effect. The runner always delegates to ProtectGate.run_if_allowed
and fail-closes when enforcement is on and evaluation fails. External agents
that never call the wrapper are outside this control -- see
docs/REMEDIATION_MATRIX.md.
