# Sentinel — product readiness

**Label: PRIVATE BETA.** Not `PRODUCTION GA`, and the reason is not a
shortfall in engineering — it is that four of the eight external gates cannot
be closed by anyone inside this repository, and the GA definition requires
them.

The numbers below are read from
[`readiness/GAP_LEDGER.md`](https://github.com/07kashish/Sentinel/blob/d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6/docs/readiness/GAP_LEDGER.md), which is generated and
refuses to cite a file that does not exist. A guard test compares this document
against it, so the two cannot drift.

---

## 1. Original score

**Not assessable.** The audit that produced the ledger is the first
machine-readable assessment of this codebase, so there is no earlier score to
compare against — only earlier documents that made claims. Recording a
"before" figure now would mean inventing one, and an invented baseline makes
every improvement look larger than it was.

What *can* be said about the starting point, from the audit itself:

- **Phase 3, authorization-to-execution binding, was MISSING.** The capability
  the product is named for. A grep for `ExecutionAuthorization`,
  `approved_parameter_digest` and `actual_parameter_digest` returned nothing.
- **Phase 15, AWS implementation, had one Terraform module of thirteen.**
- **Phase 28, release packaging, did not exist at all.**
- The rate limiter trusted an operator-declared shard count, so
  `uvicorn --workers 4` permitted four times the configured rate while every
  check reported healthy.

## 2. New score

Every figure below is asserted against `archive/pre-cleanup:release/gap_ledger.json` by
`tests_arch/test_readiness_doc_matches_ledger.py`, alongside the older
`tests_arch/test_product_readiness.py`. The newer guard exists because
the older one checked the mean, the dimension count and the zero-scored rows,
and nothing checked the status counts, the GA blocker count or the individual
dimension scores. So this section drifted exactly there: it read 28 COMPLETE /
10 PARTIAL / 10 GA blockers against a generated 30 / 8 / 9, and still listed
Endpoint discovery among the zeros long after it had moved to 7.0 — an extra
name in the zero row is invisible to a check that only asks whether the real
zeros are present.

A hand-maintained summary of a generated number will eventually flatter
itself. Nobody forgets to update a figure that got worse.

| | |
|---|---:|
| COMPLETE | 30 |
| PARTIAL | 8 |
| MISSING | 0 |
| EXTERNALLY-UNVERIFIED | 8 |
| **GA blockers** | **9** |

Unweighted mean across 26 dimensions: **8.1/10**.

**No dimension is scored 10**, and a test enforces that: a 10 requires
objective external evidence, and the eight open external gates *are* the
absence of it.

## 3. Evidence for each score

Per-dimension evidence and what would raise it is in the ledger's readiness
matrix. The distribution matters more than the mean:

| Score | Dimensions |
|---:|---|
| 9.5 | Core architecture, Authorization, MCP security, A2A security, Evidence and provenance, Transparency, Testing, Supply-chain security, Multi-tenancy |
| 9.0 | Security engineering, Release engineering, Container and Kubernetes, AWS architecture, External assurance readiness |
| 8.5 | Detection science, Integrations, Observability |
| 8.0 | Compliance evidence |
| 7.5 | Discovery, Admin UX, Reliability and DR |
| 7.0 | Endpoint discovery |
| 6.0 | AWS implementation |
| 5.0 | Performance, GTM readiness |
| **0** | **Customer validation** |

Customer validation is scored **0** rather than omitted. An absent row reads as
an oversight; a zero reads as a decision. It is not "in progress" or "early" —
there are no customers, and a discovery product with no user has learned
nothing about what operators actually do.

Two dimensions moved without code being written, which is worth stating because
it is the same mistake twice. **Integrations** went 6.5 → 8.5 when I found I had
recorded six existing SOAR connectors as absent from a grep that returned one
file. **Discovery** went 6.0 → 7.5 when connectors that were already written
were finally wired to a caller. Both had tests, ledger entries and audit trails
while being unreachable or miscounted — which is exactly why
`tests_arch/test_components_are_reachable.py` now carries the discovery and
detonation symbols.

The strongest single piece of evidence in the repository: a transparency root
is published to S3 Object Lock in COMPLIANCE mode, AWS confirmed the mode, and
**deletion was attempted and refused**. That is the only claim here tested
against a live adversarial action rather than a mock.

## 4. Remaining limitations

**The execution binding is real for parameters and single-use, and a
declaration comparison for everything else.** `execute_bound` passes the
verified parameter mapping into the tool, so what runs is what was checked. But
tool, action, resource and MCP server identity are what the *caller declares*,
compared against the authorization. A caller that both lies about them and
executes something else is not caught — an in-process wrapper cannot observe a
closure's syscalls. Full detail in
[`EXECUTION_TRUST_ARCHITECTURE.md`](EXECUTION_TRUST_ARCHITECTURE.md).

**Enforcement is opt-in and defaults off.** `SENTINEL_REQUIRE_EXECUTION_BINDING`
defaults `false` because enabling it stops any call site not yet migrated, and
a control that takes the service down on upgrade gets reverted rather than
adopted. Production refuses to start without an explicit answer either way.

**Nothing has ever been applied to AWS.** Terraform validates across three
environments; that proves coherence, not that it works.

**Delegation hops are now signed by each issuer**, so a verifier reconstructs the chain without trusting the control plane, and the chain digest is bound into the execution authorization.

**Four of seventeen priority connectors exist** (AWS, GitHub, Kubernetes,
PostgreSQL). Each remaining one needs a real tenant to test against.

**No endpoint sensor exists.** Deferred deliberately — it is worth less than
execution binding until enforcement is provable.

## 5. Remaining external validation

None of these closes by writing code. All eight stay open.

| Gate | What it needs |
|---|---|
| `INDEPENDENT_PENTEST` | a firm. Scope, threat model and test accounts are prepared |
| `PRODUCTION_SOAK` | 30 days of elapsed time against real traffic |
| `INDEPENDENT_FAILURE_DOMAIN_DR` | a cross-region exercise. In-domain RPO measured at 12.77s |
| `DESIGN_PARTNER_VALIDATION` | a design partner |
| `PRODUCTION_CUSTOMER_VALIDATION` | a customer in production |
| `MEASURED_AWS_UNIT_ECONOMICS` | an AWS bill. Every cost figure here is an estimate and labelled one |
| `REAL_WORLD_DETECTION_METRICS` | precision and recall outside a synthetic corpus |
| `REFERENCE_CUSTOMERS` | customers willing to be named |

## 6. Competitor parity

Where Sentinel is **behind**, honestly:

- **Connector breadth.** Four of seventeen priority platforms — AWS, GitHub,
  Kubernetes, PostgreSQL. This is where the incumbents are strongest and it is
  the most visible gap in an evaluation. Each remaining one needs a real
  tenant to test against.
- **Endpoint discovery depth.** A read-only configuration sensor exists and
  runs; competitors ship signed, remotely-attestable agents. Ours is a script.
- **Console UX.** Ten route modules with an API for everything, and no graph
  views — which is where an enterprise buyer forms a first impression.

**Removed from this list, and worth saying why:** *workflow integrations*
stood here until an audit error was corrected. All six connectors —
ServiceNow, Jira, PagerDuty, Slack, Teams, webhook — already existed with
per-destination injection escaping. The Phase 0 audit recorded them as absent
because a grep returned a single file and the count was read as meaning the
capability barely existed. That is exactly the inference the audit's own rule
forbids: never judge status by the presence or absence of a file.

Where it is **at parity**: MCP security, detection science, containment,
compliance mapping, multi-tenancy, Kubernetes hardening, workflow
integrations.

## 7. Where Sentinel is differentiated

The chain, not any single control:

**DISCOVER → IDENTIFY → AUTHORIZE → CONTROL → EXECUTE → PROVE → DETECT →
CONTAIN**

Three links are genuinely hard to reproduce:

1. **Authorization bound to execution.** An authorization commits to a
   domain-separated digest of canonicalised parameters; the digest is recomputed
   immediately before the side effect and the verified parameters are passed
   into the tool. Competitors largely observe and score.
2. **Portable evidence with two independent verifiers.** A published spec, 16
   conformance vectors whose malicious half is the point, and a dependency-free
   JavaScript verifier that agrees with the Python one offline. That second
   implementation found a real canonicalisation bug: Python accepted `2^53 + 1`,
   JavaScript refused it, and Python was wrong.
3. **Transparency anchored beyond the operator's reach.** COMPLIANCE-mode
   Object Lock, with a deletion attempt on record as refused.

`scripts/demo_execution_trust.py` walks all of it in one command and answers
**16 of the 18 questions**, marking the other two out of scope with the reason.

## 8. Blockers preventing PRODUCTION GA

The GA definition requires, among other things, an applied deployment, a
sustained soak, an independent DR exercise, zero unresolved high-severity
pentest findings and actual design-partner validation.

Engineering blockers, in the order to address them:

1. **Apply the AWS environment.** Everything downstream is behind it.
2. **Migrate call sites and default `SENTINEL_REQUIRE_EXECUTION_BINDING` on.**
   Until then the binding is available rather than enforced.
3. **Bind the wire-level MCP route.** It is a separate forwarding path that
   never touches `ProtectedToolRunner`, so it needs an authorization to travel
   with the JSON-RPC request.
4. **Turn on image signing** once a registry is chosen.

Then the four external gates that engineering cannot touch.

## 9. Recommended next engineering action

**Apply `deploy/terraform/aws/envs/dev`, then `pilot`.**

It is the lowest-scoring dimension, it unblocks four others (performance,
chaos at the infrastructure level, cross-region DR, measured cost), and the
work to get there is already done and validated. Order of operations is in
[`AWS_PRODUCTION_ARCHITECTURE.md`](AWS_PRODUCTION_ARCHITECTURE.md); apply
`identity/` first, because it is free and it retires the static access key.

## 10. Recommended next business action

**Start the soak clock, and engage a pentest firm.**

Those two close three gates and need money and patience rather than
engineering. The soak is the one gate nothing substitutes for and the only one
that gets cheaper the earlier it starts — in 30 days it is closed, and it will
never be closed sooner than 30 days after somebody begins.

Then find one design partner. Observe-only onboarding, progressive
enforcement, provisioning, metering, export and offboarding are all built and
waiting; what is missing is a partner, and code cannot create one.

---

## The prompt's named deliverables, and where they actually are

Twelve of the sixteen named documents exist under this repository's own names.
Creating renamed duplicates would satisfy a filename check and make the
documentation worse, so it has not been done.

| Named in the prompt | Actual file |
|---|---|
| `SENTINEL_PRODUCT_READINESS.md` | this document |
| `SECURITY_ARCHITECTURE.md` | [`SECURITY.md`](SECURITY.md), [`SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md) |
| `THREAT_MODEL.md` | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| `MCP_SECURITY.md` | [`MCP_GATEWAY.md`](MCP_GATEWAY.md) |
| `EXECUTION_TRUST_ARCHITECTURE.md` | [`EXECUTION_TRUST_ARCHITECTURE.md`](EXECUTION_TRUST_ARCHITECTURE.md) |
| `EXECUTION_PASSPORT_SPEC.md` | `../spec/execution-passport/README.md` |
| `AI_BOM_SPEC.md` | `sentinel/domain/ai_bom.py`, `sentinel.cdx.json` |
| `AGENT_IDENTITY_SPEC.md` | [`ENTERPRISE_CONTROLS.md`](ENTERPRISE_CONTROLS.md) |
| `ENTERPRISE_DISCOVERY.md` | [`CONNECTOR_MATRIX.md`](CONNECTOR_MATRIX.md) |
| `AWS_PRODUCTION_ARCHITECTURE.md` | [`AWS_PRODUCTION_ARCHITECTURE.md`](AWS_PRODUCTION_ARCHITECTURE.md) |
| `DR_RUNBOOK.md` | [`DR_RUNBOOK.md`](DR_RUNBOOK.md) |
| `PENTEST_READINESS.md` | [`PENTEST_PACKAGE.md`](PENTEST_PACKAGE.md) |
| `RELEASE_CHECKLIST.md` | [`RELEASE_GATES.md`](RELEASE_GATES.md) |
| `DESIGN_PARTNER_RUNBOOK.md` | [`DESIGN_PARTNER_RUNBOOK.md`](DESIGN_PARTNER_RUNBOOK.md) |

Machine-readable evidence lives under `docs/evidence/` and `release/`, each
artifact carrying a `.provenance.json` naming its commit and tree digest.
A missing sidecar yields `UNVERIFIED`, never `PASS`, and historical evidence
from another commit never satisfies the current gate.
