# Delivery status: what is built, what is blocked, and why

This is the answer to "how much is done" in a form that can be checked. Every
row names the code and the test, so the claim and the evidence sit together.

The four evidence statuses are the ones the release gates use, strictly:
`PASS`, `FAIL`, `UNVERIFIED`, `NOT_APPLICABLE`. **Missing evidence is
`UNVERIFIED`, never `PASS`**, and a measurement from a different commit is
informative but satisfies nothing for the current build.

---

## Built and exercised

| Capability | Where | Tests | Status |
|---|---|---|---|
| Deterministic authorization; model output cannot reach a control path | `domain/authorization.py`, `records.ModelAdvice` | `test_security_prompt_injection.py` (16) | `PASS` |
| Execution passport, signed and independently verifiable | `domain/passport.py`, `standard/execution-passport-v1/` | `test_passport_standard.py` (24) | `PASS` |
| Transparency log — inclusion and consistency proofs | `domain/transparency.py` | `test_transparency.py` (43) | `PASS` (structure) |
| Transparency log — durable storage, append-only | `infrastructure/sql/transparency_store.py` | `test_transparency_store.py` (22) | `PASS` |
| Transparency log — roots and proofs over HTTP | `interface/transparency_routes.py` | `test_transparency_routes.py` (25) | `PASS` |
| Root sink contract, refusing by default | `domain/root_sink.py` | `test_root_sink.py` (14) | `PASS` |
| AI bill of materials, with a completeness verdict | `domain/ai_bom.py` | `test_ai_bom.py` (35) | `PASS` |
| Unified exposure graph, three-valued reachability | `domain/exposure_graph.py` | `test_exposure_graph.py` (34) | `PASS` |
| Least-privilege recommender, both directions | `domain/effective_permissions.py` | `test_effective_permissions.py` (26) | `PASS` |
| Skill detonation in a container | `infrastructure/detonation_container.py` | `test_container_detonation.py` (35) | `PASS` (containment) |
| Skill detonation with syscall tracing | `infrastructure/detonation_tracing.py` | `test_detonation_tracing.py` (30) | `PASS` |
| strace parser, built from captured traces | `infrastructure/strace_parse.py` | `test_strace_parse.py` (23) | `PASS` |
| Continuous red-team campaign with regression detection | `domain/attack_campaign.py`, `scripts/run_attack_campaign.py` | `test_attack_campaign.py` (43) | `PASS` |
| Remote SDK that cannot turn an outage into an allow | `sdk/remote.py` | `test_sdk_remote.py` (40) | `PASS` |
| GitHub Actions discovery connector | `infrastructure/platforms/github_discovery.py` | `test_github_discovery.py` (25) | `PASS` |
| Kubernetes and AWS IAM discovery connectors | `infrastructure/platforms/` | `test_connectors.py` | `PASS` |
| Adoption funnel, computed locally with no egress | `domain/adoption.py` | `test_adoption.py` (27) | `PASS` |
| Labelled sequence corpus | `evaluation/sequence_corpus.py` | `test_sequence_corpus.py` (26) | `PASS` (synthetic) |
| Five-minute local experience | `scripts/quickstart.py` | `test_quickstart.py` (9) | `PASS` |
| Analyst console, ten views | `interface/console/` | `test_console_bundle.py` (27) | `PASS` |
| Guard mutation testing | `scripts/verify_guards.py` | 26 mutations, all detected | `PASS` |

Everything above is reachable over HTTP or from the CLI. That is not a given:
five of these modules were written, tested and committed with **no callers at
all**, and `test_estate_routes.py` now drives the real app rather than calling
route functions, because a unit test of a handler passes for an unreachable
one too.

## Built, with the limit stated

| Capability | What works | What does not, and why |
|---|---|---|
| Transparency log | The structure, its proofs, durable append-only storage, and four read-only routes. Every response carries `independently_verifiable` | **No root has been published anywhere the operator cannot change it**, because no sink is configured. A log whose roots are only ever served by the party that writes it proves nothing about that party. `RefusingRootSink` is the default and raises — there is no local-file fallback, because a root on a disk the operator owns would set that flag True while proving nothing. It detects mistakes, partial restores and diverging replicas; it does not detect a determined operator |
| Skill detonation | Containment AND observation. Files read and written, connections attempted and processes spawned are now measured by tracing syscalls, verified against a live container run whose trace is committed as a fixture | Tracing costs `--cap-add=SYS_PTRACE`, a genuine widening, which is why it is a separate class rather than a default. `observation_incomplete` stays True: strace cannot see a payload decoded in memory, code evaluated from a string, or a package resolved from a cache, and flipping the flag would turn "we watched the syscalls" into "we watched everything". A container is **not** a virtual machine |
| Sequence detection | Ordered multi-step patterns, with vendor-synonym canonicalisation | A published false positive: a backup job matches `staged_exfiltration`, because object storage canonicalises to an external upload. Kept in the corpus as `known_gap` rather than deleted |
| AI-BOM over HTTP | Assembles from observed agent traffic | One source only, so the verdict is never `complete`, and the coverage names every source not consulted |
| Exposure graph over HTTP | Observed edges, derived credential sharing | Built from observed traffic, so every negative reachability answer is `unknown` rather than `not_reachable` |
| Disaster recovery | PITR works. RPO 12.77s, RTO 84.70s against 300s/1800s targets | The default WAL archive is on the same host and disk as the database, and the drill left `node_loss` null. Labelled `fail` in the readiness report |

## Not done, with the reason

| Area | Status | Why |
|---|---|---|
| AWS deployment (discovery, blast radius, JIT) | `UNVERIFIED` | Terraform written and `terraform validate` passes. **Deliberately not applied**: applying provisions billable resources, and the instruction for this work was setup only with no cost. No `plan` either, since that needs credentials |
| Third-party penetration test | `UNVERIFIED` | No external party has examined this system. `SECURITY.md` is the material a tester would need, not a report from one |
| Production soak / availability | `UNVERIFIED` | A 99.9%/30-day figure requires 30 days. `SOAK_RUNBOOK.md` describes the procedure that has not been run |
| Design-partner outcomes | `UNVERIFIED` | There are no design partners. No customer results, no time-to-value, no case studies. Generating any would be fabrication |
| Bedrock, Foundry, Copilot Studio, Entra, Vertex, OpenAI, Cursor connectors | `NEEDS SDK` | Each needs a vendor SDK, credential chain or inventory API this repository has no access to and no test surface for. Listed in `CONNECTOR_MATRIX.md` because the specification names them, **not** because they are planned |
| SOC 2 / ISO 27001 / ISO 42001 certification | `NOT_APPLICABLE` to a codebase | Those certify an organisation. Access reviews, onboarding, vendor management, IR drills and change-management approvals are organisational and none is in this repository. `COMPLIANCE.md` shows the technical subset an audit would sample |

## The two defects worth knowing about

Found while doing the above, and both are the same shape — a check that reads
something other than what it appears to read.

**A whole feature was dead.** `_assess_behaviour` was indented inside another
module-level function, *after that function's `return`*: unreachable, and never
attached to `AdmitEventHandler`. Baseline-deviation and declared-intent
assessment had therefore **never run**, and the call site's
`except Exception` logged it as a warning on every single event. mypy had been
reporting it the whole time — but the `type_check` gate ran only against
`sentinel/domain`, so nobody saw the line. Widening the gate to the whole
package surfaced 71 errors, now zero, including a CLI command that always
reported zero enrolled agents and a ports layer narrower than both its
implementations and its callers.

## Checking any of this

```bash
PYTHONPATH=. python scripts/run_release_gates.py
```

A gate that did not run produces **no artifact**, and absence is read as
`UNVERIFIED`. Artifacts carry a `.provenance.json` sidecar naming the commit
and source-tree digest; one that does not match the current tree is
`UNVERIFIED` by construction. If the tree changes mid-run the run voids itself
and deletes its own artifacts rather than leaving a mixed set.

```bash
PYTHONPATH=. python scripts/verify_guards.py
```

Breaks 26 properties one at a time and requires the guard covering each to
fail. A guard that stays green while its property is broken is reported as
`VACUOUS`, which has happened twice and both times was a real defect.

## Related

- [`RELEASE_READINESS.md`](RELEASE_READINESS.md) — the gate verdict
- [`CONNECTOR_MATRIX.md`](CONNECTOR_MATRIX.md) — all connectors, with real status
- [`COMPLIANCE.md`](COMPLIANCE.md#compliance_matrix) — mapping, which is not certification
- [`engineering/CURRENT_STATE_AUDIT.md`](engineering/CURRENT_STATE_AUDIT.md) — generated per capability
