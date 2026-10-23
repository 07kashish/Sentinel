# Status

<a id="delivery_status"></a>
<a id="delivery_status--product-boundaries"></a>
## Product boundaries

<a id="delivery_status--built-with-the-limit-stated"></a>
### Built, with the limit stated

| Capability | What works | What does not, and why |
|---|---|---|
| Transparency log | The structure, its proofs, durable append-only storage, and four read-only routes. Every response carries `independently_verifiable` | **No root has been published anywhere the operator cannot change it**, because no sink is configured. A log whose roots are only ever served by the party that writes it proves nothing about that party. `RefusingRootSink` is the default and raises — there is no local-file fallback, because a root on a disk the operator owns would set that flag True while proving nothing. It detects mistakes, partial restores and diverging replicas; it does not detect a determined operator |
| Skill detonation | Containment AND observation. Files read and written, connections attempted and processes spawned are now measured by tracing syscalls, verified against a live container run whose trace is committed as a fixture | Tracing costs `--cap-add=SYS_PTRACE`, a genuine widening, which is why it is a separate class rather than a default. `observation_incomplete` stays True: strace cannot see a payload decoded in memory, code evaluated from a string, or a package resolved from a cache, and flipping the flag would turn "we watched the syscalls" into "we watched everything". A container is **not** a virtual machine |
| Sequence detection | Ordered multi-step patterns, with vendor-synonym canonicalisation | A published false positive: a backup job matches `staged_exfiltration`, because object storage canonicalises to an external upload. Kept in the corpus as `known_gap` rather than deleted |
| AI-BOM over HTTP | Assembles from observed agent traffic | One source only, so the verdict is never `complete`, and the coverage names every source not consulted |
| Exposure graph over HTTP | Observed edges, derived credential sharing | Built from observed traffic, so every negative reachability answer is `unknown` rather than `not_reachable` |


<a id="production_readiness_report"></a>
<a id="production_readiness_report--retention-limits"></a>
## Retention limits

9. **Incident and event history grows without bound UNTIL AN OPERATOR SETS A
   WINDOW, and that is now the whole of the risk.** As of 2026-08-18 the switch
   exists (`SENTINEL_INCIDENT_RETENTION_DAYS`) and the reaper behind it is tested
   on both engines. It is unset by default and therefore deletes nothing by
   default, which is deliberate: how long a SOC keeps incident records is a
   compliance decision with legal weight and no correct default. The residual is
   that a deployment which never sets it grows for ever — a decision an operator
   has to take, not a defect the code can remove.
   *Two things it deliberately does NOT bound, and they still grow with incident
   volume:* `evidence` (governed by the ledger's redaction path — body NULL,
   digest retained — because deleting the row would make chain verification fail
   rather than pass over a redaction) and `approvals` (deleting it would leave an
   executed remediation with no recorded approver). Both are declared in
   `APPEND_ONLY_TABLES` with those reasons; neither is an oversight, and neither
   is bounded. *Gate row: "Incident/event history retention policy" (pass).*

10. Reclaiming freed space is a second step the sweep does not take. On SQLite
    only `VACUUM` returns pages to the filesystem; on PostgreSQL the cheap path is
    dropping a partition, as `schema.py` describes. Neither runs automatically.


<a id="release_gates"></a>
<a id="release_gates--running-verification"></a>
## Running verification

<a id="release_gates--running-them"></a>
### Running them

```bash
python scripts/run_release_gates.py
```

The local runner lists gates including: `lint`, `type_check`, `unit_tests`,
`architecture_tests`, `security_tests`, `chaos_tests`, `migration_tests`,
`sast`, `dependency_scanning`, `secret_scanning`. The commands mirror
`.github/workflows/ci.yml`; where they differ, the difference is recorded in
each artifact's `command_rationale`.

```bash
python scripts/run_release_gates.py --list
```

Shows what will run and, for everything that will not, why. A gate that neither
runs nor appears in that second list would be one nobody decided about.

The PostgreSQL parametrisations are opt-in:

```bash
python scripts/run_release_gates.py --with-postgres
```

Off by default because the embedded server leaks a cluster per parametrisation
on Windows. Off and `UNVERIFIED` is honest; on and hung is not.

<a id="release_gates--two-rules-the-runner-will-not-bend"></a>
### Two rules the runner will not bend

**A gate that did not run gets no artifact.** Not a passing one, not a failing
one. If `gitleaks` is not installed, `secret_scanning` stays `UNVERIFIED`. That
is the correct statement about a check nobody performed, and writing a file
instead would convert *we did not look* into *we looked and it was fine*.

**A gate that ran and failed does get one.** If artifacts appeared only on
success, a red gate and an unrun gate would leave identical evidence
directories, and the report would say `UNVERIFIED` for a check that had gone
red. The verdict comes from the recorded `ok` field, compared against `is True`
— a runner that wrote `"ok": "failed"` would pass a truth test.

A timeout is recorded as a **failure**, not an absence. The gate ran; it did not
finish.

<a id="release_gates--source-changes-during-a-run"></a>
### Source changes during a run

If the source tree changes **while** the gates are running, the runner deletes
everything it wrote and exits `2`. Not `1`: the gates did not fail, the run is
void. Results that describe no single version of the code are not evidence.

<a id="release_gates--one-caveat-worth-knowing"></a>
#### One caveat worth knowing

`secret_scanning` runs `gitleaks git`, which reads **committed history**. Every
other gate reads the working tree. On a dirty tree those are different things, so
a secret-shaped line in an uncommitted file passes the gate and then fails the
next run as a history finding — needing an exception rather than an edit. Every
artifact records `working_tree_dirty`, and the runner says so once on the
console.
<a id="release_gates--proving-the-guards-are-real"></a>
### Proving the guards are real

```bash
python scripts/verify_guards.py
```

Every serious defect in this machinery was a check that read something other
than what it appeared to read, and therefore reported success no matter what.
Twenty-one gates that resolved to no filename. A test that scanned for `PASS`
and matched the prose promising the property. A console that rendered blank on
every tab while a check clicked all nine views and found text in each — because
`innerText` returns text from hidden elements.

All of them green. None found by reading the tests.

So this breaks each protected property on purpose and requires its guard to
**fail**. A guard that stays green while its property is broken is **vacuous**,
and the harness reports it as a defect.

The mutations are hand-written, and each is a defect that has already happened
here or is one careless edit away:

| Mutation | If the guard is vacuous |
|---|---|
| A console panel loses `class="view"` | The whole console renders blank, every tab |
| The pass-count regex accepts a zero | An all-skipped run reports PASS |
| A third route joins the throttle exemption | An ingest endpoint with no rate limit |
| The readiness cache is removed | An unauthenticated, unmetered database amplifier |
| A secret-allowlist entry is widened | The scanner says "no leaks found" and means nothing |

A **stale anchor counts as vacuous**, not as a skip: a mutation that no longer
applies is a guard that stopped being proven, and silence there is the failure
mode being guarded against.

<a id="release_gates--safety"></a>
#### Safety

It edits real source files, so it **refuses to run on a dirty tree** — on a
clean one `git checkout .` is a complete recovery at any moment. Every file is
snapshotted as exact bytes, restored in a `finally`, and the restoration
verified by digest; a failed restore aborts loudly with the recovery command
rather than continuing.

It runs as its own CI job for the same reason: a crashed run must not leave a
mutated tree for a later step to test and report on.

<a id="release_gates--invisible-characters"></a>
### Invisible characters

```bash
pytest -q tests_arch/test_source_hygiene.py
```

A shell heredoc once turned `\b` into a literal **backspace byte** inside a
regex. The pattern matched nothing, which would have failed every pytest gate,
and it read correctly in every editor. `cat -A` found it.

The check refuses C0 controls, zero-width characters and bidirectional
overrides. The last are the worst: they reorder how a line *displays* without
changing how it parses, so a reviewer and the interpreter read different code.

A file where an invisible character genuinely is the subject — the
whitespace-refusal fixtures, the zero-width evasion generator — opts out with a
marker **and a stated reason**, which a companion test enforces. Production code
under `sentinel/` may not claim it: two literals found there were rewritten as
escapes, which is clearer anyway, since the one thing a reader needs from
`_ZWSP` is which character it is.


<a id="release_readiness"></a>
<a id="release_readiness--release-evidence-and-external-assurance"></a>
## Release evidence and external assurance

<a id="release_readiness--the-four-states"></a>
### The four states

| State | Means |
|---|---|
| `PASSED` | evidence exists, is bound to this build, records success |
| `FAILED` | evidence exists, is bound to this build, records failure |
| `UNVERIFIED` | no evidence, or evidence belonging to another build |
| `NOT APPLICABLE` | a build is the wrong kind of thing to satisfy this |

`UNVERIFIED` is never assurance. It is the absence of it.

---

<a id="release_readiness--design_partner_validation"></a>
#### `design_partner_validation`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A real organisation running this against real traffic under a real agreement, completing the agreed validation. A commercial fact, not a technical one.
- **Owner:** founders / commercial

<a id="release_readiness--disaster_recovery_proof"></a>
#### `disaster_recovery_proof`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A recovery executed across an INDEPENDENT failure domain -- a second region or account -- with measured RPO and RTO. The domain has to exist before crossing it proves anything.
- **Owner:** SRE + cloud account owner

<a id="release_readiness--independent_pentest"></a>
#### `independent_pentest`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A scoped engagement by a firm with no stake in the result, followed by a remediation cycle and a RETEST of the findings. The retest is the part people skip and the part that matters: a report with open criticals is a to-do list, not assurance.
- **Owner:** security leadership + external firm

<a id="release_readiness--production_soak"></a>
#### `production_soak`

- **As a build gate:** NOT APPLICABLE
- **As assurance:** UNVERIFIED
- **What would satisfy it:** A continuous run against production-like traffic for the declared period, tracking event loss, memory growth, queue backlog and ledger integrity. THE ELAPSED TIME IS THE EVIDENCE. A harness that runs for an hour measures something else, and no amount of engineering compresses a thirty-day observation into an afternoon.
- **Owner:** SRE


<a id="sentinel_product_readiness"></a>
<a id="sentinel_product_readiness--remaining-product-limitations"></a>
## Remaining product limitations

<a id="sentinel_product_readiness--4-remaining-limitations"></a>
### 4. Remaining limitations

**The execution binding is real for parameters and single-use, and a
declaration comparison for everything else.** `execute_bound` passes the
verified parameter mapping into the tool, so what runs is what was checked. But
tool, action, resource and MCP server identity are what the *caller declares*,
compared against the authorization. A caller that both lies about them and
executes something else is not caught — an in-process wrapper cannot observe a
closure's syscalls. Full detail in
[`ARCHITECTURE.md`](ARCHITECTURE.md#execution_trust_architecture).

**Enforcement is opt-in and defaults off.** `SENTINEL_REQUIRE_EXECUTION_BINDING`
defaults `false` because enabling it stops any call site not yet migrated, and
a control that takes the service down on upgrade gets reverted rather than
adopted. Production refuses to start without an explicit answer either way.

**Delegation hops are now signed by each issuer**, so a verifier reconstructs the chain without trusting the control plane, and the chain digest is bound into the execution authorization.

**No endpoint sensor exists.** Deferred deliberately — it is worth less than
execution binding until enforcement is provable.

<a id="sentinel_product_readiness--5-remaining-external-validation"></a>
### 5. Remaining external validation

None of these closes by writing code. All eight stay open.

| Gate | What it needs |
|---|---|
| `INDEPENDENT_PENTEST` | a firm. Scope, threat model and test accounts are prepared |
| `PRODUCTION_SOAK` | 30 days of elapsed time against real traffic |
| `INDEPENDENT_FAILURE_DOMAIN_DR` | a cross-region exercise. |
| `DESIGN_PARTNER_VALIDATION` | a design partner |
| `PRODUCTION_CUSTOMER_VALIDATION` | a customer in production |
| `MEASURED_AWS_UNIT_ECONOMICS` | an AWS bill. Every cost figure here is an estimate and labelled one |
| `REAL_WORLD_DETECTION_METRICS` | precision and recall outside a synthetic corpus |
| `REFERENCE_CUSTOMERS` | customers willing to be named |


<a id="release_status"></a>
<a id="release_status--evidence-boundaries"></a>
## Evidence boundaries

<a id="release_status--what-this-document-will-not-say"></a>
### What this document will not say

It will not say *production-ready*, *market-leading*, *compliant*, *secure*, *superior to a named competitor*. Each of those needs evidence that does not exist in this repository at this commit. The tiers below are the evidence that does.


<a id="risk_register"></a>
<a id="risk_register--remaining-validation-requirements"></a>
## Remaining validation requirements

| ID | Severity | Concern | Closing evidence |
|---|---|---|---|
| R-001 | critical | No production deployment has observed any control | An accountable reviewer validates actual paid-pilot outcomes, environment, observation window and release identity; an unsigned JSON sidecar alone cannot close this gate. |
| R-002 | high | No independent security assessment | docs/current/evidence/external/pentest-<date>.pdf plus a remediation table in this register |
| R-003 | high | Cross-region disaster recovery is unproven | docs/current/evidence/dr/cross_region_<date>.json bound to a commit, restored row counts equal to source, ledger head verified |
| R-004 | high | The declared cloud topology has not been applied; one cloud host has | One run of the `pilot` sizing (multi-AZ, cache replica) on a paid-plan account with the same journey, plus a certificate on the listener |
| R-013 | high | Tenant policy activation and same-version rule changes escaped approval binding | Passing exact-release regressions, reviewed changes, artifact digest and recorded rollout. No external verification implied. |
| R-014 | high | Readiness tiers promoted collected tests and unsigned sidecars | Passing exact-release regressions, reviewed changes, artifact digest and recorded rollout. No external verification implied. |
| R-015 | high | Final image inherits unresolved high-severity OS advisories | The docker CI job passing the same gate on the release commit, the published image digest signed and verified, and a scheduled rescan with an owner for moving the base digest |
| R-016 | high | Workload identity is implemented but off by default and no customer issuer is integrated | A design partner running with SENTINEL_REQUIRE_WORKLOAD_IDENTITY=true against their issuer for the pilot window, including one issuer key rotation |
| R-017 | high | Bypass prevention is proven on two clusters and two network plugins, for Kubernetes only | The policy and the egress NetworkPolicy applied in a customer cluster on their CNI, with a recorded bypass attempt from an agent pod refused at both layers |
| R-018 | high | The transparency log was empty until migration 37 and is still not anchored outside the environment | A design partner's scheduled witness file covering the pilot window, and a drill in a second failure domain that verifies an old bundle against it (see R-003) |
| R-019 | high | Exact-release CI execution must be verified | A green workflow run on the release commit, with the release-hygiene and docker jobs included |
| R-005 | medium | Detection metrics are measured on a curated corpus only | docs/current/DETECTION_EVIDENCE.md with a sealed-corpus digest committed before the run and results bound to the commit |
| R-006 | medium | Fail-open exceptions are active by default in development | Removal of the development default for FCX-001 and per-tenant enforcement step in docs/current/FIRST_WORKFLOW.md observed on a design partner |
| R-007 | medium | Bounded OTLP export implemented; topology soak remains unverified | tests_arch test proving the buffer is bounded and the drop counter increments; observability soak artifact showing flat memory with the endpoint set |
| R-008 | medium | Metric cardinality repaired; multiprocess aggregation and soak unverified | Exact-release tests in tests_arch/test_observability_bounds.py, a real per-pod scrape and aggregation test, and bounded-memory soak on the declared topology. |
| R-009 | medium | Local cluster smoke passed; full production topology remains unverified | Exact-release deployment with verified CNI/TLS/identity/secret injection and fault tests on the declared supported topology; CI configuration checks alone do not close this risk. |
| R-011 | medium | Credential hygiene and owner-led rotation | Repository owner confirms investigation and any required rotation privately; artifact and history scans pass without disclosing values. |
| R-012 | medium | Automatic reconciliation covers Kubernetes, GitHub contents and brokered AWS; the rest needs a human | The reconcilers exercised against the real services used in a customer's first workflow, plus observed settlement times from a paid pilot in GET /v1/workflow/metrics |
| R-020 | medium | Throughput is measured on one machine with one service process | The same workload on the supported topology (multiple replicas, managed PostgreSQL, TLS) with the customer's expected concurrency, bound to the release commit |
| R-021 | medium | GitHub App constrained credentials have never met the real service | One recorded run of the GitHub App path against a test installation, bound to the release commit |
| R-022 | medium | MCP streaming relay has met no third-party server and has no concurrency measurement | A recorded run with streaming on against at least two independently implemented MCP servers, and a load measurement of concurrent streams per replica, bound to the release commit |
| R-010 | low | Packaged console repaired locally; release verification pending | Successful release-hygiene CI plus an exact wheel digest and the clean-install smoke report in the release evidence bundle. |

<a id="risk_register--r-001--no-production-deployment-has-observed-any-control"></a>
#### R-001 — No production deployment has observed any control

- **Description:** Repository tests and CI runs are local/CI evidence only. No real tenant or supported cloud deployment has exercised the declared workflow. Current release tiers require executed reports; collection does not establish a passed control.

- **Impact:** No claim of production readiness can be made. Latency, false-refusal and availability behaviour under real traffic is unknown.

- **Closes when:** An accountable reviewer validates actual paid-pilot outcomes, environment, observation window and release identity; an unsigned JSON sidecar alone cannot close this gate.

<a id="risk_register--r-002--no-independent-security-assessment"></a>
#### R-002 — No independent security assessment

- **Impact:** Customers in fintech infrastructure require a third-party report before enforcement mode.

- **Closes when:** docs/current/evidence/external/pentest-<date>.pdf plus a remediation table in this register

<a id="risk_register--r-003--cross-region-disaster-recovery-is-unproven"></a>
#### R-003 — Cross-region disaster recovery is unproven

- **Description:** PITR and WAL-archive restore drills exist and run against a local PostgreSQL (docs/dr_postgres_wal_pitr_drill.json). No drill has restored into an independent failure domain (second region or account).

- **Impact:** RTO/RPO figures are experimental; SLOs in docs/current/PRODUCTION_ACCEPTANCE.md cannot be signed.

- **Closes when:** docs/current/evidence/dr/cross_region_<date>.json bound to a commit, restored row counts equal to source, ledger head verified

<a id="risk_register--r-004--the-declared-cloud-topology-has-not-been-applied-one-cloud-host-has"></a>
#### R-004 — The declared cloud topology has not been applied; one cloud host has

- **Description:** The declared AWS stack was applied on 2026-09-24/25 as the `proof` environment (same module, free-tier sizes) and the protected-change journey ran over its load balancer: managed PostgreSQL, managed Valkey, ALB, S3 with KMS and object lock, Secrets Manager injection, IAM task and execution roles, two Fargate tasks in two availability zones. Sixteen defects were found by that first apply and fixed (RELEASE_CHANGES, 2026-09-24/25). What remains unproven is the paid sizing: multi-AZ database, a cache replica, and therefore AZ-loss survival; TLS needs a domain; workload identity on ECS needs an identity provider.

- **Impact:** The single-AZ proof says nothing about an AZ loss; a design partner on the pilot sizing would be the first to observe it.

- **Closes when:** One run of the `pilot` sizing (multi-AZ, cache replica) on a paid-plan account with the same journey, plus a certificate on the listener

<a id="risk_register--r-013--tenant-policy-activation-and-same-version-rule-changes-escaped-approval-binding"></a>
#### R-013 — Tenant policy activation and same-version rule changes escaped approval binding

- **Description:** The gate ignored active tenant rules and the binding only identified a version label.

- **Impact:** An authorization could be issued despite tenant deny or survive a rule-content change.

- **Closes when:** Passing exact-release regressions, reviewed changes, artifact digest and recorded rollout. No external verification implied.

<a id="risk_register--r-014--readiness-tiers-promoted-collected-tests-and-unsigned-sidecars"></a>
#### R-014 — Readiness tiers promoted collected tests and unsigned sidecars

- **Description:** Presence of tests, workflow names and files was confused with executed and independent evidence.

- **Impact:** Customers could rely on unsupported readiness assertions.

- **Closes when:** Passing exact-release regressions, reviewed changes, artifact digest and recorded rollout. No external verification implied.

<a id="risk_register--r-015--final-image-inherits-unresolved-high-severity-os-advisories"></a>
#### R-015 — Final image inherits unresolved high-severity OS advisories

- **Description:** The Debian-based image carried 44 HIGH findings with no fixed version. The runtime moved to a digest-pinned Wolfi base with Python 3.12 and libstdc++ only; dependencies are installed with --require-hashes into a virtualenv in the builder, so the runtime has no pip, compiler or package cache. On 2026-09-20 a local build served /health/ready as uid 10001 after migrating to schema 37, and Trivy (vuln, secret, misconfig; HIGH,CRITICAL) reported 0 findings, judged PASS by scripts/build_and_scan_image.py. This is one local scan on one date. CI has not run it, no image has been published or signed, and a base pinned by digest stops receiving fixes until it is moved.

- **Impact:** The vulnerability release gate is not satisfied; no production release is authorized by the local functional tests.

- **Closes when:** The docker CI job passing the same gate on the release commit, the published image digest signed and verified, and a scheduled rescan with an owner for moving the base digest

<a id="risk_register--r-016--workload-identity-is-implemented-but-off-by-default-and-no-customer-issuer-is-integrated"></a>
#### R-016 — Workload identity is implemented but off by default and no customer issuer is integrated

- **Description:** SPIFFE JWT-SVIDs and pod-bound Kubernetes tokens are verified, and SENTINEL_REQUIRE_WORKLOAD_IDENTITY refuses API keys on the agent path. Keys may be pinned or fetched from a stated https jwks_uri: refreshed on a schedule and, rate-limited, when an unseen key id appears; a failed or hostile response keeps the last good keys. A projected pod-bound token from a real agent pod was accepted by deployed Sentinel pods on a local cluster. OIDC discovery is supported (the document must name exactly the registered issuer), which is how SPIRE's OIDC Discovery Provider, Okta and Entra are consumed. Tenants first seen in a verified human sign-in are now enrolled. Still missing: a SPIRE Workload API client, a Kubernetes API server JWKS fetch (needs a credential and the cluster CA), and any customer issuer. The default is false (DECISION_LOG FCX-006).

- **Impact:** Until a deployment turns the requirement on, any holder of a tenant API key can name any agent.

- **Closes when:** A design partner running with SENTINEL_REQUIRE_WORKLOAD_IDENTITY=true against their issuer for the pilot window, including one issuer key rotation

<a id="risk_register--r-017--bypass-prevention-is-proven-on-two-clusters-and-two-network-plugins-for-kubernetes-only"></a>
#### R-017 — Bypass prevention is proven on two clusters and two network plugins, for Kubernetes only

- **Description:** deploy/protected-changes ships a ValidatingAdmissionPolicy (failurePolicy Fail, Kubernetes 1.30 or later) that refuses writes by agent service accounts and unstamped writes or deletes by the executor. Deletes are now stamped on the object before deletion, closing the earlier DELETE exemption. scripts/run_deployed_journey.py showed, on a one-node local cluster with kindnet, the API server refusing both bypass attempts and the CNI blocking an agent pod from the API server and the internet. Human users and other controllers are out of scope by design. Nothing equivalent exists for AWS, GitHub or databases, and no other CNI or cloud cluster was exercised. AWS and GitHub now have per-operation constrained credentials (a fifteen-minute role session; a per-call App installation token scoped to one repository and permission family) but no target-side control that refuses changes made around Sentinel, and those paths are tested against fakes only. The deployed journey now runs over TLS under a private CA; mutual TLS and rotation are not exercised. The same refusals held on AWS under k3s with flannel and kube-router on 2026-09-20.

- **Impact:** In a cluster without the policy applied, or for a non-Kubernetes target, an agent holding a write credential can act without Sentinel and Sentinel's evidence is true and incomplete.

- **Closes when:** The policy and the egress NetworkPolicy applied in a customer cluster on their CNI, with a recorded bypass attempt from an agent pod refused at both layers

<a id="risk_register--r-018--the-transparency-log-was-empty-until-migration-37-and-is-still-not-anchored-outside-the-environment"></a>
#### R-018 — The transparency log was empty until migration 37 and is still not anchored outside the environment

- **Description:** Before 2026-09-20 nothing in the running service appended to the transparency log. Receipts are now committed by the maintenance loop and export as a bundle that verifies offline. standard/execution-passport-v1/witness_root.py lets a customer record roots on a machine the operator does not control, verifying locally that each root is a consistent extension of the last; tests show it refusing a rewritten and a truncated log, and a drill restores evidence into a new database and verifies an old bundle against the customer-held root. What is missing is a customer actually running the witness, and publication to an object-lock sink in a second failure domain. Evidence bodies are now sealed per record when a data key is configured, and production refuses to start without a key or an explicit opt-out; keys come from the environment or a Kubernetes secret rather than a KMS, and key loss loses bodies (never digests or proofs).

- **Impact:** An operator who controls the database can still rewrite the whole log undetected unless the customer holds earlier roots.

- **Closes when:** A design partner's scheduled witness file covering the pilot window, and a drill in a second failure domain that verifies an old bundle against it (see R-003)

- **Description:** Every job of the last two workflow runs failed before starting with the hosting provider's message that account payments failed or the spending limit must be raised, and later commits carry a skip marker. All evidence since is from one development machine.

- **Impact:** No change since then has been built, scanned or tested by anything other than its author's machine; the release-hygiene job has never run.

- **Closes when:** A green workflow run on the release commit, with the release-hygiene and docker jobs included

<a id="risk_register--r-005--detection-metrics-are-measured-on-a-curated-corpus-only"></a>
#### R-005 — Detection metrics are measured on a curated corpus only

- **Description:** evaluation/metrics.json is reproducible but not blind: the corpus was assembled by the people tuning the detector. Real-world precision and recall are unknown.

- **Impact:** Detection claims must carry the corpus, date and limitations; no headline number may be published.

- **Closes when:** docs/current/DETECTION_EVIDENCE.md with a sealed-corpus digest committed before the run and results bound to the commit

<a id="risk_register--r-006--fail-open-exceptions-are-active-by-default-in-development"></a>
#### R-006 — Fail-open exceptions are active by default in development

- **Description:** Five documented exceptions (docs/current/DECISION_LOG.md FCX-001..005). Production refuses to start unless the limiter fail-open and execution-binding choices are explicit; observe mode and advisory protect are defaults for new tenants.

- **Impact:** A tenant that never moves to enforce believes it is protected while every decision is advisory. The /v1/coverage model reports this rather than a score.

- **Closes when:** Removal of the development default for FCX-001 and per-tenant enforcement step in docs/current/FIRST_WORKFLOW.md observed on a design partner

<a id="risk_register--r-007--bounded-otlp-export-implemented-topology-soak-remains-unverified"></a>
#### R-007 — Bounded OTLP export implemented; topology soak remains unverified

- **Description:** The unbounded event history has been removed. Standard OpenTelemetry protobuf export uses a bounded 256-span queue, batches of 32, fixed redacted attributes and explicit delivery/drop counters. Local HTTP, partial acknowledgement, outage, saturation and shutdown tests pass.

- **Impact:** Memory exhaustion in exactly the deployments that turned tracing on.

- **Closes when:** tests_arch test proving the buffer is bounded and the drop counter increments; observability soak artifact showing flat memory with the endpoint set

<a id="risk_register--r-008--metric-cardinality-repaired-multiprocess-aggregation-and-soak-unverified"></a>
#### R-008 — Metric cardinality repaired; multiprocess aggregation and soak unverified

- **Description:** HTTP metrics use matched route templates and a fixed unmatched bucket. The registry bounds series globally, excludes tenant/agent labels, escapes values, serializes concurrent updates and emits cumulative duration buckets. Registry state remains process-local.

- **Impact:** Prometheus cardinality grows with traffic; the /metrics response grows without bound in the same process.

- **Closes when:** Exact-release tests in tests_arch/test_observability_bounds.py, a real per-pod scrape and aggregation test, and bounded-memory soak on the declared topology.

<a id="risk_register--r-009--local-cluster-smoke-passed-full-production-topology-remains-unverified"></a>
#### R-009 — Local cluster smoke passed; full production topology remains unverified

- **Description:** Removed unused signer/RLS/replica/nonce and proxy settings; chart/raw manifests now require binding, enable enforcement, inject shared Redis and permit its network path. A static alignment check reports zero problems, real settings-parser tests pass and Helm strict lint passes. On 2026-09-20 deploying to a cluster exposed two defects that no test had: the Kubernetes tool could not reach a private API server or trust the cluster CA (fixed with a client scoped to that one host and SENTINEL_KUBERNETES_CA_FILE), and no code path ever wrote a row to the tenants table, so the maintenance loop swept no tenant in a real deployment (fixed by enrolling configured tenants at startup). Tenants that appear only in human OIDC claims are still not enrolled.

- **Impact:** An operator setting a variable to change a control changes nothing and believes it changed.

- **Closes when:** Exact-release deployment with verified CNI/TLS/identity/secret injection and fault tests on the declared supported topology; CI configuration checks alone do not close this risk.

- **Description:** Earlier audit reported an ignored local dotenv file containing credential-shaped material. This continuation did not read or use its contents. Current redacted history scanning is a pattern-based check with narrowly scoped exceptions, not proof that no secret was ever exposed.

- **Impact:** If live, the values are exposed to anyone with access to that machine.

- **Closes when:** Repository owner confirms investigation and any required rotation privately; artifact and history scans pass without disclosing values.

<a id="risk_register--r-012--automatic-reconciliation-covers-kubernetes-github-contents-and-brokered-aws-the-rest-needs-a-human"></a>
#### R-012 — Automatic reconciliation covers Kubernetes, GitHub contents and brokered AWS; the rest needs a human

- **Description:** A definitive 4xx from the target is now a recorded FAILED operation, not an unknown one. A lost response or 5xx stays unknown, and for the Kubernetes tool the maintenance loop asks the target: this operation's field manager present means succeeded, the approved resourceVersion unchanged after a 120-second quiescence window means failed, anything else stays unknown. It never writes, needs evidence for every verdict and stops after SENTINEL_RECONCILE_MAX_ATTEMPTS. Proven against a fake API at every boundary and against a real local Kubernetes 1.37 API server. Other tools (AWS, GitHub, PostgreSQL, HTTP) have no reconciler and still need a human. Deletes are settled by end state and the deleting actor is not attributed. On 2026-09-20 GitHub contents writes and deletes gained a reconciler based on the git blob sha (not attributed), GitHub and AWS 4xx responses stopped being recorded as succeeded operations, and the read-only SQL adapter can no longer leave an unknown outcome. GitHub POSTs, other GitHub PUTs and every AWS mutation still need a human. Later on 2026-09-20 AWS operations run under a brokered role session gained a CloudTrail reconciler keyed on the session name: an event without an errorCode is succeeded, with one is failed, and no event stays unknown because delivery lags and only management events are recorded. It is tested against a fake only; it has never queried a real CloudTrail.

- **Impact:** A remote change can succeed despite a timeout. Operators must reconcile against the target before retrying; a consumed authorization does not prove the remote effect occurred exactly once.

- **Closes when:** The reconcilers exercised against the real services used in a customer's first workflow, plus observed settlement times from a paid pilot in GET /v1/workflow/metrics

<a id="risk_register--r-020--throughput-is-measured-on-one-machine-with-one-service-process"></a>
#### R-020 — Throughput is measured on one machine with one service process

- **Description:** scripts/run_workflow_loadtest.py drives evaluate plus bound execute against a real uvicorn process and PostgreSQL with a no-op tool. On 2026-09-20 on an arm64 macOS laptop it completed 2,000 changes with no failure at about 175 changes per second with 16 concurrent clients (evaluate p95 42 ms, execute p95 67 ms). Client, service and database shared the machine; there was no network, no TLS, one process and no replica contention, and rate limits were raised so they would not shape the result.

- **Impact:** No sizing or capacity statement can be made to a customer; the figure is a regression baseline.

- **Closes when:** The same workload on the supported topology (multiple replicas, managed PostgreSQL, TLS) with the customer's expected concurrency, bound to the release commit

<a id="risk_register--r-021--github-app-constrained-credentials-have-never-met-the-real-service"></a>
#### R-021 — GitHub App constrained credentials have never met the real service

- **Description:** AWS half CLOSED on 2026-09-25: a real AssumeRole per operation under the operation's session name, the operation signed with the temporary credential, and CloudTrail LookupEvents settling the outcome (archive/pre-cleanup:scripts/run_aws_sts_proof.py; two signer defects found and fixed on the way: NAT64 addresses and the us-east-1 scope of global endpoints). GitHub half OPEN: the App assertion and scoped installation-token request have still met only fakes.

- **Impact:** The first real use may be refused by the vendor, or a CloudTrail lookup may never match and leave every AWS unknown outcome for a human. A refusal is a known absence, so the failure is safe; it is not useful.

- **Closes when:** One recorded run of the GitHub App path against a test installation, bound to the release commit

<a id="risk_register--r-022--mcp-streaming-relay-has-met-no-third-party-server-and-has-no-concurrency-measurement"></a>
#### R-022 — MCP streaming relay has met no third-party server and has no concurrency measurement

- **Description:** Guarded incremental relay of MCP notifications is implemented and tested against scripted upstreams only. No third-party MCP server has been proxied with streaming on. Each streamed call holds one worker thread for its duration (up to 120 s), and no measurement exists of how many concurrent streams a replica sustains. Servers that depend on sampling, elicitation or the standalone GET stream do not work through the proxy, by design.

- **Impact:** A real server's event framing or notification shapes may be dropped rather than relayed, which is safe but not useful; many long streams could exhaust the worker pool of a replica that enables the setting.

- **Closes when:** A recorded run with streaming on against at least two independently implemented MCP servers, and a load measurement of concurrent streams per replica, bound to the release commit

<a id="risk_register--r-010--packaged-console-repaired-locally-release-verification-pending"></a>
#### R-010 — Packaged console repaired locally; release verification pending

- **Description:** The wheel now explicitly includes the default policy and three advertised console assets. A fresh Python 3.13 installation served these over localhost HTTP.

- **Impact:** Pip-installed operators can load the console. CI on the exact release and signed distribution remain required.

- **Closes when:** Successful release-hygiene CI plus an exact wheel digest and the clean-install smoke report in the release evidence bundle.
