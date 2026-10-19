# Remediation â€” Seventh Board (v7)

Status of the ten findings in `COUNCIL_REPORT.md` Â§6. The report itself is left
unedited: it is a point-in-time artifact, and rewriting it to look better after
the fact is exactly the failure it criticises elsewhere.

Every fix below follows the same discipline the codebase already uses: **prove
the defect RED first**, fix it, then lock it so it cannot come back silently.

| ID | Finding | Status | Guard |
|---|---|---|---|
| C-4 | K8s egress denies Postgres | **Closed** | `tests/test_deployment_manifests.py` â€” strict parse + egress assertions |
| C-2 | Fence dropped at `COMPLETED` | **Closed** | mid-flight steal probe + AST call-site guard |
| H-1 | Concurrent seal race | **Closed** | atomic claim + `BatchAlreadySealed`, mutation-locked |
| H-2 | OIDC tenant collapse to `"default"` | **Closed** | fail-closed `tenant_from_claims`, 401 path pinned |
| M-1 | Protect mode `block` unreachable | **Closed** | identity verified; thresholds named and compared |
| M-2 | Redaction tombstone overwritable | **Closed** | `EvidenceRedacted`, mutation-locked |
| C-1 | Retry non-resumable | **Closed** | `tests/test_pipeline_retry_taxonomy.py` â€” mandatory-stage outage propagates to queue retry/DLQ |
| C-3 | Authenticated relabelling | **Closed** | `tests/test_evidence_provenance.py` â€” v2 identity-bound manifests + trusted signer verification |
| H-3 | Dashboard cannot authenticate | **Closed** | `tests/test_browser_auth.py` â€” OIDC PKCE session, CSRF, private dashboard assets |
| H-4 | Side effects precede fenced transition | **Closed** | `tests/test_execution_fencing.py` â€” fenced artifact commits + attestation outbox |

---

## What was fixed, and why each fix is shaped the way it is

### C-4 Â· Kubernetes egress (RICE #1 â€” half a day, total outage)

A duplicate `ports:` key meant YAML last-key-wins kept the removed Redis `6379`
and discarded PostgreSQL `5432`. Under the file's own default-deny policy, no
pod could reach its database.

Nothing in the suite had ever loaded a YAML file, so the entire deployment
surface was untested. The new tests parse every shipped manifest **the way
kubectl does** â€” rejecting duplicate keys rather than silently taking the last â€”
and then assert the policy permits the database and no longer permits removed
services.

One test deliberately guards the others: `test_postgres_rule_targets_the_postgres_pod`
stops a future "fix" that appends a bare `- ports: [5432]` rule, which would
satisfy "5432 is allowed" while punching a hole to every destination.

### C-2 Â· The execution fence at the finish line

Every intermediate transition threaded `epoch=lease_epoch` through a local
`advance()` helper. The final `COMPLETED` transition called
`repository.transition(...)` directly and omitted it, so a worker whose lease
was stolen mid-flight was refused at every step *except the last one*.

Existing fencing tests all stole the lease **before** `process()` ran, so the
stale worker aborted at its first `advance()` and never reached the defect. The
new probe steals the lease **during** `publish_attestation` â€” the last call
before completion â€” which is the only window that exposes it.

The fix routes the transition through `advance()`. The more important addition
is the structural guard: an AST walk over `process()` that fails if
`repository.transition` is ever called there without `epoch=`. That guard has
its own mutation test, because a structural test that never really inspects
anything is the substring-assertion theatre this codebase already removed once.

**This finding is why the mutation harness needed extending.** The harness
deletes a guard and checks a probe goes red â€” it proves guards are load-bearing
*when invoked*. It cannot see a call site that never invokes one. Guard
*presence* was covered; guard *coverage* was not.

### H-1 Â· Two sealers, one set of leaves

`ledger.seal()` reads the unsealed entries, computes a Merkle root and **signs
it**, all before `db.seal_batch()` claims those rows â€” and the claim was an
unconditional `UPDATE ... SET batch_id=?` with no rowcount check. Two sealers
racing therefore produced two signed roots over the same leaves, the second
silently stealing the first's rows and leaving a signed batch describing
nothing.

This is the same read-compute-write shape already closed one level down for
ledger *append*; it survived up here because the read lives in a different
module. The claim now requires `batch_id IS NULL` and refuses unless it claims
exactly what the caller signed over.

The partial-overlap case is tested separately and is the one that matters: if
the transaction did not roll back, a refused seal would strand a leaf pointing
at a batch that was never inserted â€” worse than the original race.

### H-2 Â· Fail-open tenancy

`tenant_from_claims` ended `or "default"`, so a valid token from a misconfigured
issuer landed in a shared tenant. With RLS off by default, application
predicates are the *entire* isolation boundary, and a boundary with a fallback
is not a boundary.

**The fix nearly introduced a worse bug.** `tenant_from_claims` was called
during principal construction *outside* the `OidcError` handler, so making it
raise would have turned a silent isolation failure into a 500 on every token
from a misconfigured issuer â€” a stack trace instead of `WWW-Authenticate`. Claim
extraction now sits inside the guarded block, and a test pins that the response
is 401.

### M-1 Â· A documented state that could never happen

`protect_evaluate` hardcoded `trust_level="unsigned"`. Unsigned severity is
capped at 79; `block` requires â‰¥ 85. The strongest of four documented states was
arithmetically unreachable, and a correctly signed high-risk action got the same
answer as an anonymous one.

The fix **verifies identity** rather than lowering the threshold. Lowering it
would let an unverified claim trigger a block â€” handing a denial-of-service
primitive to anyone who can forge a request, which inverts the guarantee the cap
exists to provide. `block` deliberately stays above the cap so only a VERIFIED
event can reach it.

The two thresholds and the cap now live as named constants with an assertion
tying them together, because as bare literals in two different files nothing
noticed they contradicted each other for an entire release.

### M-2 Â· Erasure that undid itself

`save_evidence` upserted `content_json` with no tombstone check, so any later
write â€” a retry, a stale worker, a replayed job â€” restored content destroyed
under a GDPR or CSAM obligation while `redacted_at` kept asserting it was gone.

It now raises `EvidenceRedacted` rather than no-op'ing: a silent skip would
leave the caller believing it had stored evidence it had not. The check and the
write share one transaction, so the check-then-act window this codebase has
repeatedly had to close is not reopened here.

---

## Final pass closures

### C-1 Â· Retry lifecycle and resumable execution

`api/pipeline.py` is now a resumable stage dispatcher rather than a top-to-bottom
script. Each stage declares the state it produces; on retry, the dispatcher reads
the durable incident state and skips work whose output has already been committed.
Mandatory infrastructure failures propagate as `RetryablePipelineError`, so the
durable queue owns retry and DLQ exhaustion. Deterministic lifecycle/policy
failures still terminalise the incident as `FAILED`, because retrying them cannot
change the answer.

The root cause was stage progress being implicit in call order. Progress is now
owned by the lifecycle state machine and repository commits, making restart
position a database fact rather than a convention.

### C-3 Â· Authenticated provenance and relabelling resistance

Evidence packages are exported as `sentinel-evidence-package/v2`. The ledger leaf
is computed from an evidence manifest binding `tenant_id`, `incident_id`, and the
evidence body hash, so relabelling a valid body onto a different incident changes
the committed leaf. Sealed batches carry signed batch manifests, and
`verify_package()` fails closed unless the verifier supplies a trusted signer out
of band.

The root cause was verification of self-consistency rather than provenance.
Verification now requires both identity-bound evidence commitments and an
external trust root.

### H-3 Â· Authenticated analyst dashboard

The dashboard is private same-origin UI. Browsers authenticate through OIDC
Authorization Code + PKCE, receive an opaque HttpOnly session cookie, and never
store bearer tokens in JavaScript. Mutations require a signed CSRF secret from
`/auth/session`; dashboard assets redirect unauthenticated users to `/auth/login`.
All dashboard fetches funnel through one credentialed transport.

The root cause was a static console trying to call protected APIs with no browser
principal model. The console now uses the same RBAC dependency as machine clients
through a minimal signed browser session.

### H-4 Â· Fenced side effects and transactional outbox

Evidence storage, ledger append, report storage, approval creation, and lifecycle
transition are now repository-owned operations that run under the execution
epoch. External attestation uses an idempotent outbox: intent is durable before
delivery, delivery is claimed under the incident fence, and the receipt plus
state transition commit together.

The root cause was side effects performed after an ownership read but before the
fenced transition. Side effects now either share the transition transaction or
are represented as durable outbox intents before they can occur.

## Remaining external work

The repository now contains engineering controls for the v7 findings. Production
certification still depends on external systems and evidence that cannot be
manufactured inside this codebase: customer-controlled KMS/HSM deployment,
organization-specific OIDC setup, live PostgreSQL RLS validation in the target
cluster, independent cryptographic review, SOC2/ISO control operation, and real
design-partner traffic for detector calibration.

None of this changes the board's verdict. The fixes above close six defects,
including one guaranteed outage â€” they do not create a customer, a detector, or
a distribution channel, which is what Â§18 says the score actually depends on.

