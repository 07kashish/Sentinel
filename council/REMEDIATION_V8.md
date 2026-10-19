# Remediation — Eighth Pass (v8)

This pass began with the repository in a **broken mid-edit state**: two
load-bearing modules had been truncated to zero bytes, and six tests were red.
It records what was recovered and fixed, and — as the prior docs do — is honest
about what is genuinely already done versus what cannot be built inside this
repository.

Discipline unchanged: **prove the defect first, fix the root cause, lock it so
it cannot silently return.** No cosmetic changes; no suppression.

---

## 1. Data-loss recovery: two zero-byte modules

`api/pipeline.py` and `app/core/dlq.py` were both 0 bytes — truncated, not
refactored. The `.pyc` files had been recompiled after truncation, so nothing
was recoverable from bytecode, and this tree is not under git. The test suite
could not even collect (8 errors: `dlq has no attribute 'initialise'`).

Both were reconstructed from the contract the rest of the repository pins — 9
`dlq.*` call sites plus the `delivery_queue` schema, and the retry-taxonomy /
fencing / deterministic-authority / mutation tests for the pipeline.

### `app/core/dlq.py`

Rebuilt as an exclusive, tenant-scoped dead-letter queue. `claim_due()` pushes
`next_at` forward **in the same transaction that reads the row**, so two workers
cannot both take a message. `fail()` increments attempts and decides terminality
under one lock, so two concurrent failures cannot each grant an extra attempt.
`enqueue()` type-checks its arguments, because the defect that first motivated
this queue was an error string landing in `max_attempts`, making every retry
comparison meaningless. It owns no DDL — `initialise()` only validates the shared
schema, which `tests/test_schema_ownership.py` enforces.

### `api/pipeline.py` — resumable stage dispatcher (root-cause C-1)

Rebuilt as a **resumable stage dispatcher over durable state** rather than a
top-to-bottom script. Each stage declares the state it produces; the dispatcher
runs only stages whose output is not already durable, reading "where do I start"
from the incident's committed state. A retry therefore *resumes* instead of
replaying into an illegal backward transition — which is the root cause that
turned any transient error into permanent incident loss.

Two properties are structural, not optional:

- **No unfenced transition helper exists.** `Context.advance()` is the only way
  to change state and always threads `epoch`. A stage physically cannot make an
  unfenced write, so C-2 (the dropped completion fence) cannot recur at a new
  call site.
- **Every side effect goes through the repository outbox** (`store_evidence`,
  `store_report`, `store_approvals`, `ensure/claim/complete_attestation`), which
  commits the artifact and its state transition together. Attestation is
  claim → publish → record with an idempotency key, so a retry replays the
  receipt instead of double-anchoring an un-withdrawable external write (H-4).

Performance: the dispatcher tracks state in the `Context` from the one initial
read and each committed transition, costing **one SELECT per incident** rather
than one per stage. This is sound because the execution fence makes the worker
the single writer — if another worker takes the fence, the next write raises
`FenceLost` rather than returning stale state, so a re-read could not have
protected anything.

---

## 2. Real defects found while getting the suite green

### remote_signer rejected every valid signature (KMS path was dead)

`RemoteSigner.sign()` gated on `signature.startswith("0x")`, but the repo's own
`sign_digest` returns **bare** hex on the installed `hexbytes` version. The KMS
happy path could not accept a well-formed signature from its own signing
primitive, and the untrusted-key-substitution test never reached its trust
check because the format gate rejected it first.

Root cause: a **string-format proxy standing in for cryptographic validity**.
The proxy is both insufficient (a forged signature is also `0x`-prefixed) and,
here, wrong. Removed it; the real gate — recover the signer and compare to the
configured trust address — already existed one line below and is now the sole
arbiter. Fixed the misleading `sign_digest` docstring that caused the false
assumption. `tests/test_remote_signer.py` 6/6.

### Three silent exception swallows

`tests/test_failure_classes_are_structural` flagged three handlers that
swallowed without a trace — a SOC tool must never make a decision-not-to-act
invisible. Each fixed at its root, not blanket-suppressed:

- `app/core/config.py` — validated a hex contract address with `int(...,16)`
  inside `try/except ValueError`. Replaced with an explicit digit check that has
  **no failure mode to swallow**.
- `api/browser_auth.py` — a rejected session on a protected dashboard asset was
  discarded. It is now logged at debug: an expired cookie is benign and
  high-volume, but a *tampered* one now leaves a trace to correlate.
- `api/pipeline.py` — `_terminalise` swallowed the already-terminal case with a
  bare `pass`. Now logged: benign, but visible.

---

## 3. Three structural tests that had gone stale (invariants intact)

Each of these failed because code **moved**, not because a guarantee broke. In
every case the invariant was verified to still hold at the source before the
test was adjusted, and each updated test is still tight enough to fail if the
invariant regresses:

- **Row lock** (`test_repository_takes_a_row_lock_on_postgres`): the Postgres
  `FOR UPDATE` moved into `_locked_incident` when the fence was added. The lock
  still happens on the write path; the test now follows it into the helper.
- **Incident-scoped retention** (`test_retention_is_incident_scoped_not_per_table`):
  RLS threading inserted `tenant_id=? AND` into the WHERE clause, breaking a
  hard-coded substring. Retention still selects aged incidents and deletes each
  whole; the test now asserts that shape.
- **Report XSS** (`test_report_markdown_is_not_parsed_raw`): the dashboard
  dropped its markdown parser entirely and now renders the report as
  `esc()`-escaped plain text in a `<pre>` — strictly safer than the old
  `marked.parse(esc(...))`. The test now pins the new renderer's escaping.

---

## 4. Verified already-done (no work needed)

Auditing the surfaces the brief calls out, these are genuinely implemented and
sound — confirmed by reading the code, not by trusting a claim:

- **KMS/HSM signing** — `signing.py` prefers `configured_remote_signer()`; the
  in-process key is demo/test only and rejected in live mode. Private key
  material never enters the process on the production path.
- **Readiness vs liveness** — `/health` is liveness; `/health/ready` checks the
  database, repository, and maintenance-job health, returns 503 with
  structured-logged reasons. k8s and Helm probes are wired correctly.
- **Session security** — HMAC over the full payload (including `exp`),
  constant-time compare, expiry enforced, CSRF + OIDC state + nonce all
  constant-time verified. Secret comes from a mounted file shared across
  replicas; live mode rejects the env-var fallback and fails closed under 32
  bytes.
- **Observability** — structlog JSON logging, OpenTelemetry tracing, and a
  Prometheus endpoint are wired into `api/main.py`.
- **Outbox / fencing / RLS / leader election / durable queue** — present and
  test-covered.

---

## 5. Honestly out of scope for an in-repo change

These appear in the brief but cannot be truthfully "implemented" inside this
repository, because they are infrastructure, not code. The **seams** for them
already exist (a KMS gateway client, a broker-agnostic queue, OTLP export, a
service-mesh mTLS values contract), so adopting the real systems is
configuration rather than a rewrite — but claiming them done here would be the
exact "stale documentation" failure this codebase tests against:

- Kafka/NATS brokers, multi-region / multi-cluster topology, horizontal
  autoscaling under real load
- Grafana dashboards, a running OTLP collector, DAST against a deployed instance
- A physical HSM and real mTLS certificate rotation (the `remote_signer` client
  and Helm `serviceMesh.mtls` contract are the integration points)

---

## Status

Full non-live suite: **459 passed, 7 skipped, 0 failed.** Lint clean across
`app api agents evaluation sentinel_sdk tests`. App boots; detection gate exits
0. Live tests are memory-bound on this machine (each replica imports scipy);
they are unchanged by this pass.
