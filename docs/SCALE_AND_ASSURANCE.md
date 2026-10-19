# Scale and assurance

Phase 6: sections 60 (performance testing), 61 (chaos testing), 62 (disaster
recovery) and 76 (red teaming).

This phase is different from the others: most of it is **proof about work
already done** rather than new capability. That makes the honesty rules matter
more than the code, because the failure mode here is not a bug — it is a
confident number that nobody can reproduce.

---

## 1. Red teaming (§76)

> Each release should be attacked. Track: attack / expected detection /
> expected prevention / actual result / regression.

`tests_arch/test_red_team_suite.py` is that table, executed. Each case drives
the **real HTTP surface against a real container** — not the components.

That distinction is the reason it exists. Phase 4 shipped five correct
components of which four were unreachable, and every unit test passed
throughout. **An attacker does not call your functions directly.**

### Detection and prevention are tracked separately

```python
expected_detection   # an incident is raised
expected_prevention  # the action is refused
```

Keeping them apart is the whole design. Sentinel detects far more than it
prevents, deliberately: correlation is self-reported, so blocking on it would be
a control an attacker can aim at *someone else's* agent. A suite with one boolean
would force every case into "did we stop it", and the honest answer for most is
*"no, on purpose, and here is why"*.

### The rows that expect no prevention are the honest part

| Attack | Detected | Prevented | Why not |
|---|---|---|---|
| `staged_exfiltration` | ✅ | ❌ | Only the **order** is the attack, and order is self-reported |
| `credential_to_privilege` | ✅ | ❌ | CRITICAL severity, same self-reported correlation |
| `out_of_order_steps` | ❌ | ❌ | Negative case: proves it matches a sequence, not a set |
| `incomplete_chain` | ❌ | ❌ | Negative case: a prefix must not fire the rule |
| `unverified_severity_claim` | ❌ | ❌ | Severity is computed, never accepted — the claim has no effect |

`test_the_suite_contains_cases_that_are_deliberately_not_prevented` asserts at
least one such row exists. **A red-team report where every row says PREVENTED is
a report nobody should believe**, and this stops the table being curated to look
good.

`test_the_suite_contains_negative_cases` requires at least two cases expected to
produce *nothing*. Without them the suite cannot distinguish a detector from a
system that flags everything — the failure this codebase measured at 51.7% of
ordinary tool calls.

### Regression is the value

The parametrised test compares actual against the tracked expectation. A case
that used to be detected and now is not **fails the build**. That is what makes
this a suite rather than an exercise.

`test_no_tracked_attack_returns_a_server_error_on_the_ingest_surface` is a
separate claim: a 5xx from an attack is a finding in itself — an unhandled path
in an ingest endpoint is both a denial-of-service primitive and a signal the
input was not understood.

**That test was originally named as though it covered every attack on every
endpoint, and the name was a lie.** It visits `/v1/events` and nothing else,
while claiming the whole API — and schemathesis found a 500 on
`/v1/policy/diff` from an out-of-range integer *while this test was passing*.
A claim is only as wide as the surface it actually visits, so the name now says
which surface that is.

(The dead identifier is deliberately not written here. This document is scanned
for test citations, and naming a removed test — even to describe its removal —
is indistinguishable to the scanner from claiming coverage that does not
exist.)

Breadth across the API is the fuzzer's job in CI (`dynamic-api-security`),
which generates inputs a hand-written table never would. This codebase has now
shipped three 5xx bugs found that way — a whitespace tool name, a SCIM
`startIndex` overflow, and the policy-version overflow — and **none** was found
by reasoning. That is the argument for keeping the fuzzer a required check.

---

## 2. Performance testing (§60)

### What already existed

`scripts/run_ingest_loadtest.py` measures ingest p95 **out of process** against
real PostgreSQL, with N separate OS processes as load generators. Its docstring
records why that matters: the two numbers it replaced were measured through an
in-process `TestClient` with Python threads, and 78% of the measured latency was
GIL contention between the load generator and the request handler inside one
interpreter. Neither number measured the service.

`docs/PERFORMANCE_REPORT.md` carries an explicit honesty rule — *only numbers
produced by runnable harnesses in this tree* — and real measurements against it.

### What was missing, and is now added

§60 does not ask "how fast can it go". It asks **"at 1,000 events/sec, what is
the latency"**, which is a different measurement and the only one useful for
capacity planning: a saturated system reports the latency of a queue, not of the
service.

`scripts/run_throughput_tiers.py` paces senders to each declared target rate
(100 / 1,000 / 5,000 / 10,000 per second) and reports the full §60 metric set
alongside `achieved_rate`.

Three rules are enforced in the artifact itself:

- **A tier that missed its target is marked `latency_is_meaningful: false`** with
  an explicit interpretation string. A p95 measured while falling behind is the
  p95 of a backlog, and publishing it as a throughput figure is precisely what
  §60's last line forbids.
- **`achieved_rate` always appears next to `target_rate`.** A table with only
  latency invites the reader to assume the target was met.
- **Event loss is counted from stored rows, not HTTP status.** A `202` means
  accepted, not stored.

The environment (platform, CPU count, memory, Python version) is recorded in the
artifact rather than a commit message, because a number without its machine is
not reproducible.

**Status: harness complete and self-tested; the four tiers have not been run
against a real server on representative hardware.** `--self-test` exercises the
pacing, percentile and reporting logic against an in-process stub and labels its
own output as unusable for a performance report. Running the real tiers needs a
machine that can plausibly sustain 10,000 events/sec, which this development
machine cannot — and reporting a saturated tier from it would be the exact
misuse the harness is built to prevent.

---

## 3. Chaos and disaster recovery (§61, §62)

Both were substantially built before this phase, and were **not rebuilt**:

| Asset | What it is |
|---|---|
| `scripts/run_dr_postgres_pitr_drill.py` | PostgreSQL point-in-time recovery |
| `scripts/run_dr_postgres_wal_pitr_drill.py` | WAL-based PITR |
| `scripts/run_dr_sqlite_drill.py` | SQLite restore |
| `tests_arch/test_dr_postgres_pitr_drill.py` | Automated restore verification |
| `tests_arch/test_dr_postgres_wal_pitr_drill.py` | Automated WAL restore |
| `tests_arch/test_execution_chaos.py` | Execution-path fault injection |
| `docs/dr_*.json` (5 files) | Recorded drill evidence |

§62 says *"do not merely document backups; prove recovery works"* — the drills
are executable and produce evidence artifacts, which is that requirement met.

### The evidence-overwrite defect, now fixed

The WAL drill test invoked `run_dr_postgres_wal_pitr_drill.py` with **no output
override**, so every run rewrote `docs/dr_postgres_wal_pitr_drill.json` — the
committed baseline — and left a spurious git diff. That had been outstanding
across several sessions.

An artifact that changes whenever the suite runs cannot serve as the baseline it
is committed to be, and the two jobs are genuinely different:

- `test_recorded_result_is_internally_consistent` validates the **committed
  baseline** — whatever it claims, it must not claim measurement without numbers.
- `test_live_wal_archive_pitr_drill_runs_and_meets_targets` proves the **drill
  still works**, and now writes to a temporary path.

The script gained an `--out` override; the default paths are unchanged, so a
deliberate operator run still records evidence where it always did. Verified by
running the live drill (43.9s, a real initdb/archive/crash/recover cycle, not a
skip) and confirming `docs/` stayed clean afterwards.

The sibling `run_dr_postgres_pitr_drill.py` test was already safe — it `chdir`s
into a temp directory, so the script's relative path resolves there.

### Chaos coverage (§61)

Audited against the twelve scenarios the section names. Eleven have coverage
somewhere in the suite; **MCP server timeout had none**, and it does not map
where you would expect: `McpGateway` is deliberately transport-free — "no
client, no transport, no server discovery" — so the gateway cannot experience a
timeout. The timeout happens in whatever calls the MCP server, which is the same
hardened outbound client every integration uses.

`tests_arch/test_outbound_chaos.py` covers that path and the three outbound
surfaces Phase 4 added, against §61's actual requirement — that the **decision**
degrades safely, not merely that nothing crashes:

- a timing-out remediation endpoint produces **no receipt**, stays classified
  transient so the claim is released and the action is retryable, and is audited
  as failed
- a hanging SOAR connector cannot fail the incident that produced it, and one
  hanging connector cannot stop the others
- an unreadable containment store does not halt the estate, and says so loudly

### The keyword audit was wrong, and here is the real one

The paragraph above originally said eleven of twelve scenarios were covered.
That number came from grepping the suite for each scenario's vocabulary, and
grep finds mentions, not tests. Checked properly — reading what the matching
tests actually assert — the count is **seven**:

| Scenario | Covered | Evidence |
|---|---|---|
| worker crash | ✅ | `test_repeated_crashes_still_converge_on_one_effect` |
| network timeout | ✅ | `test_a_timing_out_remediation_endpoint_produces_no_receipt` |
| MCP server timeout | ✅ | `test_a_timeout_is_transient_and_a_refusal_is_not` |
| tool adapter failure | ✅ | `test_a_timed_out_action_is_audited_as_failed` |
| duplicate events | ✅ | `test_a_replayed_signed_event_is_refused_and_writes_no_incident` |
| bad model | ✅ | `test_unreadable_artifact_degrades_loudly_instead_of_killing_the_process` |
| partial deployment | ✅ | `test_the_service_refuses_to_serve_against_an_unknown_schema` |
| PostgreSQL unavailable | ✅ | `test_the_engine_translates_driver_failures_into_transient_failures` |
| Redis unavailable | ✅ | `test_an_allow_from_a_dead_cache_is_marked_degraded` |
| clock skew | ✅ | `test_timestamp_comparison_is_timezone_normalised` |
| **disk pressure** | ❌ | retention bounds *growth*, which is adjacent but not the same |
| queue backlog | ~ | touched by the retention and soak suites, not tested directly |

Two of the false positives are worth naming, because they are the same mistake
in miniature that this document exists to correct. "Attestation unavailable"
matched a search for a database being unavailable and means something entirely
different. "Skew" matched a TOTP time window. A keyword audit reports both as
coverage.

The four absent ones were the interesting half, because each is a dependency
whose loss should degrade a security decision rather than break it — so three
were closed in `tests_arch/test_dependency_chaos.py`.

The behaviour mostly already existed: `TransientFailure` maps to 503, and
`RateLimitDecision.degraded` exists precisely to distinguish "allowed because
there was budget" from "allowed because the limiter was down". What did not
exist was anything asserting it, so nothing would have noticed it stopping being
true. `test_a_healthy_cache_decision_is_not_marked_degraded` is the negative
case — without it, a limiter that marked *every* decision degraded would pass
the others while making the flag meaningless.

**§61 coverage is now ten of twelve, one partial, one absent.** Disk pressure
remains untested: simulating it meaningfully needs a filesystem that actually
fills, which is a container-level concern rather than a unit test, and a fake
that raises `ENOSPC` would test the mock. Queue backlog is exercised indirectly
by the retention and soak suites rather than directly.

---

## 4. What this phase does not and cannot contain

Stated plainly rather than left as an implied gap.

- **An external penetration test.** The phase brief names one. It requires
  commissioning a third party. Everything on this side can be prepared —
  scope, an internal red-team baseline, fixes for what it would find — but the
  test itself is a procurement action, and any document showing it as complete
  would be false.
- **A Kubernetes cluster smoke test (§63) — CORRECTION.** An earlier draft of
  this document listed this as blocked on cluster access. That was wrong, and
  the evidence is in CI: the `kind-helm-smoke` job builds the image, creates a
  real kind cluster, loads the image, installs PostgreSQL and the Helm chart,
  runs the migration, and executes the chart's own `helm test` hook. It passed
  on this branch.

  What remains genuinely unavailable is running that locally, and any claim
  about a PRODUCTION cluster — node sizing, real storage classes, a real
  ingress, multi-node scheduling. The CI job proves the chart installs and the
  service comes up in a single-node kind cluster. It does not prove the chart
  is production-ready, and §63's list (pod disruption budgets, HPA, network
  policies, seccomp) has not been audited item by item here.
- **A 30-day API availability SLO (§59).** Cannot be produced in less than 30
  days, by construction.
- **Real-hardware throughput tiers**, as above.

Each of these is blocked on access or elapsed time, not on code.
