# Adversarial self-review: fourteen attempts to reject this project

Each role below was asked one question: *what would make you refuse to sign off?*
Findings are recorded whether or not they were fixed, and the roles that still
reject the project are named.

> **Correction, 2026-08-18 — this document cited evidence that does not exist.**
>
> Three artifacts were named here as though they were in the tree. None of them
> were, which was established by searching for them rather than by argument:
>
> | Cited as evidence | Reality when checked |
> |---|---|
> | `test_tenant_isolation_is_enforced_by_the_real_database` | No such test anywhere in `tests_arch/` |
> | `test_every_table_is_either_reaped_or_declared_append_only` | No such test; no `APPEND_ONLY_TABLES` either |
> | `tests/test_failure_classes_are_structural.py` | There is no `tests/` directory in this repository |
>
> This is the same defect class as the F-4 claim that branch protection "had been
> applied" — a statement of evidence with no executed command behind it — and it
> is recorded rather than quietly deleted, for the same reason that one was.
>
> The first two now exist and pass (`tests_arch/test_tenant_isolation_rls.py`,
> `tests_arch/test_retention_sweep.py`); the sections below are updated to point
> at them. **The third is still absent**: the "What a fifth council would have to
> find" section opens by claiming every V1–V4 failure class is enforced
> mechanically by that file, and that claim remains **unsupported**.
>
> The test baseline previously stated here — "284 standard + 31 live = 315
> passing" — also does not correspond to this tree, which runs a little over 700.
> It has been removed rather than adjusted, because nobody can now say what it
> counted. `docs/PRODUCTION_READINESS_REPORT.md` carries the measured counts.

---

## Roles that found defects, now fixed

### Site Reliability Engineer — *"what fills up?"*
**Found: unbounded growth.** `work_queue` retained every completed row forever,
one per incident, on the hot path of every claim. `incident_transitions` and
exhausted dead letters likewise had a writer and no reaper.

**Fixed structurally — but only on the development engine, which took until
2026-08-18 to notice.** The sweep took a pooled connection and never established
a tenant. Every table it deletes from is under `FORCE ROW LEVEL SECURITY`, whose
policy is `tenant_id = current_setting('sentinel.tenant_id', true)`, so on
PostgreSQL that setting was NULL, every `DELETE` matched no rows, and the sweep
**reported zero rather than failing**:

```console
before: work_queue = 1  inbox = 1
sweep reported: {... 'retention_rows_deleted': 0}
after : work_queue = 1  inbox = 1
RESULT: DEFECT CONFIRMED
```

This is the same defect this document credits the Google SRE seat with finding in
another form, and the same one `tests_arch/conftest.py`'s own docstring holds up
as the reason the SQL suites are parametrised over both engines —
`test_retention_sweep.py` was the suite that was not. The sweep now runs per
tenant with `set_tenant` **and** an explicit `tenant_id = ?` predicate, every test
in that module runs on both engines, and the regression asserts
`before − after == reported` against a non-zero `before`, so a sweep that deletes
nothing can no longer satisfy a pair of agreeing zeroes.

**The declared-or-reaped gate now exists.** It was cited here as though it did;
it did not, and neither did `APPEND_ONLY_TABLES` (see the correction at the top).
Building it immediately found a table nobody had decided about:
`webauthn_challenges` ships `ix_challenges_issued(issued_at)` — an index whose
only possible purpose is an age purge — with no caller, exactly the signature of
`ix_inbox_age` and `ix_nonces_expiry` before this work started.

The evidence ledger is declared append-only on purpose: trimming a hash chain
destroys the non-repudiation it exists to provide, and a test asserts retention
never touches it — including the new incident-history sweep, which may delete an
incident while its ledger entry, evidence row and audit trail all remain.

### Google SRE — *"does a skipped test look like a passing one?"*
**Found: silent skip.** A stale PostgreSQL data directory turned 23 live tests
into "23 skipped" with exit code 0 — green CI, nothing verified. That is the same
shape as every silent failure this project has found.

**Fixed.** `SENTINEL_REQUIRE_LIVE=1` converts unavailable infrastructure into a
failure. CI must set it.

### Principal Engineer (Microsoft / AWS) — *"where is the shared mutable state?"*
No module-level mutable containers remain. Configuration is parsed once and
cached; the cache has an explicit `reload()` rather than being reached into.

**Previously found and fixed:** a class-level sweep timestamp shared across
`DurableQueue` instances, and background threads started as an import side
effect.

### Enterprise CISO — *"can one tenant see another's evidence?"*
Every accessor is tenant-scoped — 27 distinct `tenant_id=?` predicates — and
`test_tenant_isolation_is_enforced_by_the_real_database` proves it against live
PostgreSQL with the same incident id under two tenants. (That test did not exist
when this paragraph was first written; see the correction at the top. It exists
now, in `tests_arch/test_tenant_isolation_rls.py`, and runs on both engines.)

**Residual concern CLOSED, 2026-08-18.** The concern as written — "isolation is
enforced in application SQL, not by PostgreSQL row-level security" — was **already
false when it was written**. `sentinel/infrastructure/sql/schema.py::rls_statements`
issues `ENABLE`/`FORCE ROW LEVEL SECURITY` plus a `USING`/`WITH CHECK` policy for
every one of the 19 tables in `PROTECTED_TABLES`, and `migrate.py` applies it at
versions 2, 4, 6, 8 and 10. What was genuinely missing was any test that could
tell RLS apart from the application predicate, because every existing isolation
test still carried `WHERE tenant_id = ?` and so would have passed with the
policies dropped entirely.

That is now closed by tests that **deliberately remove the application
predicate** — the exact situation a forgotten `WHERE` creates in production:

| Statement issued, no `WHERE` at all | PostgreSQL | SQLite |
|---|---|---|
| `SELECT tenant_id, incident_id FROM incidents` | 1 row, tenant A only | 3 rows, both tenants |
| `UPDATE incidents SET state='failed'` | 1 row; tenant B untouched | 3 rows; tenant B corrupted |
| `DELETE FROM incidents` | 1 row; tenant B's 2 rows survive | 3 rows; tenant B wiped |
| `INSERT` labelled with another tenant's id | refused by the policy | permitted |

The SQLite column is asserted, not skipped: SQLite has no row-level security, so
on the development engine the application predicate really is the only thing
between tenants, and a reader should not have to infer that.

Two further assertions stop the file from becoming decorative:
`test_the_application_role_is_not_a_superuser` (a superuser bypasses FORCE RLS,
which would make every row above pass vacuously), and
`test_every_protected_table_actually_carries_a_forced_policy`, which asks
`pg_class`/`pg_policy` whether the server agrees the DDL ran, rather than trusting
that an `IF NOT EXISTS` migration did something.

**Evidence:** `tests_arch/test_tenant_isolation_rls.py`, 18 tests, 14 passed +
4 skipped (the PostgreSQL-only assertions under the SQLite parametrisation),
0 failed.

---

## Roles that found nothing new

### OWASP reviewer — prompt-injection handling
Untrusted text is sanitised before reaching any agent
(`sanitize_untrusted`, applied in `detection_agent` and `supervisor_agent`), with
a 12,000-character bound so a huge payload cannot starve the pipeline.

### Blue team — attribution
Every incident records which layer fired — policy rules or the statistical
classifier — with the detector version, and the two verdicts are never merged.
An analyst is never shown a probability dressed as a policy match.

### SOC 2 / ISO 27001 auditor — audit trail
Every state change appends to `incident_transitions` in the same transaction as
the state write. The trail cannot disagree with the state, because they commit
together.

**Caveat recorded:** the trail is deleted with its incident at end of retention.
That is deliberate (an orphaned audit record describes something that no longer
exists), but an auditor requiring 7-year retention would need the window changed
and the ledger exported.

---

## Roles that still reject the project

These are honest NOs. Engineering did not move them, and claiming otherwise
would be the failure this whole exercise exists to prevent.

### Red team — *"I can still get past this"*
Cross-source AUC is **0.763**. Roughly one in four attacks from a corpus the
model has not seen ranks below a benign prompt. A red team does not need a
sophisticated bypass; it needs a phrasing the training corpora did not contain.

**Not fixable by engineering.** It needs attack data from a distribution nobody
here authored — ideally real traffic from a design partner.

### Gartner analyst — *"where is the operational evidence?"*
No production traffic has ever been processed. No customer has run this.

> **CORRECTION 2026-08-19 — the 0.48 calibration figure is withdrawn.**
>
> This paragraph said "the expected calibration error of 0.48 means the
> confidence scores cannot be used to set an operational threshold". Two things
> were wrong with that number.
>
> **1. It came from a script that cannot run in this repository.** The 0.4836
> lives in `evaluation/results/leave_one_source_out_semantic.json`, produced by
> `evaluation/validate.py --model semantic`. That path imports
> `app.detection.semantic_features`, and **there is no `app` package in this
> tree** — it is the predecessor's namespace, the same way the `tests/`
> directory is. The command exits `ModuleNotFoundError`. The artifact is also
> under `evaluation/results/`, which is gitignored, so it was never committed
> and cannot be regenerated here.
>
> **2. It was computed by a pooling this very module refuses to publish.**
> `leave_one_source_out()` carries a long comment explaining that ROC/AP must
> **not** be pooled across folds, because four of the six sources are
> single-class and "reporting it as a headline would be its own dishonesty".
> It then computed `expected_calibration_error` from exactly that pooled set.
> Calibration compares predicted probability against an *observed positive
> rate*, and in a single-class fold that rate is 1.0 or 0.0 in every bin **by
> construction** — so the pooled figure is governed by the class balance of the
> concatenation, not by the model.
>
> **What is actually measured**, from the reproducible n-gram path
> (`PYTHONPATH=. python evaluation/validate.py --model ngram`):
>
> | | ECE |
> |---|---|
> | **Mean over mixed-class folds — the headline** | **0.1872** |
> | `deepset/prompt-injections` (mixed) | 0.1122 |
> | `jackhhao/jailbreak-classification` (mixed) | 0.2622 |
> | Pooled across all six folds *(the old method)* | 0.5524 |
> | *single-class folds, for illustration:* MultiJail 0.8841, xquad 0.6746, synthetic 0.6652, gandalf 0.3035 | — |
>
> Cross-source AUC over the mixed folds is **0.7495**, so the model does rank
> meaningfully on sources it was not trained on.
>
> **The conclusion survives in direction, not in magnitude.** 0.187 is still
> poor calibration — a well-calibrated model is under ~0.05 — so an operator
> still cannot read a probability off this model and set a threshold on it. But
> it is roughly a third of what was claimed, and the claimed figure was an
> artefact of invalid pooling reported by a script that does not run here.
> `validate.py` now reports the per-fold value as the headline and keeps the
> pooled one under `expected_calibration_error_pooled_INVALID` with a note,
> rather than deleting it.

### YC partner — *"why does this win?"*
No wedge against funded incumbents. Lakera, Protect AI and Prompt Security are
inside Check Point, Palo Alto and SentinelOne. The clearest opening the market
research identified — stranded buyers from those acquisitions — is a go-to-market
thesis with no corresponding work in the codebase.

### Fortune 100 pilot lead — *"can I run this next quarter?"*
No. No Kubernetes cluster has ever run this code; no container runtime exists in
this environment, so the Helm chart is lint- and render-verified only. No live
telemetry collector or Prometheus has scraped it. The ECDSA recovery primitive
remains unaudited.

### The three council seats
Their commercial votes stand. Every infrastructure and honesty finding they
raised is closed and verified, but "viable commercial product" and "viable
venture company" were never engineering questions.

---

## What a fifth council would have to find

**The claim that used to open this section is withdrawn.** It read: "Every
failure class from V1–V4 is now enforced mechanically
(`tests/test_failure_classes_are_structural.py`)", followed by a list of thirteen
classes. There is no `tests/` directory in this repository and no such file. The
thirteen classes may well each be covered somewhere in `tests_arch/`, but no
single artifact enforces them as a set, and nothing here should be read as saying
one does. Re-establishing that claim means writing that file; until someone does,
this section makes no blanket assertion.

Of the three candidates this section named, **two are now closed and one is
not.**

1. ~~**Application-enforced tenant isolation** — one missing SQL predicate bleeds
   data. PostgreSQL row-level security would make it structural.~~
   **CLOSED 2026-08-18.** RLS was already implemented and applied; what was
   missing was a test that could distinguish it from the application predicate.
   `tests_arch/test_tenant_isolation_rls.py` removes the predicate entirely and
   shows SELECT, UPDATE and DELETE all still bounded to one tenant on PostgreSQL,
   with a non-superuser assertion so the result cannot be vacuous. See the
   Enterprise CISO section.

2. ~~**A single-node evidence ledger head** — the append protocol is not proven
   safe under concurrent multi-replica writes, so the chain could fork.~~
   **CLOSED 2026-08-18 — and it was (a), structurally impossible, not (b).**
   `tests_arch/test_ledger_multi_replica.py` runs two INDEPENDENT
   `ConnectionPool`s — separate connections, separate transaction state, no
   shared Python object, so every protection under test is server-side — with
   twelve threads released together on a `threading.Barrier`, on both engines.
   It then reads the chain back and checks four properties rather than checking
   that nothing raised: no two entries share a predecessor, `seq` is dense from
   1, every link recomputes from its own predecessor and payload, and every
   append either committed or raised a **retryable** error (so a loser retries
   and the evidence still lands, rather than being dropped). A fifth test inserts
   a deliberate fork directly, bypassing `append()`, and confirms the database
   refuses it on `ux_ledger_chain` — without which all of the above would be
   consistent with a unique index that had never been created.

   The mechanisms differ per engine, which is why running on one would not have
   settled it: SQLite serialises writers at `BEGIN IMMEDIATE`, PostgreSQL at the
   transaction-scoped advisory lock in `Connection.serialise_tenant`. Only the
   second is production.

   **Limit, stated:** the two pools share an interpreter, so a real cluster's
   interleavings are a superset of those reachable here. What is established is
   that the server-side protocol holds when two independent pools contend.

3. **Detection that cannot be tuned** — ~~calibration error 0.48 means the
   probability is not a probability, and no threshold is defensible.~~
   **PARTIALLY CLOSED 2026-08-19, and the number was wrong.** See the Gartner
   correction above. The 0.48 came from a script that cannot execute in this
   repository (`--model semantic` imports `app.detection.semantic_features`;
   there is no `app` package) and was computed by pooling across single-class
   folds — a pooling the same module refuses to publish for AUC.

   The reproducible figure, from `validate.py --model ngram`, is **0.1872**
   ECE over the folds where calibration is a meaningful question, with
   cross-source AUC **0.7495**.

   **What that does and does not settle.** 0.187 is still poor — a
   well-calibrated model is under ~0.05 — so the direction of the original
   objection stands: an operator cannot read a probability off this model and
   set a threshold on it. What is now false is the magnitude, and the claim
   that the figure was evidence at all. What remains genuinely open is
   *improving* calibration, and that part still needs attack data from a
   distribution nobody here authored — isotonic or Platt scaling fitted on
   in-distribution data does not fix out-of-distribution calibration, which is
   precisely what leave-one-source-out measures.

A fifth review would now have to find a class outside all of these.

## The class the fifth review actually found: gates that execute nothing

Written up on 2026-08-19, because it is a *class* and not a list of bugs.

Four separate gates were found in one pass that looked healthy from the outside
and were doing no work at all:

| Gate | How it looked | What it was doing |
|---|---|---|
| Operational retention sweep | `pass` — 110,000 rows swept, DB halved | deleted **zero** rows on PostgreSQL and reported zero |
| `dynamic-api-security` (DAST) | a job that ran and failed at 31s | timed out waiting for a schema the app is configured not to serve; **0 operations tested** |
| PostgreSQL test parametrisation | green locally on Windows | **every** `[postgres]` test errored on connect in CI |
| Independent-English promotion floor | a test in the suite | asserts a file under a **gitignored** directory; never once ran in CI |

A fifth, `bandit`, was running but permanently red on 99 false positives — with
the same practical effect, because nobody read the output. **It was concealing a
real pre-authentication XML denial of service in the SAML path.**

### What they have in common

Not a shared root cause — an unscoped connection, an unset feature flag, a
string-sliced DSN and a gitignored path have nothing technical in common. What
they share is a **shape**: each produced a result indistinguishable from success
while doing nothing.

- A sweep that deletes nothing satisfies "no old rows remain".
- A fuzzer that tests nothing reports no failures.
- An erroring parametrisation is invisible if you read only the local exit code.
- A file assertion that never runs never fails.

This is the same shape as the F-4 retraction that this project already treats as
its worst mistake — *a claim of coverage with nothing behind it* — and it turns
out to be the dominant defect class in the repository, well ahead of anything on
the V1–V4 list.

### What was done about it

Each fix now carries a **positive** assertion that work happened, rather than an
absence of failure:

- the retention regression asserts `before − after == reported` against a
  non-zero `before`, so agreeing zeroes fail;
- the DSN helpers are tested against both DSN shapes as pure strings, so a
  Windows developer catches a Linux-only regression without a Linux machine;
- the DAST job's schema endpoint is asserted to return 200 and 18,124 bytes;
- the promotion-floor artifact is regenerated in CI rather than assumed present.

### What was NOT done, and is the honest residual

**There is no general mechanism that would catch a fifth.** Nothing checks that
a gate is doing work. A plausible next step is a meta-test asserting every
`test_*` name cited in `docs/` resolves to a collected test, plus a convention
that any gate whose subject can be empty must assert a non-zero denominator —
but neither exists, and claiming otherwise would repeat the mistake this section
is about. It is recorded as residual risk 13 in
`docs/PRODUCTION_READINESS_REPORT.md`.
