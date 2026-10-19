# Sentinel research: what we measured, and what we could not

This page exists because a security product's research page is usually a
marketing surface, and a marketing surface is the wrong shape for the only
question that matters here: **which of these claims has evidence behind it,
and what kind.**

Every row below carries its evidence status. The allowed values are the same
four the release gates use, and they are used strictly:

| Status | Meaning |
|---|---|
| `PASS` | Measured, with a bound artifact naming the commit it came from |
| `FAIL` | Measured, and the result was negative |
| `UNVERIFIED` | Not measured. **Never** the same as a negative result |
| `NOT_APPLICABLE` | The question does not apply to this architecture, with the reason |

**Missing evidence is `UNVERIFIED`.** It is never quietly converted to `PASS`,
and a historical measurement from a different commit may be informative but
does not satisfy anything for the current build.

---

## 1. Prompt-injection detection

**Claim:** a trained classifier detects injection attempts in English at
recall 0.855, precision 0.972, FPR 0.044 on a held-out, group-aware split.

**Status:** `PASS` — [`evaluation/BENCHMARK.md`](../evaluation/BENCHMARK.md),
`evaluation/metrics.json` with a provenance sidecar.

**What the number is not.** The all-languages figure (0.957 recall) is in the
benchmark and is marked untrustworthy there, because the non-English cases came
from a source whose label quality we could not establish. Quoting the higher
number would be the easiest available dishonesty in this repository, which is
why the lower one is the headline.

**The finding that matters more than either number.** The handcrafted 22-case
corpus this project started with reported recall 0.643. The same rules scored
**0.025** against 7,075 third-party cases. A corpus written by the people who
wrote the rules overstated capability by roughly 26x, and that gap is the most
useful result here — it is a measurement of how wrong a self-authored corpus
can be, and it generalises to every other detector anybody builds this way.

## 2. Sequence detection

**Claim:** ordered multi-step patterns are recognised where the individual
steps are legitimate.

**Status:** `UNVERIFIED` for production traffic. `PASS` for regression against
a synthetic corpus — [`evaluation/sequence_corpus.py`](../evaluation/sequence_corpus.py),
21 cases, `tests_arch/test_sequence_corpus.py`.

**Why it cannot be stronger.** Every trace in that corpus was written by hand.
A figure from it measures agreement between the corpus and the rules, and the
corpus reports `corpus_agreement` rather than "accuracy" precisely so nobody
can quote it as a detection rate. Every malicious trace is one somebody already
thought of; the traces that matter are the ones nobody wrote.

**A known false positive, published rather than deleted.** A backup job —
read, compress, write to object storage — matches `staged_exfiltration`,
because object storage canonicalises to an external upload and the rule cannot
tell the estate's own bucket from anyone else's. It is in the corpus as
`known_gap`. Removing it would improve the headline and hide the product's most
likely operational complaint.

## 3. False positives on ordinary traffic

**Claim:** none. Specifically, we measured the opposite.

**Status:** `PASS` (as a negative result) — `docs/benign_tool_call_false_positives.json`,
`scripts/measure_benign_tool_call_false_positives.py`.

A soft prompt detector fired on **51.7%** of ordinary tool calls. It is
disabled by default as a result, and `SENTINEL_SOFT_PROMPT_DETECT=false` logs a
warning naming its independent English recall (0.067) so nobody re-enables it
believing it is free.

This is the result a vendor research page would omit. It is here because a
detector that fires on half of normal work is not a detector, and publishing
that is cheaper than a customer discovering it.

## 4. Authorization determinism

**Claim:** authorization decisions are deterministic and no model output can
reach a control path.

**Status:** `PASS` — structural rather than statistical. `ModelAdvice` has **no
field for a decision**, so injected text cannot authorize; the property is
enforced by the type, not by a filter that could be evaded.
`tests_arch/test_security_prompt_injection.py` (16 cases).

## 5. Transparency and tamper-evidence

**Claim:** an entry cannot be removed, reordered or rewritten without a proof
failing.

**Status:** `PASS` for the data structure —
[`sentinel/domain/transparency.py`](../sentinel/domain/transparency.py), RFC
6962 Merkle log, 43 tests, 4 mutation guards.

**Status:** `PASS` for persistence and serving. Leaves are stored append-only
-- `(tenant_id, sequence)` is the primary key, so an overwrite is a constraint
violation rather than a silent rewrite -- and `/v1/transparency/root`,
`/inclusion/{index}`, `/consistency` and `/published` serve roots and proofs.
`tests_arch/test_transparency_store.py` (22) and
`tests_arch/test_transparency_routes.py` (25).

**Status:** `UNVERIFIED` for the deployment property, and this is the part that
matters. **No root has been published anywhere the operator cannot change it**,
because no sink is configured. **A transparency log whose roots are only ever
served by the same party that writes the log proves nothing about that party.**

That is now enforced rather than merely documented: every proof response
carries `independently_verifiable`, false until a root is published to a sink
that returns a reference a third party can fetch. `RefusingRootSink` is the
default and it raises -- there is deliberately no local-file fallback, because
a root on a disk the operator owns would set that flag True while proving
nothing, and the flag is the only thing separating evidence from an assertion.

In the current state the log detects a mistake, a partial restore, or a second
replica diverging. It does not detect a determined operator, and every response
says which. Configuring a sink -- S3 Object Lock in compliance mode, a WORM
appliance, an RFC 3161 timestamping authority, or a public transparency service
-- is a deployment decision with cost and jurisdiction attached, so the code
defines the contract and refuses rather than choosing.

## 6. Skill detonation

**Claim:** an untrusted skill runs without reaching the control plane.

**Status:** `PASS` for containment —
[`sentinel/infrastructure/detonation_container.py`](../sentinel/infrastructure/detonation_container.py):
no network, no capabilities, read-only root, non-root user, no new privileges,
pid and memory ceilings. The isolation flags are asserted against the argument
vector actually executed, not against a comment.

**Status:** `PASS` for behavioural observation, as of this change.
[`sentinel/infrastructure/detonation_tracing.py`](../sentinel/infrastructure/detonation_tracing.py) runs the payload under `strace` and
turns syscalls into real observations -- files read and written, connections
attempted, processes spawned. Verified against a LIVE container run; that
run's trace is committed as `tests_arch/fixtures/strace_live_detonation.log`
and every parser test reads it.

The live run earned its place immediately: every argv assertion passed while
the payload died with `EACCES`, because a tmpfs defaults to root-owned and the
container runs as uid 65534 -- the skill could not write to its own workspace.
No string assertion would have found that.

**The cost is one capability.** Tracing needs `--cap-add=SYS_PTRACE` on an
otherwise `--cap-drop=ALL` container. That is a genuine widening, and it is why
tracing is a separate class rather than a flag: a deployment should choose
observation over minimal capability deliberately. A test asserts `SYS_PTRACE`
is the ONLY capability added, as a set difference against the untraced vector.

**`observation_incomplete` stays True.** strace sees syscalls, not what a
process did inside itself: a payload decoded in memory, code evaluated from a
string, a package resolved from a cache. Flipping the flag would turn "we
watched the syscalls" into "we watched everything", and the point of the field
is that a reader can tell those apart. An empty `files_read` is also reported
as untrustworthy unless a file-opening syscall actually appeared -- because
busybox uses `open` rather than `openat`, and an `openat`-only filter reports
zero file access for an Alpine image.

**A container is not a virtual machine.** It shares the host kernel; a kernel
exploit escapes it. `ISOLATION_KIND` is `"container"`, never `"sandbox"`.

## 7. Red-team resistance

**Claim:** each release is attacked and regressions fail the build.

**Status:** `PASS` for the tracked table —
`tests_arch/test_red_team_suite.py`, and a commit-bound ledger at
`docs/evidence/attack_campaign.json`.

**No defence rate is published.** The campaign refuses to compute one from
fewer than 30 cases; there are 5. A ratio of small integers with a percentage
sign is not a measurement, and the artifact carries the refusal reason instead
of a number.

**`techniques_not_attempted` is part of the artifact**, and the artifact states
that the list is itself incomplete.

## 8. Disaster recovery

**Claim:** point-in-time recovery works. Measured RPO **12.77s** and RTO
**84.70s**, against targets of 300s and 1800s.

**Status:** `PASS` for the mechanism, `FAIL` for the failure domain —
`docs/dr_postgres_wal_pitr_drill.json`, recorded 2026-08-19.

Those are the numbers in the artifact. An earlier draft of this page said
"RPO ≈ 57s" from memory; the artifact says 12.77s, and the artifact is what
counts. A research page that rounds its own evidence from recollection is the
thing this page exists not to be.

The default WAL archive writes to a Docker volume on the same host, usually the
same disk, as the database. Losing the node loses both, so the default archive
cannot recover from the one failure a WAL archive exists for. The artifact
records `node_loss: null` — the drill did not test node loss, which is the
scenario the archive exists for. It is labelled `fail` in the production
readiness report rather than presented as working.

## 9. Availability

**Claim:** none.

**Status:** `UNVERIFIED`. A 99.9%/30-day figure requires 30 days. There has
been no production soak, and `docs/SOAK_RUNBOOK.md` describes the procedure
that has not been run.

## 10. Third-party security assessment

**Status:** `UNVERIFIED`. No external party has examined this system. No
penetration test has been performed. `docs/PENTEST_PACKAGE.md` is the material
a tester would need, not a report from one.

## 11. Customer outcomes

**Status:** `UNVERIFIED`. There are no design partners and no production
deployments, therefore no customer results, no time-to-value measurements and
no case studies. `docs/DESIGN_PARTNER_RUNBOOK.md` describes what would be
measured.

---

## What we would most like to be wrong about

Two things, and an outside result on either is more valuable to us than a
confirmation:

1. **The sequence rules are probably too narrow.** They were written from
   reasoning about attacker behaviour and are evaluated against a corpus
   written by the same people. Section 1 measured exactly that mistake costing
   26x in a different detector. We expect the same class of error here and
   currently have no way to size it.

2. **`canonical_action` is the attack surface.** A sequence rule matches
   canonicalised actions, so an action name that canonicalises to nothing
   defeats the rule silently. The mapping is a hand-written table. A systematic
   search for actions that should canonicalise and do not would be the single
   most useful adversarial contribution to this codebase.

## Reproducing anything here

Every number above comes from a script in `scripts/` or `evaluation/`, and
every artifact carries a `.provenance.json` sidecar naming the commit and
source-tree digest it was produced from. An artifact whose provenance does not
match the current tree is `UNVERIFIED` by construction — see
`scripts/release_binding.py`.

```bash
PYTHONPATH=. python scripts/run_release_gates.py
```

A gate that did not run produces **no artifact**, and absence is read as
`UNVERIFIED`. That is the property that makes the rest of this page checkable
rather than assertable.
