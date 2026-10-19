# Release gates: how to run them, and how to read the result

## The three words

| Verdict | Means | Does **not** mean |
|---|---|---|
| `PASS` | An artifact exists, is bound to this build, and records success | The gate is comprehensive |
| `FAIL` | An artifact exists, is bound to this build, and records failure | |
| `UNVERIFIED` | **We do not know.** No artifact, or one that belongs to another build | The gate passed. It must never be read as assurance |

`UNVERIFIED` is the default and the safe answer. A gate cannot become `PASS` by
being ignored.

## Running them

```bash
python scripts/run_release_gates.py
```

Nine gates run on a developer machine: `lint`, `type_check`, `unit_tests`,
`architecture_tests`, `security_tests`, `chaos_tests`, `migration_tests`,
`sast`, `dependency_scanning`, `secret_scanning`. The commands mirror
`.github/workflows/ci.yml`; where they differ, the difference is recorded in
each artifact's `command_rationale`.

```bash
python scripts/run_release_gates.py --list
```

Shows what will run and, for everything that will not, why. A gate that neither
runs nor appears in that second list would be one nobody decided about, and a
test refuses to let that happen.

The PostgreSQL parametrisations are opt-in:

```bash
python scripts/run_release_gates.py --with-postgres
```

Off by default because the embedded server leaks a cluster per parametrisation
on Windows. Off and `UNVERIFIED` is honest; on and hung is not.

Then build the report:

```bash
python scripts/build_release_evidence.py
```

## Two rules the runner will not bend

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

## Provenance

Every artifact carries a `.provenance.json` sidecar naming the commit and a
digest of the source tree. `build_release_evidence` verifies it, and an
**unbound artifact is `UNVERIFIED`, never `PASS`** — an artifact whose origin
nobody recorded is epistemically the same as one that does not exist.

Producers stamp their own output, immediately after writing it. Stamping
anywhere else — a later job, a cleanup step, a human — would let a sidecar claim
a build the artifact did not come from.

If the source tree changes **while** the gates are running, the runner deletes
everything it wrote and exits `2`. Not `1`: the gates did not fail, the run is
void. Results that describe no single version of the code are not evidence, and
their sidecars would verify perfectly while saying so.

### One caveat worth knowing

`secret_scanning` runs `gitleaks git`, which reads **committed history**. Every
other gate reads the working tree. On a dirty tree those are different things, so
a secret-shaped line in an uncommitted file passes the gate and then fails the
next run as a history finding — needing an exception rather than an edit. Every
artifact records `working_tree_dirty`, and the runner says so once on the
console.

## Why a local report goes to zero right after you commit

`verify()` compares the **commit** before it compares the source-tree digest, so
an artifact produced at `abc123` reads `produced from a different commit` at
`abc124` — even when `sentinel/**/*.py` is byte-identical and the measurement
therefore describes exactly the same code.

That has a consequence worth understanding before it surprises you:

1. Run the gates. The report reads *15 pass*.
2. Commit the regenerated artifacts. HEAD moves.
3. Rebuild the report. It reads **0 pass, 26 unverified.**

Nothing broke. The evidence is now one commit behind the tree it is being
checked against, and the mechanism says so.

**This flow is designed for CI**, where artifacts are produced fresh in the job
at the checked-out commit, uploaded, and never committed. There, step 2 does not
happen and the report closes. The provenance sidecars are gitignored for the
same reason, and `.gitignore` states it: a committed sidecar is stale the moment
it lands.

Locally, then: generate the report **for a commit**, read it, and do not expect
the copy on disk to stay true once you commit again. Do not "fix" it by stamping
an existing artifact where it sits — that makes a sidecar claim a build the
measurement did not come from, which is the forgery the whole mechanism exists
to make hard.

### The loosening that is deliberately not implemented

Comparing only the tree digest would make a docs-only commit stop invalidating
measurements, and it is a defensible reading: the tree digest is what answers
*does this evidence describe this code*.

It is not implemented, because it widens what counts as this build's evidence,
and that is a security invariant rather than an ergonomics decision. Anyone
changing it should do so on purpose, in a commit that says so, having decided
that a commit identity is metadata rather than part of the release's identity.
The four measurement artifacts under `docs/` and `evaluation/` being tracked in
git while their sidecars are ignored is the other half of the same question, and
it should be answered at the same time.

## The four gates no build can satisfy

`independent_pentest`, `production_soak`, `disaster_recovery_proof`,
`design_partner_validation`.

Not one is code. They accrue from operating the product — a contract, a second
failure domain, a calendar, other organisations running this against their own
traffic. **No amount of engineering moves them**, and the best tier any build
can report is `RELEASE CANDIDATE`.

They are emitted with their reasons rather than omitted, because a reader
seeing twenty-one green rows and no mention of pentesting could reasonably
conclude the product was ready to sell. These four rows are what answer *why is
this not GA*, from the generated document rather than from whoever is asked.

`test_ga_gates_cannot_be_faked.py` proves this behaviourally rather than
asserting it: it plants a well-formed artifact for each, correctly bound to the
real HEAD and the real source tree, recording success in the exact shape every
other gate uses — and requires the verdict to still be `UNVERIFIED`.

## Proving the guards are real

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
| `ok is True` relaxed to a truthy test | `"ok": "failed"` reports PASS |
| The pass-count regex accepts a zero | An all-skipped run reports PASS |
| A third route joins the throttle exemption | An ingest endpoint with no rate limit |
| The readiness cache is removed | An unauthenticated, unmetered database amplifier |
| A gate leaves the unsatisfiable GA set | A planted artifact claims customer validation |
| A secret-allowlist entry is widened | The scanner says "no leaks found" and means nothing |

A **stale anchor counts as vacuous**, not as a skip: a mutation that no longer
applies is a guard that stopped being proven, and silence there is the failure
mode being guarded against.

### Safety

It edits real source files, so it **refuses to run on a dirty tree** — on a
clean one `git checkout .` is a complete recovery at any moment. Every file is
snapshotted as exact bytes, restored in a `finally`, and the restoration
verified by digest; a failed restore aborts loudly with the recovery command
rather than continuing.

It runs as its own CI job for the same reason: a crashed run must not leave a
mutated tree for a later step to test and report on.

### Why it is not a release gate

`REQUIRED_GATES` is evidence about a build. This mutates the build while it
runs, and a release-evidence runner that rewrites source is not a habit worth
normalising. It answers a different question — *are the checks real* — and
belongs beside them, not inside them.

## Invisible characters

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

## Adding a gate

1. Add the name to `REQUIRED_GATES`.
2. Give it a runner in `run_release_gates._specs()`, **or** an entry in
   `NO_RUNNER` saying why it has none.

A gate with neither is one nobody decided about, and
`test_release_gate_runner.py` fails on it. It resolves to
`gate_<name>.json` automatically — a gate absent from the filename map used to
report `UNVERIFIED` forever with a message inviting someone to produce an
artifact that nothing would ever look for.

## Related documents

- [`PRODUCTION_READINESS_REPORT.md`](PRODUCTION_READINESS_REPORT.md) — what is
  verified in this tree
- [`attack_surface.json`](attack_surface.json) — every route and the capability
  it declares; the input to a pentest scope, and not pentest evidence
- [`COMPLIANCE_MAP.md`](COMPLIANCE_MAP.md) — control coverage, with the standing
  caveat that SOC 2, ISO 27001 and NIST certify an organisation and not a
  codebase
