# Design partner runbook

How to put Sentinel in front of a real organisation without breaking their
traffic, and what to hand back at the end.

**This document is the process. It is not evidence that anyone has run it.**
The `design_partner_validation` gate stays `UNVERIFIED` until a real
organisation completes the agreed validation. There are no reference customers
in this repository and none will be invented.

---

## The rollout ladder

Six stages. **Nobody starts at the top**, and each rung has an exit condition
the partner agrees before moving up.

| Stage | Sentinel does | Partner risk |
|---|---|---|
| 1. `OBSERVE` | Records only. Decides nothing | **None.** No decision is in any path |
| 2. `SIMULATE` | Replays history against a candidate policy | **None.** Simulation never executes |
| 3. `WARN` | Records a decision, does not act on it | None to traffic; alert volume becomes real |
| 4. `REQUIRE_APPROVAL` | Holds consequential actions for a human | Latency on held actions, and a queue somebody must staff |
| 5. `ENFORCE_LOW_RISK` | Blocks reversible actions | A wrong block is recoverable |
| 6. `ENFORCE_HIGH_RISK` | Blocks irreversible actions | A wrong block is expensive. This rung is a decision, not a default |

The reason the ladder exists is that stage 5 is the first one where Sentinel can
cause an outage. Everything before it is measurement, and a partner who reaches
stage 4 with a clean simulation has learned most of what a pilot teaches at none
of the risk.

### Exit conditions

- **1 → 2**: discovery has plateaued. New agents per day approaching zero, and
  the partner recognises the inventory. *If they do not recognise it, that is
  the finding* — see shadow agents below.
- **2 → 3**: a simulated policy produces a decision set the partner's security
  owner accepts.
- **3 → 4**: warning volume is triaged rather than ignored. A partner drowning
  in warnings at stage 3 will not staff an approval queue at stage 4.
- **4 → 5**: approval decisions match what the policy would have done, over a
  meaningful sample. Disagreement means the policy is wrong, not that the
  humans are.
- **5 → 6**: explicit, named, written sign-off. Nothing automatic.

**Rolling back a rung is normal and should be pre-agreed**, so it is an
operational step rather than an escalation.

---

## Before stage 1

- A tenant, provisioned and isolated. Cross-tenant isolation is testable
  independently — offer the partner the test, do not just assert it.
- Their own SIEM sink configured, with a credential. A `credential_ref` that
  resolves to nothing **refuses to start** rather than exporting their security
  events over an unauthenticated connection.
- Retention agreed **in writing**, including what Sentinel keeps after the
  pilot ends. This is the question a partner's legal team asks first.
- A named owner on both sides.

## What the partner gets back

A report containing only what was measured:

| Section | Sourced from |
|---|---|
| Agents discovered, by state | `MANAGED` / `UNMANAGED` / `REVOKED_BUT_ACTIVE`, with the coverage denominator |
| **Shadow agents** | Agents nobody enrolled. Usually the highest-value finding of a pilot |
| **Revoked-but-active** | Enrolment withdrawn, still acting. Neither managed nor gone |
| MCP servers and tools | Including cross-server name collisions and credential sprawl |
| Overprivileged agents | Effective reach vs declared need |
| Blast radius | Per agent, with **coverage** stated. A low score over low coverage means nobody has classified the estate, not that the agent is safe |
| Policy simulations | What a candidate policy would have changed, from immutable history |
| High-risk actions observed | Ranked, with the evidence chain |
| **Actions actually blocked** | Only from stages 5–6. Zero at lower stages, and the report says so rather than leaving a blank |
| **False positives** | Named individually, not summarised. This is the number that decides whether they renew |
| Latency added | Measured at their traffic, not ours |
| **Coverage holes** | What Sentinel could not see, and why |

### Two rules for the report

**Every figure carries its denominator.** "14 agents discovered" is not a
finding; "14 of an estate we could enumerate to 80% via these three connectors"
is.

**Coverage holes are a required section, not an appendix.** A pilot report
without them implies complete visibility, and no connector set achieves that.
The connector matrix already records per-connector scope, unreachable areas,
permissions used and pagination status — carry it through.

---

## What not to do

- **Do not start at `ENFORCE`.** A wrong block in week one ends the pilot and
  deserves to.
- **Do not quote detection metrics from our corpus as their expected results.**
  Our recall figures are an upper bound measured on evasions we already know
  about. Say so.
- **Do not present a clean simulation as proof enforcement is safe.**
  Simulation replays what happened; enforcement changes what happens next.
- **Do not let a pilot finding become a marketing claim** without the partner's
  written agreement on the wording.
- **Do not fill a gap with an estimate.** An unmeasured number in a pilot report
  is the one thing that destroys the credibility of every measured number
  beside it.

---

## When the gate flips

`design_partner_validation` moves from `UNVERIFIED` only when a real
organisation has completed the agreed validation and a human records that
outcome.

---

## Related

- [`RELEASE_READINESS.md`](RELEASE_READINESS.md) — the two scoreboards
- [`CONNECTOR_MATRIX.md`](CONNECTOR_MATRIX.md) — coverage per connector
- [`OPERATIONS.md`](OPERATIONS.md#observability) — what a partner can measure
