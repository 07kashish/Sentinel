# Automated response and containment

Phase 4 of the master specification: sections 32 (human approval), 33 (safe
autonomous response), 34 (real remediation executors), 35 (emergency kill
switch) and 37 (SOAR / ITSM).

This is the point in the product where a detector stops writing rows and starts
breaking things. Every other subsystem's worst failure is a missed alert or a
noisy one. This one's worst failure is stopping production work that was fine.

Everything below is organised around that asymmetry.

---

## 1. What the system may do, and who decides

Two questions, deliberately separated across two modules:

| Question | Module |
|---|---|
| What is this action, and can it be undone? | `sentinel/domain/remediation.py` |
| May it run without a human? | `decide_response`, same module |

`REMEDIATION_ACTIONS` is the catalogue from §34 — all fourteen named actions,
plus their inverses, plus `pause_high_risk_agents` from §35. Each entry declares
its blast radius, whether it is reversible, and whether it disrupts work.

Those flags are **read by the strategy**, not documentation. An action that
declares `reversible=True` without a real inverse is the way to get it run
automatically when it should not have been, which is why
`test_every_reversible_action_names_a_rollback_that_actually_exists` resolves
every declared rollback through the catalogue.

### The response strategy (§33)

```
LOW      → notify (non-disruptive only), otherwise observe
MEDIUM   → automatic, reversible actions only
HIGH     → human approval
CRITICAL → deterministic emergency containment, from a fixed list
```

`decide_response` is a pure function of severity and the action's own
properties. The specification is emphatic — *"Do NOT give an LLM unrestricted
power to perform remediation"* — and that requirement is satisfied here by there
being **nowhere for a model to plug in**, rather than by a comment asking
callers not to. `test_the_strategy_reads_nothing_but_its_arguments` holds it
there.

---

## 2. The attack that shaped this, and where it stops

This is the part worth reading even if you skip the rest.

Phase 3 raises incident severity when a sequence rule matches on the execution
graph. That graph is built from `eventId`, `sessionId` and `parentEventId` —
**all three self-reported by the agent**. `execution_graph.py` is explicit that
this makes it evidence and never authority, and that nothing in the enforcement
path consults it.

Severity-driven automatic containment would have undone that guarantee from a
different direction:

1. A hostile agent forges a `credential_to_privilege` chain — three JSON bodies.
2. That rule scores 90. Severity 90 is `CRITICAL`.
3. `CRITICAL` triggers deterministic containment.
4. Point the forged `sessionId` at **a different agent** and you have disabled
   somebody else's production agent by writing three HTTP requests.

So evidence provenance travels with the severity:

```python
decide_response(action, severity, origin=EvidenceOrigin.OBSERVED)      # may automate
decide_response(action, severity, origin=EvidenceOrigin.SELF_REPORTED) # never automates
```

`SELF_REPORTED` caps the disposition at `REQUIRE_APPROVAL` **at any severity**.
The finding still reaches a human at full weight — the severity is not reduced —
it simply does not get to pull the trigger by itself.

`EvidenceOrigin.SELF_REPORTED` is the **default**, so a caller who forgets the
argument gets a human in the loop rather than an automatic action against
production. The safe value is the one you get by accident.

Written down as a test:
`test_a_forged_sequence_chain_cannot_trigger_automatic_containment`.

### Two further ceilings

- **Estate-wide actions are never automatic, at any severity.** A false positive
  on an action that halts a fleet *is* the incident.
  (`test_an_estate_wide_action_is_never_automatic_at_any_severity`)
- **Containment is a fixed list, not a threshold.** `kill_container` is drastic
  and irreversible; no severity promotes it into the automatic set.
  (`test_critical_severity_does_not_promote_an_action_outside_the_declared_set`)

---

## 3. Executing an action (§34)

`GuardedRemediationExecutor` implements the six required properties **once**,
wrapping whatever actually talks to AWS, Kubernetes or GitHub:

| Property | Where |
|---|---|
| dry run | returns a receipt with `executed=False`, never reaches the integration |
| authorization | `AllowListAuthorizer`, default deny, checked **before** the dry run |
| audit | every outcome including refusals and failures |
| idempotency | a replayed key returns the prior receipt and makes no call |
| rollback | `rollback()` runs the catalogued inverse under a distinct key |
| failure handling | errors re-raised unchanged so transient stays distinguishable from refused |

Fourteen actions across six providers means implementing these in each
integration would mean writing them fourteen times, and the thirteenth would
differ from the first in some way nobody notices until an auditor asks.

### The lie this is shaped against

`executors.py` records the predecessor's defect: it returned
`status="simulated", executed=false` from what looked like a success path,
*"which reads as success to any caller that only checks for an exception"*.

**Dry run reintroduces exactly that risk**, because a dry run *is* a successful
call that did nothing. So `executed` and `dry_run` are independent fields, and:

- `test_a_dry_run_never_reports_that_it_executed`
- `test_a_dry_run_does_not_satisfy_a_later_real_attempt` — otherwise "preview
  it, then do it" silently becomes "preview it, then think you did it"
- `test_a_dry_run_cannot_be_rolled_back`

---

## 4. The kill switch (§35)

Six scopes, tenant-scoped, revocable, expiring:

```
agent · agent_group · tool · mcp_server · credential · high_risk_agents
```

### Why the existing one was not enough

`ProtectControls.kill_switch` is a process-local boolean from
`SENTINEL_PROTECT_KILL_SWITCH`. It is the right tool for one job — an operator
with shell access halting a runaway deployment — and it can do none of the six
things above. It is not tenant-scoped (one tenant's emergency stops every
tenant sharing the process), not granular, not revocable without a restart, and
records nobody's name.

Both now exist. They answer different questions.

### Properties that matter

- **Exact matching, never substring.** A block on `bot` matching `chatbot-7` is
  over-blocking, which operators forgive least because it looks like the product
  being broken. (`test_a_containment_matches_exactly_and_not_by_substring`)
- **Expiry.** A 3am pause nobody lifts becomes a silent permanent state.
  Indefinite is allowed, but it is a choice made at creation.
- **The narrowest match is reported first** — it is the one an operator can lift
  without re-opening the whole estate.
- **Attribution is mandatory.** A kill switch with no name attached is an outage
  with no owner. (`test_a_containment_must_record_who_authorized_it`)

### Fail-open on the lookup, stale-on-error

Containment is a *deny* list. Failing closed on an unreadable deny list means a
database blip halts every agent in every tenant — the transient fault becomes a
larger outage than the attack the control defends against.

But when a cached set is held and the store becomes unreadable, `ContainmentGuard`
serves **the cached set rather than an empty one**, so a blip does not briefly
lift every containment. Both paths log loudly; a kill switch that is quietly
serving old data is one nobody knows to distrust.

- `test_an_unreadable_store_serves_the_cached_set_rather_than_lifting_it`
- `test_an_unreadable_store_with_no_cache_fails_closed_and_is_logged_loudly`

`CACHE_TTL_SECONDS` is the worst-case delay between an operator hitting the
switch and it taking effect. It is chosen as a security property, not a
performance one.

### It is actually on the enforcement path

The failure mode for all of the above is a containment table nothing reads,
which is indistinguishable from a working one until it matters.
`ProtectedToolRunner` consults it **before** the gate — a containment is an
operator's explicit override and should not depend on a policy evaluation
succeeding.

- `test_the_runner_consults_containment_when_one_is_configured`
- `test_an_uncontained_agent_still_runs` — a switch that blocks everything is
  not a switch
- `test_containing_a_tool_stops_it_for_every_agent`

---

### Operator surface

```
POST   /v1/containments            → activate   (201)
DELETE /v1/containments/{id}       → lift       (200)
```

Both require `MANAGE_CONTAINMENT`, held by `analyst` and `admin`. It is
deliberately **not** folded into `DECIDE_APPROVAL`: approving starts an action
against one named target that a policy already proposed, while containment stops
work across a scope the caller chooses. Different blast radius is a different
grant, so an integration that can approve a proposed remediation cannot thereby
halt an estate.

It is also not admin-only. §35 wants this reachable fast by whoever is handling
the incident, and a control that requires finding an administrator at 3am is one
that gets worked around.

An `ingest` credential — held by the agents being watched — cannot activate
containment at all. (`test_an_agent_credential_cannot_contain_anything`)

Lifting an unknown id and lifting an already-lifted one return the **same**
refusal, so a caller cannot use the difference to discover whether an id exists
in a tenant they are probing.
(`test_lifting_an_unknown_containment_does_not_disclose_whether_it_exists`)

### Retention: the predicate that must not be dropped

Containments are reaped by the retention sweep, but only once `revoked_at` is
set:

```sql
DELETE FROM containments
WHERE tenant_id = ? AND revoked_at <> '' AND revoked_at < ?
```

Without `revoked_at <> ''`, an indefinite containment whose `created_at` had
aged past the cutoff would be swept away — silently un-blocking an agent an
operator had stopped. **A retention job that lifts a kill switch is the worst
possible way to discover a missing `WHERE` clause**, so
`test_retention_never_deletes_an_active_containment` runs that exact predicate
against one active and one revoked row on both engines.

The permanent record is not lost: `security_audit` holds
`containment.activate` and `containment.lift` for every one of these, is
hash-chained, and is declared append-only.

---

## 5. Human approval (§32)

The approval execution path already had the hard part right: claim, then act,
then record, with a conditional `UPDATE` as the claim. What it lacked was
**content**.

### The expiry is a security fix, not a field

An approval with no window is a standing authorization to act on production.
Approved three months after it was raised — against an estate that has changed,
over an incident long since closed — it still fires, and the analyst clicking
approve is agreeing to a situation that no longer exists.

`expires_at` is checked **after the claim** (so the caller owns the row; checking
before would let two concurrent decisions both pass and race on to the claim,
which is the shape of the original defect) and **before any external effect**.
The state moves to `expired`, which is terminal — a retry cannot walk it back
open.

This required three things to line up: a column, a hydration line, and a branch
in the handler. Miss the hydration line and `expires_at` is permanently `None`,
making the branch unreachable — a gate that executes nothing.
`test_an_approval_expiry_survives_a_write_and_a_read` goes through real storage
on both engines to catch exactly that.

`context` carries the rest of §32: risk factors, execution graph session,
business impact, recommended decision.

---

## 6. SOAR / ITSM (§37)

ServiceNow, Jira, PagerDuty, Slack, Teams and a generic webhook.

### The content is attacker-controlled and going somewhere privileged

This is what makes SOAR different from an ordinary integration. Incident fields
carry text the attacker chose — the tool name they invoked, the resource path,
the destination, and since Phase 3 the prompt text itself. That text is about to
render in a Slack channel full of people with production access, and in a ticket
an on-call engineer will read at 3am and act on.

Two concrete failures, both closed:

- **`@channel` in a resource path pages the entire security team.** An attacker
  who can trigger a low-severity incident gets a free megaphone — and after the
  third one the team mutes the channel, which disables the alerting path for
  real incidents. Denial of service by alert fatigue.
  (`test_a_broadcast_mention_in_incident_text_cannot_page_the_channel`)
- **A ticket description containing `Approved by: security — safe to close`** is
  a social-engineering payload delivered by the security tool itself, with the
  credibility of having arrived through it. Newlines are collapsed so a value
  cannot insert its own label.
  (`test_a_newline_cannot_forge_a_ticket_field`)

Escaping order follows the same rule as `escape_cef_header`: ampersand before
angle brackets, or a literal `&lt;` the attacker typed becomes a real `<` on the
way out. (`test_ampersand_is_escaped_before_the_angle_brackets`)

### Delivery

Fan-out is independent and failures are collected, never raised. A ServiceNow
outage must not stop the Slack notification — during an incident those are the
minutes that matter. Partial delivery is logged, because silent partial delivery
is how a team believes the SOC was notified.

- `test_one_failing_connector_does_not_stop_the_others`
- `test_partial_delivery_is_logged_rather_than_silent`

`should_dispatch` defaults to HIGH and above. This codebase has measured what
happens without a threshold — a detector firing on 51.7% of ordinary tool calls
— and the same failure with a ticket queue attached is worse.

---

## 7. Known limits

Stated rather than left to be discovered:

- **`InMemoryIdempotencyStore` is process-local.** It dedupes retries within one
  process and does nothing across replicas. Real cross-replica exclusivity is
  the approval claim in `DecideApprovalHandler`, which is a conditional `UPDATE`
  in the database. This is a second layer, not the primary defence.
- **`GuardedRemediationExecutor.rollback` has no `ProtectedToolRunner` of its
  own.** Nothing calls it today and
  `test_no_application_code_calls_rollback_directly` keeps that true, but any
  future application-layer caller must wrap it the way `decide_approval` wraps
  the forward action.
- **There are no per-provider SDK adapters yet, and this is the largest gap.**
  §34 names AWS, Azure, GCP, Kubernetes, GitHub and Okta/Entra as initial
  targets. What exists is `HttpRemediationIntegration`: a real, working adapter
  that posts to an operator-configured endpoint through the hardened outbound
  client. What does **not** exist is provider-specific authentication — SigV4
  request signing for AWS, in-cluster service-account tokens for Kubernetes, and
  so on.

  A deployment can therefore drive any of the fourteen actions through a
  webhook or a small broker it runs itself, and cannot yet point Sentinel
  straight at an AWS account. Closing this means writing and *testing* signed
  requests against each provider, which needs real credentials against real
  accounts.

  What it deliberately does not do is pretend. An action with no configured
  integration is `unsupported_action` with a receipt saying nothing ran — it does
  not quietly succeed, and it does not quietly dry-run, because a dry run nobody
  asked for is a failed remediation reporting success. `supports()` additionally
  requires the action to be in the catalogue, so a misconfigured registration
  surfaces as a clear refusal rather than as a retryable "provider trouble" that
  would be retried for ever.
- **SOAR dispatch is synchronous, inside the request path.** The subscriber
  fires after the transaction commits — so a slow ServiceNow cannot hold a
  database transaction open — but it still runs before the ingest response is
  returned. A slow or hanging connector therefore adds latency to the request
  that triggered it.

  Two things bound the damage today: only HIGH and CRITICAL incidents dispatch
  at all, and a failing connector is caught rather than raised. Neither helps
  during an incident storm, which is precisely when ingest latency matters most
  and when the most notifications fire.

  **The correct fix is the outbox that already exists** — `outbox` is described
  in this codebase as "a durable intent to perform an externally-visible
  effect", which is exactly what a SOAR notification is, and it already has a
  separate dispatcher with leased delivery and retry. Routing SOAR through it
  would remove the latency coupling and make delivery survive a process
  restart, which the current design does not. This is a known gap, not a
  finished design.

- **SOAR connectors are configured per DEPLOYMENT, not per tenant.** One set of
  endpoints receives every tenant's incidents in that deployment. For a
  single-tenant install (customer VPC, on-premises) that is exactly right. For a
  multi-tenant SaaS install it means incident summaries for all tenants reach
  the operator's own SOC tooling — which is the vendor's SOC, and defensible,
  but it is not the same thing as each customer's incidents reaching their own
  Slack. Per-tenant connector configuration is not implemented. A deployment
  that needs it should run one deployment per tenant, which the residency work
  in `ENTERPRISE_CONTROLS.md` already assumes is possible.

- **Containment cache TTL bounds propagation across replicas.** The process that
  handled the operator's request invalidates immediately; others wait out
  `CACHE_TTL_SECONDS`.

---

## 8. How this is wired, and why that has its own section

Phase 4 was first written, tested and reported complete while **four of its five
sections were unreachable in production**. Every component below existed, had
passing tests, and was called by nothing:

| Component | State when first reported "complete" |
|---|---|
| `decide_response` | 12 passing tests, **zero callers** |
| `GuardedRemediationExecutor` | 20 passing tests, container hardcoded `NullRemediationExecutor` |
| `SoarDispatcher` | 6 connectors + escaping, **constructed by nothing** |
| `ApprovalRecord.expires_at` | column + hydration + enforced branch, **nothing set it** |

The last one is the clearest: the expiry had a database column, a hydration
line, a branch in `DecideApprovalHandler` and a test proving the branch works —
and the single site that creates approvals never passed the field. Every real
approval therefore had `expires_at = None`, so the branch could not be taken.
Described as "a security fix, not a field," it was at that point neither.

Unit tests could not catch any of this, because a unit test calls the component
directly. **A passing test proves a component works; it never proves anything
uses it.**

### The three things that now hold it in place

**`tests_arch/test_components_are_reachable.py`** fails the build when a
load-bearing component is referenced by no other module under `sentinel/`. Test
references do not count — tests are exactly what failed to notice. On its first
run it immediately found two more, both from Phase 3: `compare_to_baseline` and
`assess_intent_divergence` were built, tested, reported complete, and reachable
from nothing, so no agent could ever be flagged for departing from its own
baseline or contradicting its declared intent. Both are now called from
`AdmitEventHandler`.

**`tests_arch/test_phase4_wiring.py`** follows the value rather than the
reference. A reference is not a wire: it asserts a proposed approval actually
carries an expiry and the §32 context, that the recommended decision comes from
`decide_response`, and that the container yields `Null` or `Guarded` according
to configuration.

**`test_every_proposed_action_is_in_the_catalogue`** closes a vocabulary
mismatch that would have made every remediation refuse. `RuleBasedPlanner`
proposed `quarantine_agent_session`, `revoke_tool_grant`, `isolate_agent` and
`require_human_review` — **none of which exist in the catalogue**. This was
invisible while the deployment ran `NullRemediationExecutor`, which refuses
everything identically. The moment a real executor was wired, every proposal
would have become an approval an analyst could click that could never do
anything. The same failure Phase 3 hit with sequence rules written for action
names no agent emits.

### Configuration

```bash
SENTINEL_REMEDIATION_ENDPOINTS="disable_agent=https://...,notify_owner=https://..."
SENTINEL_REMEDIATION_DRY_RUN=false
SENTINEL_SOAR_ENDPOINTS="slack=https://...,servicenow=https://..."
SENTINEL_SOAR_PAGERDUTY_ROUTING_KEY="..."
SENTINEL_SOAR_MIN_PRIORITY=HIGH
```

Both endpoint maps are validated **at startup**, not at first use: an action or
connector name that is not recognised, or any non-HTTPS URL, refuses to boot. A
typo would otherwise register an integration under a name no proposal can
produce, and the deployment would look configured while being unable to
remediate anything — discovered during an incident. A plaintext endpoint that
can disable production agents can be forged by anyone on the path.

Unset means unconfigured, which is an explicit supported state: `Null` refuses
every action with a reason, and no SOAR dispatcher is built at all.
