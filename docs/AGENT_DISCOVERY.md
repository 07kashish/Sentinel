# Agent discovery and the attack surface graph

Phase 2 §15–16. Companion to [MCP_GATEWAY.md](MCP_GATEWAY.md) and
[TOOL_GATEWAY.md](TOOL_GATEWAY.md).

## The defect, demonstrated before it was fixed

`AdmitEvent` recorded contact only for agents that were **both enrolled and
signed**:

```python
if identity.trust is TrustLevel.VERIFIED and identity.address is not None:
    self._agents.record_event(tenant, address=identity.address, at=now)
```

`record_event` issues `UPDATE agents ... WHERE address=?`. For an agent nobody
enrolled that updates **zero rows**, and the agent leaves no trace.

Run against a live build:

```
ingest of an UNENROLLED agent -> 202
rows in `agents` table        -> []
incidents created             -> 1        (severity 79, HIGH)
```

Sentinel knew something bad had happened and could not say who did it. So
"unknown agents must be classified as unmanaged" was not merely unimplemented —
it was **unimplementable**, because the data was never recorded.

A shadow agent is not hypothetical. It is the normal outcome of a platform team
moving fast, and it is invisible precisely because nobody enrolled it.

## Classification

| State | Meaning |
|---|---|
| `managed` | Enrolled and active. The intended state, and the only one that does not need attention. |
| `unmanaged` | Observed sending events, never enrolled. The shadow agent. |
| `revoked_but_active` | Enrolled, **revoked**, and still sending events. |

`revoked_but_active` is its own member deliberately. Somebody withdrew that
agent's standing and it is still running — calling that "unmanaged" understates
it and "managed" is false, so a two-state enum would have hidden the one case
that most needs to be seen
(`test_a_revoked_agent_still_sending_events_is_not_folded_into_either_bucket`).

Classification is **derived** by comparing observation against enrolment, never
stored — a stored value can drift from the two facts it summarises, and the
drift would surface as an agent still marked `managed` after revocation.

## Observation is not authorisation

The easiest way to ruin this feature would be to let *"we have seen it"* quietly
imply *"it is fine"*. If observation wrote to the enrolment table, an attacker
could enrol themselves by sending one event.

`test_observing_an_agent_does_not_enrol_it` asserts the enrolment table stays
empty after an observation, and `test_observing_an_agent_grants_it_nothing`
asserts it confers no capability.

The agent id is **self-reported**, which is exactly why it is safe to record and
would not be safe to act on. An attacker forging an id gets themselves listed as
an unmanaged agent rather than promoted to a managed one.

## The attack surface graph

Edges are recorded per `(agent, kind, target)`, with occurrence counts — an edge
seen once and an edge seen four thousand times are different facts, and a graph
that flattens them makes every agent look equally connected.

```bash
python -m sentinel.interface.cli agent-inventory acme
python -m sentinel.interface.cli agent-reach acme destination 'https://%'
python -m sentinel.interface.cli agent-reach acme resource '%pii%'
```

```
! shadow-agent      unmanaged   events=2  incidents=1
    sent data to: https://evil.example
! reporting-agent   unmanaged   events=1  incidents=0
```

Queries are scoped to an edge **kind**: an agent whose *action* is named
`customer_pii_sync` has not read PII, and a query ignoring kind would report it
as though it had (`test_the_reachability_query_is_scoped_to_the_edge_kind`).

`ungranted_tools_used` is the most actionable line in a profile — tools an agent
**used** that it was never **granted**. It is the list to work through before
turning capability enforcement on, and it should be empty afterwards, which
makes it a check on the rollout rather than only a report.

### A second defect this surfaced

`EventPayload` had **no `destination` field**, so pydantic silently discarded
it — while `docs/history/PILOT_README.md` documents `destination` in both its PowerShell and
curl examples. Every pilot following the instructions was sending a field that
went nowhere.

That is the edge answering "can this agent send data **out**", so the graph's
most important question was unanswerable. Everything else records what was
touched; `destination` records where it went.

## What is NOT inferred

The specification's profile lists Owner, Team, Purpose, Framework, Model,
Environment and Risk Tier. **None are observable from a stream of tool calls.**
Guessing them would be fabrication, and this product's claim is that it does not
invent findings. They live in `AgentProfile.declared`, visibly separate from
everything Sentinel worked out for itself, and are absent until a human writes
them down.

Likewise the graph has no `HUMAN` or `CLOUD_ENVIRONMENT` edge: Sentinel does not
observe those, and a graph with invented nodes answers reachability questions
wrongly in the direction that gets somebody hurt.

Sentinel also does not know that `orders_pii` is PII or that `s3://backups` is
production. `agents_reaching` takes a pattern from the operator rather than
shipping a built-in guess, because answering a security question with a hunch is
worse than declining to answer it.

## Bounds, because this runs on the ingest hot path

| Bound | Value | Why |
|---|---|---|
| Edges per agent | `MAX_EDGES_PER_AGENT` | An agent touching a million distinct paths must not become a million rows |
| Target length | `MAX_TARGET_CHARS` | A path is attacker-influenced text |

The cap is on **breadth**, not repetition: only a *new* target consumes
headroom, so an agent hammering one resource keeps being counted however long it
runs (`test_a_repeated_target_is_never_capped_out`). An overlong target is
truncated rather than refused — refusing would lose the **agent** as well as the
target, and the agent is the more valuable of the two.

Discovery failure never rejects an event. Visibility is not enforcement: losing
an inventory row is a degraded inventory, while losing the event is a blind spot
in the thing this product is for.

## Retention

`agent_observed_edges` is **reaped**, not declared append-only — unlike
`agent_tool_grants`, which is bounded by agents × tools. An edge exists per
*distinct target*: one row for every path, URL and table an agent has ever
touched, which is unbounded by construction.

Reaped on `last_seen`, so an edge survives as long as it keeps being observed.
Attack surface is what an agent can reach **now**; a path read once ninety days
ago and never again is history rather than exposure. The observation row goes
only when nothing is left to describe — deleting it while its edges survived
would orphan them and leave the graph saying "something reads `/etc/shadow`"
without saying what.

---

## Infrastructure discovery: asking the cluster instead of the telemetry

Everything above classifies agents that **sent Sentinel an event**. That answers
"which of the agents talking to us are enrolled". The question an operator asked
was "what is running", and the agent an attacker introduced yesterday is exactly
the one that will not be sending telemetry — it is not classified `unmanaged`, it
is **absent**.

`sentinel/infrastructure/platforms/discovery.py` asks the infrastructure,
using the credentials the Tier-1 adapters already hold.

```bash
python -m sentinel.interface.cli agent-discover <tenant> <namespace>...
```

### Why it is a CLI command

It reads with the deployment's Kubernetes credential across whole namespaces —
a broader read than anything the HTTP surface performs. MCP enrolment is
CLI-only for the same reason: an analyst who can call `/v1/incidents` should not
thereby be able to enumerate every workload in production.

### `revoked_but_active` is the finding that justifies it

An agent whose enrolment was withdrawn and whose pod is still running is
**invisible** to telemetry-based inventory: it stopped reporting, so it stopped
appearing. Reconciliation reuses `AgentClassification` rather than inventing a
parallel vocabulary — two enums for one concept is two enums that drift
(`test_reconciliation_reuses_the_inventory_vocabulary`,
`test_a_running_workload_whose_enrolment_was_revoked_is_the_headline`).

### Recognition is by declared marker, not by guessing

A workload is a candidate because it carries a label, an annotation, or an image
name that says so — something a team wrote on purpose. Heuristics over process
names and open ports would produce a longer list and a worse one: an operator
who dismisses forty false candidates stops reading, and then the real one goes
unnoticed too.

`app.kubernetes.io/component` is matched on its **value**, not its key
(`test_a_generic_component_label_matches_on_its_value_not_its_key`) — most
workloads in a well-labelled cluster carry that key, and matching it would report
the whole namespace.

An identity taken from a pod name rather than an annotation is flagged
`identity_is_declared: false`
(`test_an_undeclared_identity_is_flagged_as_a_guess`). A name-based match is an
inference and a reader must be able to tell.

### The denominator is not optional

Every report carries its scope, its holes and its limits.

| Field | Why |
|---|---|
| `examined` | the denominator. `found: 2` without it is a number with no meaning |
| `scope` | which namespaces were actually listed |
| `unreachable` | namespaces that could not be read, with the reason |
| `limits` | what the marker approach structurally cannot see |

A namespace that failed to list is a **hole**, and a report that hides its holes
is worse than one that admits them
(`test_a_namespace_that_cannot_be_listed_is_a_recorded_hole`). A truncated IAM
listing is reported as incomplete rather than paged through silently
(`test_a_truncated_listing_is_reported_as_incomplete`).

Namespaces are **required**, never defaulted
(`test_namespaces_are_required_rather_than_defaulted`): falling back to `default`
would produce a confident report about one namespace out of forty.

### NOT_SUPPORTED, said plainly

A deployment with no Kubernetes credential gets a refusal and exit code 78, not
an empty list (`test_discovery_without_a_cluster_credential_says_not_supported`).
An empty result would read as "nothing is running" — the single most dangerous
wrong answer this command has, because an operator concludes the cluster is clean
when it was never looked at. A run that could not read part of its scope exits
non-zero, so a script grepping the output cannot treat a half-read cluster as a
pass.

### What it does not find

An agent on a laptop. An agent in a cloud account nobody supplied a credential
for. A namespace the token cannot list. A framework whose image and labels match
nothing on the marker list. A serverless function.

**Absence from the list is not evidence that nothing is running.** That sentence
is in the module docstring, in this document, and in the `limits` field of every
report produced (`test_every_report_carries_its_own_limits`).
