# A2A gateway: delegation lineage, privilege amplification, agent cards

## The question this answers

When a Finance Agent asks a Research Agent to fetch a document, and the Research
Agent calls a tool that reads customer records, the record of that read says
`research-agent`. That is true and it is useless. The authority came from an
employee who asked for a quarterly report, through two agents, and the only
question an incident review has is whether that employee's authority actually
extended this far.

`execution_graph.py` records that the calls happened. `sentinel/domain/a2a.py`
records what each hop was **entitled to**, and refuses the ones that were not.

## Why delegation is not just another graph edge

An edge in the execution graph is an *observation*: this happened. A delegation
hop is a *claim*: I am permitted to ask you to do this, on behalf of someone who
permitted me. Claims can be false, and the failure modes are specific.

| Finding | Severity | What it means |
|---|---|---|
| `privilege_amplification` | critical | a hop granted a scope its delegator did not hold |
| `unenrolled_agent` | critical | delegation to an agent nobody registered |
| `unknown_principal` | critical | the chain is rooted in nobody |
| `card_drift` | high | the target's capabilities changed after approval |
| `capability_not_advertised` | high | the target was granted something its card never claimed |
| `task_replay` | high | the same task id presented twice |
| `delegation_loop` | high | an agent appears twice in one chain |
| `depth_exceeded` | moderate | longer than any human reviewing hop 1 could anticipate |
| `self_delegation` | moderate | an agent delegated to itself |

## Privilege amplification is the one a graph cannot see

Every other finding is detectable by looking at a single hop. Amplification is
not: each hop can look locally reasonable and the chain still ends somewhere
nobody authorised.

```text
alice          holds  read:*
  │  grants read:docs
  ▼
finance-agent  holds  read:docs          ← narrowed, correctly
  │  grants read:customers               ← it does not hold this
  ▼
research-agent                            PRIVILEGE AMPLIFICATION
```

The comparison is against what the delegator held **at that point**, never
against the principal's original scopes. Comparing to the origin would call this
chain fine, because Alice *could* have granted `read:customers` — she just
didn't, and the finance agent had already dropped it
(`test_a_scope_dropped_at_one_hop_cannot_be_regained_later`).

### Monotonic narrowing

Authority may narrow along a chain and may never widen, so `effective_scopes` is
an **intersection** (`test_narrowing_is_an_intersection_not_a_union`). A union
would make every chain end with the sum of everything anyone granted anywhere in
it, which is the opposite of delegation.

Wildcards match one **segment**, not a string prefix: `read:*` covers
`read:customers` and does *not* cover `read:customers:pii`
(`test_a_wildcard_covers_one_segment_and_not_a_deeper_one`). A scope that covered
everything beneath it would make narrowing impossible to express.

## Agent cards, and why the fingerprint ignores prose

An agent enrolled as `research-agent` advertising `read:docs` on Monday and
`read:customers` on Friday presents the same **name** to the same allowlist. Only
a fingerprint over the capabilities catches it — the same failure and the same
fix as MCP tool-definition drift.

The fingerprint covers the agent id, version, endpoint and capabilities. It does
**not** cover the description or display name
(`test_the_fingerprint_covers_capabilities_and_ignores_prose`). A publisher
rewording a description would otherwise raise drift nobody can action, and that
is how a drift alert comes to be ignored.

An agent with **no pin** is not reported as drift
(`test_an_agent_with_no_pin_is_not_reported_as_drift`). "Changed since approval"
and "never approved" need different operator responses, and conflating them makes
both harder to act on.

## Cross-agent injection lives in the prose

The instruction one agent sends another is text a model reads and acts on, and it
may have originated in a document nobody vetted. Inspecting the **scopes** will
never find it. The instruction goes into `metadata.prompt` — the same field an
MCP tool description goes to — so the existing deterministic detector reads it
(`test_the_instruction_reaches_the_injection_detector`).

## One ruleset, three paths

The gateway does **not** decide ALLOW / WARN / REQUIRE_APPROVAL / BLOCK.
`ProtectGate` does, from the deterministic policy, and every delegation is
projected onto the payload that gate already understands. The protect path, the
MCP path and this one share one ruleset, so there is no third place for them to
disagree.

The projection names both the terminal agent and the human principal
(`test_the_projection_names_both_the_terminal_agent_and_the_principal`): policy
rules are written against `agentId`, and an investigator needs the principal.
Amplification is projected as its own boolean so a rule can match that one case
without substring-matching a list of finding names
(`test_amplification_is_projected_as_its_own_flag`).

### Structural refusal is independent of policy

`require_allowed` refuses on a CRITICAL structural finding **regardless of what
policy decided** (`test_a_critical_structural_finding_refuses_regardless_of_policy`).
Policy can be misconfigured; privilege amplification is not a matter of opinion,
and a deployment whose rules happen not to match must still not execute a
delegation that laundered authority.

Task ids are recorded only on the allowed path
(`test_a_refused_delegation_does_not_burn_its_task_id`) — recording a refused
delegation's task would make the operator's corrected retry look like a replay.
Replay state is per tenant (`test_a_replay_is_scoped_to_one_tenant`).

## HTTP surface

| Method | Path | Capability |
|---|---|---|
| POST | `/v1/a2a/evaluate` | `evaluate_protect` — same question as `/v1/protect/evaluate`, richer subject |
| POST | `/v1/a2a/cards` | `manage_policy` — **admin-only** |

Enrolment takes `manage_policy` because a caller able to enrol is a caller able
to re-pin a drifted card as the new normal, which is the one operation that can
silence drift detection permanently: durable, silent, and undetectable for
months — the failure shape `MANAGE_POLICY` exists for, rather than the
minutes-to-notice shape `MANAGE_CONTAINMENT` covers.

`MANAGE_AGENTS` would read as the natural name and does not exist. It was removed
as a capability defined, granted and enforced nowhere; reintroducing it for one
route would recreate the table an access review misreads.

There is no field for whether the principal is known — that is resolved from the
tenant's directory, so a caller cannot assert its own chain into
attributability. A directory holding nobody yields "no opinion" rather than an
empty set, because an empty set would make every chain `unknown_principal` and a
deployment that has not wired SCIM yet would have every delegation refused. That
is not a safe default; it is an unusable one, and unusable controls get switched
off.

## Known limitations

These are stated rather than implied, and none of them is claimed as working.

1. ~~The card store is in-process.~~ **Resolved.** `SqlAgentCardRegistry` and
   `SqlTaskLedger` (schema v29, table `a2a_agent_cards`, under RLS with the
   other tenant tables) make cards and replay state durable and shared. The
   in-process store it replaces held pins in one worker's memory, so
   `card_drift` could not fire at all in a multi-replica deployment and
   `unenrolled_agent` fired for agents that *were* enrolled, just not on that
   replica. `test_a_card_enrolled_on_one_replica_is_visible_to_another` and
   `test_a_replayed_task_is_caught_by_a_different_replica` are the tests that
   distinguish those two situations, and both run against SQLite **and**
   PostgreSQL because RLS exists on only one of them.

   The replay ledger reuses `replay_nonces` with `agent` fixed to `a2a` as a
   namespace, so a task id cannot collide with a signed event's digest
   (`test_a_task_id_is_namespaced_so_it_cannot_collide_with_an_event_digest`).
   That does inherit the retention window: **a delegation replayed after the
   nonce expires is not detected**, the same bound signed-event replay
   protection operates under.

2. ~~There is no A2A wire proxy.~~ **Resolved.** `/v1/a2a/proxy/{agent_id}`
   (`interface/a2a_proxy_routes.py` + `infrastructure/a2a_wire.py`) puts the gate
   in the path rather than beside it. See the section below.

   The residual risk F-11 records is unchanged in kind: a framework that never
   points at Sentinel stays outside enforcement. The proxy narrows it from "any
   A2A traffic" to "traffic that bypasses the configured endpoint".

3. **Scopes are a Sentinel vocabulary, not an A2A protocol field.** Callers must
   map their own authority model onto `read:*`-shaped strings. Nothing validates
   that the mapping is faithful.

4. **`known_principals` is only as good as the directory.** A deployment whose
   SCIM sync is stale will see `unknown_principal` for real employees, or miss it
   for departed ones.

---

## The wire proxy

`/v1/a2a/proxy/{agent_id}` is an A2A endpoint a calling agent points at
**instead of** the remote agent. Four properties `/v1/a2a/evaluate` cannot
provide, because that route judges a delegation somebody described and this one
stands in the path.

### 1. The endpoint comes from the enrolment record

There is no URL parameter (`test_there_is_no_url_parameter_to_aim_this_process_with`).
An unenrolled `agent_id` is refused **before any network activity**
(`test_an_unenrolled_agent_is_refused_before_any_network_activity`). A caller who
wants Sentinel to reach a new agent has exactly one path: enrol it.

### 2. A laundered chain never reaches the peer

Refusal happens upstream of the network
(`test_privilege_amplification_is_refused_upstream_of_the_network`), so
amplification is *prevented* rather than reported after the message left.

**The caller's authority is not caller-supplied.** The first version of this
route read one `X-Sentinel-Scopes` header into both what the principal holds and
what the hop grants — so the two sets were equal by construction, no grant could
exceed the holding, and `find_amplification` could never fire. The check was
decorative, and the tests said so.

Authority now comes from the **calling agent's enrolled card**: what an operator
recorded it may do. The header says only what it wants to hand on. An unenrolled
caller holds nothing, so any grant it attempts is amplification
(`test_an_unenrolled_caller_holds_nothing_so_any_grant_is_amplification`,
`test_the_caller_cannot_widen_its_own_authority_with_a_header`).

### 3. The card is checked against what the peer serves *now*

The proxy fetches the agent card at call time, so the pin is compared against
what the agent claims today rather than what the caller cached
(`test_a_widened_card_is_caught_at_call_time`). The cost is one extra round trip
per call, stated rather than hidden — the same trade `mcp_proxy_routes` makes for
live tool definitions.

A card that cannot be fetched is a **refusal**, not a pass
(`test_an_unfetchable_card_refuses_rather_than_skipping_the_check`): forwarding
anyway would mean skipping the drift check while appearing to have performed it.

### 4. The reply is inspected, not only the request

Cross-agent injection travels **inbound**. A compromised peer answers with
instructions the *calling* agent's model reads and acts on, and a proxy scanning
only outbound text misses the entire class
(`test_an_injection_in_the_reply_is_refused`).

A refused reply is **not returned**, not even sanitised
(`test_a_refused_reply_is_not_returned_even_sanitised`) — editing a hostile reply
into a safe-looking one would be fabricating a peer's response.

Reply text is projected onto the same `metadata.prompt` field an outbound
instruction uses, so one ruleset governs both directions. A second inspection
path is how the two come to disagree about what an injection looks like.

### Methods

| Method | Behaviour |
|---|---|
| `message/send`, `tasks/get`, `tasks/cancel` | forwarded |
| `message/stream`, `tasks/resubscribe` | **`NOT_SUPPORTED`, by name, with the reason** |
| anything else | `-32601` |

### Streaming: a correction

An earlier version of this document said streaming **could not be secured**,
because a gate must either buffer the whole stream — not streaming — or forward
chunks nobody evaluated.

**That named two options where there are three, and it was wrong.**

The third is to inspect each chunk as it arrives, release only what passes, and
abort on the first failure. `sentinel/domain/stream_guard.py` implements it and
`tests_arch/test_stream_guard.py` holds the boundary at chunk granularity. What
is still missing is the SSE transport wiring in this route — not the security
argument — and the refusal message now says which
(`test_streaming_is_refused_by_name_with_a_reason`).

The distinction matters to an operator: one told "cannot be secured" stops
asking, where one told "not wired" might ask when it will be.

**What the guard holds, precisely:**

| Stage | What is checked |
|---|---|
| Before the first byte | Full pre-flight: delegation validity, privilege amplification, card drift against what the peer serves now, tenant and environment constraints |
| Per chunk | The chunk's text through the same detector the non-streaming path uses. A chunk that fires is **never released** — inspected before it is yielded, not after |
| On failure | Stream closed, caller told which chunk index failed and why. **No further chunks are read from the peer** — one that has begun sending an injection does not get to finish |
| Bounds | Chunk count and byte total, separately: ten thousand tiny chunks and one enormous one are different exhaustion shapes and neither bounds the other |

**What it provably cannot do:** retract a chunk already released. If chunk 7
carries an injection, chunks 1–6 are in the calling agent's context and may
already have been acted on. Aborting stops the rest; it does not undo them.

`StreamOutcome.released_before_abort` is a **field, not a footnote**, so a
caller cannot avoid seeing it — and a client that ignores `aborted` and uses the
partial text has been handed exactly the fragment an attacker chose to send
first.

### Configuration

```bash
SENTINEL_A2A_PROXY_ENABLED=true
SENTINEL_A2A_PROXY_ALLOWED_HOSTS=research.internal,billing.internal
SENTINEL_A2A_PROXY_ALLOW_PRIVATE=false
```

Its own allowlist, separate from the MCP proxy's: these are different peers
reached for different reasons, and sharing one would mean enabling the A2A proxy
silently widened what the MCP proxy could dial. Unconfigured, the route is not
registered at all (`test_an_unconfigured_deployment_has_no_route_at_all`).

### What the proxy still does not do

- **No streaming**, above.
- **Text parts only.** `file` and `data` parts are not scanned; a base64 blob
  scored as prose is noise, and noise is how a detector comes to be ignored.
  Their presence is not currently surfaced to the caller.
- **One hop per call.** The chain constructed here is caller → target. A longer
  lineage must be presented to `/v1/a2a/evaluate`; the proxy does not reconstruct
  a chain it did not carry.
