# Architecture

Canonical dependency rules, ports, CQRS and fitness tests live in
[`sentinel/ARCHITECTURE.md`](../sentinel/ARCHITECTURE.md).

<a id="architecture_baseline"></a>
<a id="architecture_baseline--architecture-baseline-phase-0"></a>
## Architecture Baseline (Phase 0)

**Status:** pre-production engineering baseline. Not a production-readiness claim.

Eighth Review F-numbers (review archived at archive/pre-cleanup) are tracked here and in
docs/STATUS.md. Do not conflate them with docs/SECURITY.md F-numbers.

<a id="architecture_baseline--current-architecture-verified-against-tree"></a>
### Current architecture (verified against tree)

Hexagonal / clean architecture under sentinel/, enforced by
tests_arch/test_architecture_rules.py:

    interface -> composition -> infrastructure -> application -> domain

Layers:
- domain/: lifecycle, fences, errors, authorization, protect decisions
- application/: commands, queries, saga engine, ports
- infrastructure/: SQL, attestation HTTP, detection policy, evidence
- composition/: sole wiring site
- interface/: HTTP/ASGI, worker, CLI

Deleted legacy tree: api/, app/, agents/, dashboard/ -- do not document as current.

<a id="architecture_baseline--target-architecture-near-term"></a>
### Target architecture (near-term)

Preserve the hexagonal core. Close Eighth Review F-1..F-12 with automated evidence.
Honest protect evaluate. Ungamed detection metrics gate. VCS + integrity discipline.
No fabricated AUC. No production-ready claim.

<a id="architecture_baseline--dependency-graph-summary"></a>
### Dependency graph (summary)

- Domain imports only stdlib + itself.
- Application depends on domain + Protocol ports.
- Infrastructure satisfies ports structurally; does not import handlers.
- Composition is the only package that may import every layer.
- Interface builds from a Container; importing a module starts nothing.

<a id="architecture_baseline--domain--state-machine"></a>
### Domain / state machine

- Pivot at attest (irreversible external anchor).
- COMPLETED_ATTESTED requires anchored outcome.
- COMPLETED_UNATTESTED for NOT_ANCHORABLE.
- ATTESTATION_UNAVAILABLE is non-terminal and resumable.
- Every mutator requires a Fence (no defaults).
- Resume hydrates evidence/report/approvals before any step handler.

<a id="architecture_baseline--actual-api-surface"></a>
### Actual API surface

- POST /v1/events (ingest_event)
- POST /v1/protect/evaluate (evaluate_protect)
- GET /v1/incidents ... (read_*)
- POST /v1/approvals/{id} (decide_approval)
- GET /health/live, /health/ready (unauthenticated, opaque)
- GET /health/diagnostics (read_diagnostics)


<a id="architecture_baseline--risks-accepted-at-phase-0"></a>
### Risks accepted at Phase 0

2. Protect enforced=true is a configured contractual gate, not packet interception.
3. Human passkey identity schema may still be WIP; directory SCIM Users + org
   HTTP APIs are behind `MANAGE_USERS` (agent enrolment remains CLI-only).
4. Not a SOC replacement; not multi-region HA.

<a id="architecture_baseline--strong-components-to-preserve"></a>
### Strong components to preserve

Fail-closed attestation dispositions; Merkle/evidence with redaction tombstones;
required Fence; sharded SqlWorkQueue; FORCE RLS; LLM advisory-only; architecture
fitness tests; chaos/concurrency/mutation suites.

<a id="architecture_baseline--related-docs"></a>
### Related docs

- sentinel/ARCHITECTURE.md -- enforced dependency rules
- docs/STATUS.md -- F-1..F-12 status
- docs/SECURITY.md -- different F-numbering
- docs/ARCHITECTURE.md


<a id="architecture_decisions"></a>
<a id="architecture_decisions--architecture-decisions"></a>
## Architecture decisions

<a id="architecture_decisions--kafka--message-broker-â-out-of-scope"></a>
#### Kafka / message broker â€” out of scope
The durable queue handles the current ingest model. A broker becomes correct when
ingest is multi-producer across systems that need independent consumer groups and
replay. Adding it now would mean a second queue alongside the database queue â€”
the split-authority class again. The queue interface is narrow enough
(`put`/`claim`/`complete`/`fail`) to swap later.

<a id="architecture_decisions--mtls--x509-service-identity-â-implemented-at-the-service-mesh-layer"></a>
#### mTLS / x509 service identity â€” implemented at the service mesh layer
Mutual TLS is enforced in Kubernetes through the Helm chart, not duplicated in
FastAPI. `deploy/helm/sentinel/templates/mtls.yaml` renders an Istio
`PeerAuthentication` with `STRICT` mode for Sentinel pods and a `DestinationRule`
using `ISTIO_MUTUAL` for in-mesh calls to the Sentinel service. The chart schema
requires this block and restricts the mode to `STRICT`, so a production render
cannot silently downgrade to permissive transport.

Sentinel still authenticates callers by API key, OIDC bearer token, or the
browser OIDC session. mTLS supplies workload-to-workload transport identity and
encryption; application RBAC remains the authorization boundary.

---


<a id="architecture_review"></a>
<a id="architecture_review--preserved-architecture-constraints"></a>
## Preserved architecture constraints

1. **The LLM stays out of the control path.** Deterministic authority is the best decision in this codebase.
2. **`lifecycle.py` stays pure.** Extend it; do not give it I/O.
3. **Fail-closed `verify_package`.** Never accept a trust root from the package.
3. **Identity-bound Merkle leaves.** Do not "optimise" to body-only hashing.
4. **Redaction-preserving chains.**
5. **Fail-closed config validation.** Refusing to boot is correct.
6. **`create_in` / `store_evidence` single-transaction commits.**

Preserve second-preimage prefixes and odd-node geometry checks in Merkle verification,
constant-time key comparison with no early exit, and refusal to downgrade failed OIDC
authentication to API-key authentication.

The predecessor review's full findings remain in the
[archive](https://github.com/07kashish/Sentinel/blob/d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6/docs/ARCHITECTURE.md).
Its `api/` and `app/` implementation inventory does not describe the current tree.

**Every asserted invariant has an executable guard.**
**Seams are tested, not just units.**
**Ports and adapters at every I/O boundary** — storage, LLM, attestation gateway, threat intel, notification.


<a id="aws_production_architecture"></a>
<a id="aws_production_architecture--aws-deployment-design"></a>
## AWS deployment design

<a id="aws_production_architecture--1-nat-is-off-by-default-and-that-is-a-real-constraint"></a>
#### 1. NAT is off by default, and that is a real constraint

Private subnets reach AWS through VPC endpoints instead.

**The trade-off, stated rather than buried:** with NAT off, tasks cannot reach
the public internet *at all*. In dev, `interface_endpoints` is also empty — so
a dev task cannot reach ECR or Secrets Manager either, and therefore cannot
actually start without enabling one or the other. That is a genuine limitation
of the cheapest configuration, and it is written in the dev root rather than
discovered during a first apply.


<a id="aws_production_architecture--2-four-kms-keys-not-one"></a>
#### 2. Four KMS keys, not one

One key gives everyone who can decrypt anything the
ability to decrypt everything. The split follows the lines a compromise would:

| Key | Protects |
|---|---|
| `data` | database, snapshots, queue messages |
| `secrets` | Secrets Manager entries |
| `evidence` | transparency roots, evidence bucket |
| `logs` | CloudWatch log groups |

**The `evidence` key is the one that matters.** Evidence encrypted under the
same key as application data means an attacker who can read the database can
also read and re-encrypt the record of what they did.

<a id="aws_production_architecture--3-two-iam-roles-per-task-and-the-distinction-is-load-bearing"></a>
#### 3. Two IAM roles per task, and the distinction is load-bearing

- **execution role** — used by the ECS *agent* before the container starts:
  pull the image, fetch secrets, create log streams.
- **task role** — used by the *application* at runtime.

Collapsing them gives the application the ability to pull any image and read
any secret the agent could. The task role is assembled from policies the other
modules **export** (`consumer_policy_json`, `reader_policy_json`,
`publisher_policy_json`) rather than written by hand, so a least-privilege
policy cannot drift from the resource it governs.

<a id="aws_production_architecture--4-the-waf-starts-in-count-mode-everywhere"></a>
#### 4. The WAF starts in count mode, everywhere

`AWSManagedRulesCommonRuleSet` contains
`SizeRestrictions_BODY`, which blocks bodies over 8 KB — and a passport with a
delegation chain routinely exceeds that. Left on, it silently drops exactly the
traffic this service exists to receive, as a 403 from a load balancer with no
application log line to explain it.

That one rule is overridden to `count` and the rest of the group stays on.
Removing the whole group to solve one rule is how a WAF becomes decorative.

Then: read the count metrics against real traffic for a week, *then* set
`waf_blocking = true`. A WAF switched straight to blocking on unfamiliar
traffic causes an outage, a rollback, and a permanent reluctance to try again.

---

<a id="aws_production_architecture--validation-boundary"></a>
### Validation boundary

`terraform validate` proves configuration coherence, not a running deployment.
Production soak, independent failure-domain recovery and measured AWS cost require external evidence.


<a id="execution_trust_architecture"></a>
<a id="execution_trust_architecture--execution-trust-architecture"></a>
## Execution trust architecture

**What this document is for:** every other proof in Sentinel attests to a
*decision*. This one is about the gap between the decision and what actually
ran, why that gap existed until now, how much of it is closed, and exactly how
much is not.

---

<a id="execution_trust_architecture--the-gap"></a>
### The gap

Sentinel could already answer seventeen of the eighteen questions it sets out
to answer. Question 12 was the exception:

> Did approved and executed parameters differ?

Nothing could answer it. Here is the shape of why, from `tool_runner.py` as it
stood:

```python
self._gate.run_if_allowed(payload=payload, trust=trust, action=side_effect)
```

The gate evaluates policy over `payload` — a description of the intended
action, built by the caller. Then it invokes `side_effect()`, a zero-argument
closure, also supplied by the caller. The two are connected by nothing but the
caller having been honest.

So an agent approved to write `s3://acme-reports/q3/summary.pdf` could write
`s3://attacker-exfil/anything`, and:

- the policy decision would be correct — it was about the approved action;
- the passport would verify — it faithfully records the decision;
- the signature would verify — it covers the passport;
- the Merkle inclusion proof would verify — the record was never altered;
- the root in S3 Object Lock would confirm it — nobody tampered with anything.

Every proof is a true statement, and none of them is about what executed. That
is not a bug in any one component. It is a missing component.

---

<a id="execution_trust_architecture--what-closes-it"></a>
### What closes it

<a id="execution_trust_architecture--the-commitment"></a>
#### The commitment

`ExecutionAuthorization` carries `approved_parameter_digest` — a
domain-separated SHA-256 over the canonicalised parameters:

```python
digest_of({"context": "sentinel.execution.parameters.v1", "parameters": {...}})
```

The context envelope is not decoration. Sentinel hashes policies, passports and
Merkle leaves with the same function, and a digest that could be mistaken for a
digest of something else is a cross-protocol substitution waiting to happen —
the same reason RFC 6962 prefixes leaves with `0x00` and interior nodes with
`0x01`, which `transparency.py` already does.

The canonicaliser is borrowed from `passport.py` rather than reimplemented.
Two canonicalisers eventually disagree, and the disagreement surfaces as a
signature that verifies on one runtime and fails on another. It also refuses
floats, because `0.1` does not round-trip identically across languages.

<a id="execution_trust_architecture--the-check"></a>
#### The check

`verify_binding` runs **immediately before** the side effect — inside the
closure handed to the gate, not before `run_if_allowed`. Anything that can
change between the check and the call is unchecked, which is the entire failure
being closed.

It refuses on any of eleven defects, and reports **all** of them rather than
the first, so an operator fixes their configuration once:

| Defect | What it catches |
|---|---|
| `PARAMETERS_DIFFER` | the executed parameters are not the approved ones |
| `TOOL_SUBSTITUTED` | a different tool |
| `MCP_SERVER_SUBSTITUTED` | routed through a different server |
| `ACTION_SUBSTITUTED` | a different action |
| `RESOURCE_SUBSTITUTED` | a different resource |
| `AGENT_SUBSTITUTED` | presented by an agent it was not issued to |
| `CROSS_TENANT` | belongs to another tenant |
| `EXPIRED` / `NOT_YET_VALID` | outside its window, with skew tolerance |
| `REPLAYED` | already used; authorizations are single-use |
| `NOT_AUTHORIZED` | nothing was presented at all |

<a id="execution_trust_architecture--the-receipt"></a>
#### The receipt

`ExecutionReceipt` chains authorization digest → executed request digest →
result digest. Each link is a digest and not an id, for the reason the passport
already gives: *an id says which record came before, a digest says what it
said.*

`result_digest` may be empty — a tool returning nothing has nothing to hash.
It is empty rather than a hash of `repr(result)`, because a repr digest looks
exactly like a real commitment and changes with a memory address, so the same
result would hash differently on two runs and an auditor comparing receipts
would see tampering that never happened.

---

<a id="execution_trust_architecture--three-design-decisions-worth-the-words"></a>
### Three design decisions worth the words

<a id="execution_trust_architecture--replay-is-checked-inside-the-verification-not-by-the-caller"></a>
#### Replay is checked inside the verification, not by the caller

A pure function plus a caller who remembers to mark the nonce used is a
time-of-check-to-time-of-use race: two concurrent requests both read "unused",
both pass, both execute. So `verify_binding` claims the nonce itself, through a
`NonceLedger` whose `claim` must be atomic across every enforcing process.

The default is `RejectingNonceLedger`, which claims nothing — so a missing
ledger is an immediate, obvious outage. The tempting default, an in-process
set, works perfectly in every test and protects nothing across replicas. That
is the same defect class as a per-process rate limiter.

The claim happens **only after every other check passes**. A refused attempt
executed nothing, so burning the authorization would turn a transient network
failure into a permanent one while preventing no attack — each retry is refused
on its own merits anyway.

<a id="execution_trust_architecture--bounded-mutation-is-named-never-a-boolean"></a>
#### Bounded mutation is named, never a boolean

Some parameters legitimately change between approval and execution: a request
id, a timestamp, a cursor. `mutable_parameters` lists the permitted keys **by
name**. There is deliberately no "allow mutation" flag, because a flag gets
switched on once for a request id and thereafter permits substituting the
destination bucket.

Two further refusals fall out of that. Verifying a mutation-permitting
authorization *without* the approved values is refused rather than waved
through — comparing key by key needs the values, and their absence is an
unchecked difference. And supplied "approved" values must themselves hash to
the committed digest, or a caller would be defining the comparison it is being
held to.

<a id="execution_trust_architecture--permitted-is-derived-never-stored"></a>
#### `permitted` is derived, never stored

`BindingVerdict.permitted` is a property over `defects`. As a field, some
constructor would eventually set it `True` alongside a defect. Relatedly, no
`BindingDefect` member is falsy: an enum with a falsy member gets used in a
boolean test somewhere, and then the most serious case is the one that reads as
"no problem". Sentinel already shipped that bug once, in an SDK decision enum.

---

<a id="execution_trust_architecture--what-is-not-closed"></a>
### What is NOT closed

This is the section to read before quoting any of the above.

<a id="execution_trust_architecture--two-things-are-genuinely-bound"></a>
#### Two things are genuinely bound

- **The parameters.** `execute_bound` passes the *verified* mapping into the
  tool, so the values that run are the values that were checked. The binding is
  structural, not a promise.
- **Single use.** The nonce is claimed by the verifier, not the caller.

<a id="execution_trust_architecture--everything-else-is-a-declaration-compared"></a>
#### Everything else is a declaration, compared

`agent_id`, `tool`, `action`, `resource` and `mcp_server` are what the caller
**says** it is about to do, checked against what was authorized. A caller that
both lies about them *and* executes something else is not caught — an
in-process wrapper cannot observe the syscalls of a closure it was handed.

What *is* caught is every case where the declared action and the approved action
disagree, which is what parameter, tool and resource substitution actually look
like when an agent is manipulated rather than when the platform itself is
malicious.

Closing the residual needs an instrument that observes the execution rather
than accepting a description of it. Three exist; one is now bound.

| Instrument | Sees | Bound? |
|---|---|---|
| `InlineToolProxy` | the tool's real `arguments` | **yes** — passes the verified mapping to the effect |
| `mcp_wire` / `mcp_proxy_routes` | the real JSON-RPC request on the wire | no |
| detonation tracer | real syscalls | no |

The wire-level MCP path is a **separate forwarding route** that does not go
through `ProtectedToolRunner` at all, so binding it is not a matter of passing
one more argument — it needs an authorization to travel with the request. That
is the next piece of work, and it is the one that would catch a caller which
both lies about the tool *and* executes something else.

The tracer is the only instrument that could catch that at the syscall level,
and it currently runs in detonation rather than in the live path.

<a id="execution_trust_architecture--the-legacy-path-is-still-open-but-it-can-now-be-closed"></a>
#### The legacy path is still open, but it can now be closed

`ProtectedToolRunner.execute` still takes a zero-argument closure and provides
**no binding at all**. `SENTINEL_REQUIRE_EXECUTION_BINDING=true` refuses it
outright, and production will not start unless the value is stated either way —
so the choice is forced rather than defaulted.

It defaults to `false` because enabling it stops every unmigrated caller, and a
security control that takes the service down on upgrade gets reverted rather
than adopted.

`InlineToolProxy` — the chokepoint the MCP gateway routes through — accepts an
`authorization` and a `nonces` ledger, and passes the **verified** arguments to
the registered effect. That migration was not planned; it came from observing
that with the flag on, the proxy refused *every* tool call in the product,
because it called the unbound path. The switch was turning the service off
rather than enforcing binding. A test keeps that state recorded.

So a deployment is bound exactly to the extent that its call sites pass an
authorization, and `true` is what makes the absence of one an error rather than
a silent gap.

**So the honest status is `PARTIAL`.** The mechanism is complete and tested;
enforcement across all call sites is not. Anyone reading this as "Sentinel binds
authorization to execution" should read it as "Sentinel *can*, on migrated call
sites, and the residual above is real."

---

<a id="execution_trust_architecture--where-the-evidence-is"></a>
### Where the evidence is

| | |
|---|---|
| Domain | `sentinel/domain/execution_binding.py` |
| Seam | `sentinel/application/tool_runner.py` (`execute_bound`) |
| Comparison tests | `tests_arch/test_execution_binding.py` |
| Reachability tests | `tests_arch/test_execution_binding_seam.py` |
| Status | `archive/pre-cleanup:docs/readiness/GAP_LEDGER.md`, Phase 3 |

The seam tests observe refusals by **counting side-effect invocations**, not by
catching the exception. An implementation that ran the tool and then raised
would satisfy `pytest.raises` perfectly, and that is precisely the failure worth
testing for.

---

<a id="execution_trust_architecture--related"></a>
### Related

- [`TRANSPARENCY_SINK.md`](TRANSPARENCY_SINK.md) — why the root has to leave the
  operator's control
- [`readiness/GAP_LEDGER.md`](https://github.com/07kashish/Sentinel/blob/d63463cd3bc49bcd3e420ff4a100cc52fe6f4ad6/docs/readiness/GAP_LEDGER.md) — every phase, honestly
  classified


<a id="aws_architecture"></a>
<a id="aws_architecture--aws-boundaries"></a>
## AWS boundaries

<a id="aws_architecture--the-one-structural-rule"></a>
### The one structural rule

**Nothing on the authorization path may depend on a third party.**

```
request → authorize → decide → commit → OUTBOX → SQS → worker → integrations
                                   ↑
                        the transaction ends here
```

A SIEM outage, a Slack outage, an attestation gateway timeout — none of them can
delay or fail an authorization decision. They are consumers of a durable outbox,
not participants in the request.

This is why the queue is between the decision and the integrations rather than
beside them, and it is the reason `SiemNotConfigured` is *retryable*: a security
export that cannot be delivered stays on its retry budget and becomes visible in
the dead-letter queue, rather than being dropped or blocking the caller.
<a id="aws_architecture--why-sqlite-is-still-in-the-tree"></a>
### Why SQLite is still in the tree

SQLite is a development and unit-test engine, and production **refuses to boot
on it**. That refusal is tested.

Both engines matter because they disagree in ways that matter. The predecessor's
worst defect was invisible on SQLite and fatal on PostgreSQL: terminal delivery
operations used an unscoped connection, and under `FORCE` row-level security
their statements matched no rows — every one silently failed on the production
engine while the whole suite passed on the development one.

So the SQL, chaos and concurrency suites are parametrised over both, and
`postgres_tests` is its own release gate. A test that only ever runs on SQLite
cannot see that class of bug.

<a id="aws_architecture--tenant-isolation-in-layers"></a>
### Tenant isolation, in layers

1. An application predicate on every query.
2. PostgreSQL row-level security, `FORCE`d, with `USING` **and** `WITH CHECK`.
3. Tenant-scoped S3 key prefixes.
4. Per-tenant KMS encryption context.
5. Tenant-scoped integration credentials.

The suite deletes layer 1 and requires layer 2 alone to block the leak — for
reads, updates *and* deletes. It connects as a **non-superuser**, because a
superuser bypasses RLS entirely and every assertion would otherwise pass
vacuously.

**The tenant comes from the credential, never from the request.** Any code path
where a caller can name their own tenant is a defect, not a feature.
<a id="aws_architecture--disaster-recovery"></a>
### Disaster recovery

Automated PITR drills exist and measured **RPO ≈ 57s** with `archive_timeout`
set, unbounded without it. The Helm chart refuses to render until an operator
confirms continuous archiving is configured — the acknowledgement is required
because the chart consumes a database DSN it cannot configure, and the RPO
depends on settings it cannot apply.

`disaster_recovery_proof` remains `UNVERIFIED`, and the drill artifact says why
in its own words: the WAL archive currently sits on the **same host and disk**
as `pgdata`. Recovery across an independent failure domain requires a second
region to exist first, and a drill that does not cross a boundary has not tested
one.
