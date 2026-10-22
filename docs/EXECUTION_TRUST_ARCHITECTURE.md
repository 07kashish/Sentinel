# Execution trust architecture

**What this document is for:** every other proof in Sentinel attests to a
*decision*. This one is about the gap between the decision and what actually
ran, why that gap existed until now, how much of it is closed, and exactly how
much is not.

---

## The gap

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

## What closes it

### The commitment

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

### The check

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

### The receipt

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

## Three design decisions worth the words

### Replay is checked inside the verification, not by the caller

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

### Bounded mutation is named, never a boolean

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

### `permitted` is derived, never stored

`BindingVerdict.permitted` is a property over `defects`. As a field, some
constructor would eventually set it `True` alongside a defect. Relatedly, no
`BindingDefect` member is falsy: an enum with a falsy member gets used in a
boolean test somewhere, and then the most serious case is the one that reads as
"no problem". Sentinel already shipped that bug once, in an SDK decision enum.

---

## What is NOT closed

This is the section to read before quoting any of the above.

### Two things are genuinely bound

- **The parameters.** `execute_bound` passes the *verified* mapping into the
  tool, so the values that run are the values that were checked. The binding is
  structural, not a promise.
- **Single use.** The nonce is claimed by the verifier, not the caller.

### Everything else is a declaration, compared

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

### The legacy path is still open, but it can now be closed

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

## Where the evidence is

| | |
|---|---|
| Domain | `sentinel/domain/execution_binding.py` |
| Seam | `sentinel/application/tool_runner.py` (`execute_bound`) |
| Comparison tests | `tests_arch/test_execution_binding.py` |
| Reachability tests | `tests_arch/test_execution_binding_seam.py` |
| Status | `docs/readiness/GAP_LEDGER.md`, Phase 3 |

The seam tests observe refusals by **counting side-effect invocations**, not by
catching the exception. An implementation that ran the tool and then raised
would satisfy `pytest.raises` perfectly, and that is precisely the failure worth
testing for.

---

## Related

- [`TRANSPARENCY_SINK.md`](TRANSPARENCY_SINK.md) — why the root has to leave the
  operator's control
- [`readiness/GAP_LEDGER.md`](readiness/GAP_LEDGER.md) — every phase, honestly
  classified
