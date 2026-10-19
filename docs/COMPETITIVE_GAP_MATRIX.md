# Competitive gap matrix

**Read this first.** Every competitor column below is `NOT PUBLICLY CONFIRMED`
or `UNKNOWN` unless stated otherwise, because **I have not tested any
competitor product.** Nothing here is derived from running Noma, Zenity,
Prisma AIRS, WitnessAI, Straiker, HiddenLayer, Microsoft Agent 365, Cisco AI
Defense, or Check Point/Lakera.

Marketing material is not a capability assessment. A vendor who does not
mention a feature may still have it; one who advertises it may implement it
shallowly. Both errors are easy to make from the outside, and both make a
matrix worse than useless — it becomes a document that *feels* like competitive
intelligence while containing none.

So this document does something narrower and more honest: **it states what
Sentinel can prove, and where the category is contested.** The competitor
column records only what is publicly claimed, labelled as such.

---

## Sentinel's own status, with evidence

| Capability | Sentinel status | Evidence | Competitor position |
|---|---|---|---|
| **Deterministic authorization** | **PASS** | `security_tests` gate; `ModelAdvice` has no field for a decision | `UNKNOWN` — the industry advertises "AI-powered detection", which is a different claim |
| **Execution Passport** | **PASS** | Signed, canonical, chained. `standard/execution-passport-v1/` | `NOT PUBLICLY CONFIRMED` for any competitor |
| **Independent verifier** | **PASS** | 24 tests. Second implementation sharing no code; **byte-identical canonicalisation** | `NOT PUBLICLY CONFIRMED` |
| **Authorization-vs-execution comparison** | Partial | Passport carries `authorized_action` and `executed_action` | `UNKNOWN` |
| **MCP definition pinning + drift** | **PASS** | `mcp_estate.py`; cross-server collision detection | `LIKELY` for several — MCP security is actively contested |
| **A2A delegation validation** | **PASS** | Card pinning, privilege amplification, loop detection | `UNKNOWN` |
| **Tenant isolation** | **PASS** | RLS suite on real PostgreSQL, non-superuser, app predicate deleted | `LIKELY` — table stakes for enterprise SaaS |
| **Blast radius** | Partial | `blast_radius.py`; reports `coverage`, refuses to infer sensitivity | `LIKELY` for cloud-native vendors |
| **Policy simulation** | **PASS** | `policy_as_code.py`; replays immutable history; never executes | `UNKNOWN` |
| **Skill detonation** | **Contract only** | Canary exfiltration as the only PROOF; `RefusingDetonator` refuses rather than pretending | `LIKELY` for Zenity — this is their stated area |
| **Universal cloud discovery** | **Not built** | Connector interfaces + matrix; AWS adapters exist | `CONFIRMED` for Noma and Microsoft — this is their strength |
| **Threat intelligence** | **PASS** | k-anonymity ≥3 reporters, banded counts, date-only | `LIKELY` |
| **Enterprise console** | Partial | 9 data-backed views | `LIKELY` — mature vendors have more |
| **Independent pentest** | **UNVERIFIED** | — | `CONFIRMED` for funded vendors |
| **Production references** | **UNVERIFIED** | — | `CONFIRMED` for all named vendors |

## The honest read

**Where Sentinel is probably ahead:** verifiable execution evidence. A signed
passport a third party can check with a public key, and a reference verifier
written from the specification that shares no code with the producer, is not
something any competitor publicly claims. Two independently written
canonicalisers agreeing byte-for-byte is the concrete artifact behind that.

**Where Sentinel is behind, and it is not close:** breadth of discovery, and
external proof. Noma and Microsoft have cloud discovery Sentinel does not.
Every named vendor has customers, pentests and production traffic. Those are
`UNVERIFIED` here and the four external gates say so.

**The category question.** Sentinel bets that *verifiable execution* becomes
the thing enterprises buy, rather than better prompt filtering. That is a
strategic bet, not a technical fact, and no matrix settles it. If the market
decides detection quality matters more, breadth of discovery and a customer
list beat a cryptographic evidence chain.

## What would make this document real

1. **Hands-on evaluation** of each product against the same test corpus.
2. **A published passport format** other tools can emit and verify — turning a
   feature into an interoperability standard, which is why
   `standard/execution-passport-v1/` is separated from the control plane.
3. **Design-partner findings** comparing what Sentinel discovered against what
   the incumbent tool found in the same estate. That is the only comparison a
   CISO actually credits.

Until then this is a self-assessment with citations, and it should be read as
one.

---

## Related

- [`RELEASE_READINESS.md`](RELEASE_READINESS.md)
- [`SECURITY_ASSURANCE.md`](SECURITY_ASSURANCE.md)
- [`CONNECTOR_MATRIX.md`](CONNECTOR_MATRIX.md)
- [`../standard/execution-passport-v1/SPEC.md`](../standard/execution-passport-v1/SPEC.md)
