# Execution Passport — specification v1

A portable, offline-verifiable record of one consequential action taken by an
autonomous agent.

**Verification MUST NOT require access to the system that issued the passport.**
That is the whole point of the format: an auditor holding a passport, a public
key and this document can check it with no network access and no cooperation
from the issuer. If verification needed to call the issuer, the issuer would be
attesting to its own conduct.

---

## Status of this document

This describes the format as **implemented**, verified against
`sentinel/domain/passport.py` at the commit that introduced this file. Where
the implementation and this document disagree, the implementation is the
authority and this document is a bug.

Two things it deliberately does **not** do:

- It does not describe `ExecutionAuthorization` or `ExecutionReceipt`
  (`sentinel/domain/execution_binding.py`). Those carry the approved- and
  executed-parameter digests, and they belong in **v2** of this schema. They
  are omitted rather than sketched, because publishing a field before its
  shape is settled means breaking it later.
- It does not grant any licence. Licensing boundaries are a business decision
  and are not asserted here.

---

## 1. Canonical form

A passport is a JSON object. The bytes a signature covers are produced by
exactly this procedure:

1. **Refuse non-representable values.** Walk the document. A `float` anywhere
   is an error. So is any value that is not an object, array, string, integer,
   boolean, or null. Object keys must be strings.
2. **Sort every object's keys** by Unicode code point, recursively.
3. **Serialise with no whitespace** — `,` between members, `:` between key and
   value, nothing else.
4. **Do not escape non-ASCII.** Emit UTF-8 directly.
5. **Encode as UTF-8.**

The digest is `SHA-256` of those bytes, lowercase hex.

### Why floats are refused

`0.1 + 0.2` does not round-trip. A risk score serialising as
`96.00000000000001` on one runtime and `96.0` on another produces two
signatures for one passport, and the failure surfaces a year later as two
byte-different documents that both look correct. Integers only.

This is a **hard error at write time**, not a normalisation. Normalising would
hide the problem from whoever wrote the passport and hand it to the auditor.

### Why integers are bounded

An integer outside ±(2^53 − 1) is refused. Past that an IEEE-754 double — what
every JavaScript parser and most others use — cannot hold the value exactly, so
the document round-trips to a *different* number and its digest changes in a
verifier the issuer does not control. Use a string for anything larger.

This bound was found by writing `verify.mjs`. Python has arbitrary-precision
integers and accepted `2^53 + 1` happily; JavaScript has one number type and
refused it immediately. That disagreement is precisely what a second
implementation of a specification is for, and the Python implementation was
corrected to match.

### Why non-ASCII is not escaped

`ensure_ascii` would give a Cyrillic agent name two representations differing
only in escaping. A canonical form with two representations is not canonical.

### Signature scope

The signature covers the canonical bytes of the document **excluding the
signature field itself** — a signature cannot cover itself. Implementations
serialise the body, sign, then attach.

---

## 2. What a passport claims

| Group | Fields |
|---|---|
| Identity of the execution | `execution_id`, `tenant_id`, `occurred_at`, `previous_passport_digest`, `parent_execution_id`, `session_id` |
| Who | `human_principal`, `agent_id`, `agent_instance`, `agent_version`, `agent_framework`, `model_identity`, `delegation_chain` |
| Through what | `mcp_server_id`, `mcp_server_fingerprint`, `tool_name`, `tool_definition_fingerprint`, `skill_ids`, `credential_id` |
| Against what | `action`, `action_semantics`, `resource`, `environment`, `data_classifications`, `destination` |
| Under which rules | `policy_id`, `policy_version`, `policy_digest`, `decision`, `risk_score`, `risk_reasons` |
| Human involvement | `approval_required`, `approval_actor`, `approval_at` |
| What happened | `idempotency_key`, `execution_fence`, `outcome`, `side_effect` |
| Proof | `evidence_digest`, `attestation_status`, `attestation_reference` |

### Required fields

`execution_id`, `tenant_id`, `occurred_at`, `agent_id`, `action`, `decision`.

Without all six the document records *something* rather than being evidence
*about somebody*. Every other field is optional and defaults to empty — a
passport recording what was actually known beats one that could not be written
because a field nobody had was mandatory.

### `previous_passport_digest` is a digest, not an id

An id says which record came before. A digest says what that record **said**.
An id lets the earlier record be edited afterwards while the chain still
appears intact.

---

## 3. Verification procedure

A conforming verifier MUST perform these checks and MUST report which it could
**not** perform.

1. **Canonicalisation.** Re-serialise the supplied document per §1 and confirm
   its digest equals the passport's digest. A mismatch means the document was
   altered or was never canonical.
2. **Required fields.** Report each of the six that is absent or empty.
3. **Signature**, if a public key is supplied. Absent key ⇒ report
   `signature_unverified`, never "verified".
4. **Parent chain**, if parents are supplied. If `previous_passport_digest` is
   non-empty and no supplied parent has that digest, report it. If a supplied
   parent's recomputed digest differs from the commitment, report it.
5. **Policy digest**, if an expected value is supplied.
6. **Attestation**, if an attestation digest is supplied: it must name this
   passport's digest.

### The rule that matters most

> **An omitted input yields an explicit "unverified" finding, never a pass.**

A verifier handed no public key has not verified the signature. Reporting
"valid" in that case is the single most dangerous thing a verifier can do,
because the output is indistinguishable from a real verification. Every
optional input in this procedure follows the same rule.

---

## 4. Conformance vectors

`vectors/` holds the test corpus. Each file is:

```json
{
  "name": "...",
  "why": "what this vector is for",
  "document": { ... },
  "expect": { "digest": "...", "defects": ["..."] }
}
```

`vectors/malicious/` is the half that matters. A verifier that passes only the
valid vectors has been tested against documents nobody was trying to forge.
The malicious set is:

| Vector | What it forges |
|---|---|
| `float-risk-score` | a float where an integer belongs — two signatures for one document |
| `float-nested-deep-in-an-object` | the same, two levels down, where a shallow type check misses it |
| `float-inside-an-array` | the same, reached through a list |
| `integer-beyond-the-json-safe-range` | a value that round-trips to a different number elsewhere |
| `digest-does-not-match-document` | content altered after the digest was recorded |
| `missing-required-field` | an action attributed to nobody |
| `empty-required-field` | the same, past a presence-only check |
| `parent-commitment-with-no-parent-supplied` | a chain that cannot be walked |
| `parent-edited-after-being-committed-to` | a chain that *looks* intact — the attack an id-based chain would permit outright |
| `attestation-names-a-different-passport` | a real attestation over someone else's record |

### Three attacks that cannot be file-based vectors

Worth naming, because their absence from the corpus is a property of the corpus
format and not an oversight:

- **A duplicated object key.** Every JSON parser resolves it before a verifier
  sees the document (last one wins, in practice), so a `.json` vector cannot
  carry the ambiguity. Defending against it requires operating on the raw byte
  stream, which is a parser-level concern above this format.
- **Non-ASCII escaped instead of emitted.** Escaping is a property of a
  *serialisation*, not of a parsed document. `"А"` and `"А"` parse to the
  same string, so the vector would have to be raw bytes.
- **Keys in non-sorted order.** This cannot fail: §1 sorts keys before hashing,
  so input order is discarded by construction. A vector for it would assert
  something the format makes impossible.

The first two are real attacks against a *parser*. A verifier hardening against
them must compare the bytes it received with the bytes it would produce, not
just the digests.

### Two implementations must agree

`verify.mjs` is an independent verifier in dependency-free JavaScript. It exists
so the conformance vectors are checked by something that does not share code
with the Python implementation — two implementations of one spec disagreeing is
how an ambiguity in the spec gets found, and a corpus checked by only the
implementation it was generated from proves that implementation is
self-consistent and nothing more.

Run both:

```bash
PYTHONPATH=. python -m pytest tests_arch/test_passport_conformance.py
```

```bash
node spec/execution-passport/verify.mjs --vectors spec/execution-passport/vectors
```

---

## 5. Extension and compatibility

- **Unknown fields are preserved and included in the digest.** A verifier that
  dropped unknown fields would compute a different digest than the signer, so
  forward compatibility and digest stability are the same requirement.
- **New fields are additive and default to empty**, so an older verifier still
  checks everything it knows about and reports the rest as unverified rather
  than failing.
- **Breaking the canonical form requires a new `schema` value.** Silently
  changing the serialisation would make every historical passport unverifiable
  with no explanation.

---

## 6. What this format does not prove

Stated here because a portable evidence format invites over-reading.

A passport proves what the issuer **recorded**, that the record has not been
altered since, and — where the transparency log's root has been published
somewhere the issuer cannot rewrite — that the record was present at a point in
time. See [`../../docs/TRANSPARENCY_SINK.md`](../../docs/TRANSPARENCY_SINK.md).

It does **not** by itself prove that the recorded action is the action that
executed. That binding lives in `ExecutionAuthorization` /
`ExecutionReceipt`, which are v2 work, and their current residual is documented
in
[`../../docs/EXECUTION_TRUST_ARCHITECTURE.md`](../../docs/EXECUTION_TRUST_ARCHITECTURE.md).
Anyone citing a passport as proof of what an agent *did* should read that
section first.
