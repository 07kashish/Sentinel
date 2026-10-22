# Execution Passport, version 1

A record of one consequential autonomous action, verifiable by someone who does
not run the system that produced it.

Status: **draft**. Stable enough to implement against; the schema string is
`sentinel.passport/v1` and will not change meaning under that name.

---

## 1. What problem this solves

An autonomous agent took an action. Later, someone needs to know what happened
and whether to believe the answer. The usual artefact is a log line, and a log
line has three problems:

1. It is written by the system being asked about.
2. It can be edited by anyone who can edit logs.
3. Reading it requires the vendor's tooling, which is also the thing under
   question.

A passport is a signed, self-contained statement about one action, in a form
that a third party can check with a public key and about four hundred lines of
code. `verify_passport.py` in this directory is that code, and it is
deliberately not written by importing the producer.

**A passport is evidence, not a control.** Nothing about verifying one stops an
action; by the time a passport exists, the action has happened. Its job is to
make "what did this agent do, and who let it" answerable later, by someone
else.

---

## 2. Document shape

A signed passport is a JSON object with exactly two members:

```json
{
  "passport": { "schema": "sentinel.passport/v1", "...": "..." },
  "signature": {
    "algorithm": "ed25519",
    "key_id": "audit-key-1",
    "signed_at": "2026-03-01T12:00:00+00:00",
    "value": "<base64 of the raw 64-byte Ed25519 signature>"
  }
}
```

### The signature is detached, and that is deliberate

The signature is **not** a field inside the passport. A signature cannot cover
itself, and the usual workaround — signing the document with the signature
field blanked or removed — means the bytes a verifier hashes are not the bytes
it received. Every such transformation is a place two implementations can
disagree, and a disagreement here means a genuine passport reads as forged.

So: the verifier hashes `payload["passport"]` exactly as it arrived.

---

## 3. Required fields

A passport MUST carry all of:

| Field | Meaning |
|---|---|
| `schema` | Exactly `sentinel.passport/v1` |
| `execution_id` | Unique identifier for this action |
| `tenant_id` | The tenant the action belongs to |
| `occurred_at` | ISO-8601 with a UTC offset |
| `agent_id` | Which agent acted |
| `action` | What it did |
| `decision` | What the authorization layer concluded |

A document missing any of these is reported `missing_required_field`. It is not
"invalid" — it may be perfectly signed. It simply records that *something*
happened rather than that *somebody* is answerable, and those are different
artefacts.

An empty string counts as missing. A field present and blank is not a weaker
form of attribution; it is the absence of attribution with a key attached.

Every other field in `execution-passport-v1.json` is optional. A verifier MUST
NOT refuse a document for carrying fields it does not recognise — see §7.

---

## 4. Canonical form

The signature covers the UTF-8 bytes produced by serialising the passport
object with:

| Rule | Why |
|---|---|
| Object keys sorted, lexicographic by code point | Key order is not semantic, so it must be fixed or two orderings give two signatures |
| No insignificant whitespace (`,` and `:` as separators) | Formatting is not semantic |
| Non-ASCII emitted as UTF-8, **not** `\uXXXX` escaped | `агент` and `агент` are two renderings of one value; a canonical form with two renderings is not one |
| `null` serialised, never dropped | `"human_principal": null` says nobody authorised this. Absence says the question was never asked. Erasing the difference lets two different claims share a signature |
| Floats **refused**, not rounded | See below |
| `NaN` and `Infinity` refused | Not JSON |

### Why floats are forbidden

`0.1 + 0.2` serialises as `0.30000000000000004` in one runtime and `0.3` in
another. A passport carrying a float therefore has two canonical forms and two
valid signatures — and an adversary gets to present whichever one the verifier
in front of them will accept.

Producers MUST refuse to sign a document containing a float, and verifiers MUST
refuse to verify one, reporting `uncanonical_document`. Scale to an integer at
the edge, where the conversion is visible: a risk score is `96`, not `96.0`.

Integers are exact and unbounded in JSON. `9007199254740993` MUST survive a
round trip, which means a verifier MUST NOT parse numbers as IEEE doubles.

### Known incompatibility: integer range

The service (`sentinel.domain.passport`), the JavaScript canonical verifier
(`verify_canonical.mjs`), the TS SDK and `schema.json` use the bounded rule:
integers must be within ±(2^53−1). The standard Python verifier
(`verify_passport.py`) follows the unbounded integer rule above; its
`vectors/10-large-integer.json` expects `2^53 + 1` to be accepted. Both rules
and all existing conformance expectations are preserved in Phase 1. This
incompatibility must be resolved before any external party verifies Passports.

### Digest

`digest_of(document)` is the lowercase hex SHA-256 of the canonical bytes. It
is used for chain linkage (§6) and nowhere else.

---

## 5. Signature

* Algorithm: **Ed25519**, identified by the exact string `ed25519`.
* `value`: standard base64 (with padding) of the raw 64-byte signature.
* Public keys: standard base64 of the raw 32-byte public key.

A verifier presented with any other `algorithm` MUST report
`unsupported_algorithm` and stop. Guessing at another algorithm would mean
reporting a result about a check it did not perform.

### Key identity and key windows

A key travels with its own validity window:

```json
{
  "key_id": "audit-key-1",
  "public_key": "<base64 raw 32 bytes>",
  "not_before": "2026-01-01T00:00:00+00:00",
  "not_after":  "2027-01-01T00:00:00+00:00"
}
```

The window travels **with the key** rather than being looked up, so a verifier
holding a key file can check a passport without asking anybody. That
independence is the point of the format.

Two failures that MUST be reported distinctly:

* `wrong_key` — the passport names a different `key_id` than the key supplied.
  Nothing has been proven about the document either way.
* `key_outside_validity_window` — the signature is cryptographically perfect
  and was made by a key that nobody had agreed could speak at that time.

Collapsing these into one "invalid" sends an auditor hunting a forgery that did
not happen.

---

## 6. Chains

`parent_execution_id` names the action this one followed from.
`previous_passport_digest` carries the parent's digest (§4).

A verifier checks the digest against the **parent's own canonical bytes**, which
means it must be given the parent. A child that carried both the digest and a
copy of its parent would let one forger write both halves and agree with
itself.

If the parent was not supplied, the result is `missing_parent`, which means
**UNKNOWN** — not sound. Reporting nothing for an unverifiable link would let a
forger simply omit the parent whose digest does not match.

If a document carries `previous_passport_digest` but no `parent_execution_id`,
that is `broken_lineage`: it claims to follow something it cannot name.

---

## 7. Forward compatibility

`additionalProperties` is `true`. A v1 verifier reading a later passport MUST
check the fields it knows and ignore the rest, rather than refusing.

Refusing would make every schema addition a flag day across every deployed
verifier, and the predictable result is that nobody adds fields and the format
stops describing reality.

The `schema` constant is checked **exactly**. Unknown *fields* are tolerated;
an unknown *schema* is not, because the schema is what gives the known fields
their meaning.

---

## 8. Findings, not booleans

A verifier returns a list of findings. Empty means sound.

| Code | Meaning |
|---|---|
| `modified` | The signature does not cover these bytes |
| `wrong_key` | Verified against a key the passport does not name |
| `key_outside_validity_window` | Signed by a key outside its declared window |
| `unsupported_algorithm` | Not `ed25519` |
| `unrecognised_schema` | Not `sentinel.passport/v1` |
| `missing_required_field` | A §3 field is absent or empty |
| `malformed_timestamp` | Not ISO-8601 |
| `naive_timestamp` | ISO-8601 with no UTC offset |
| `malformed_signature` | Signature or key is not valid base64 |
| `malformed_envelope` | Not a `{passport, signature}` object |
| `uncanonical_document` | Contains a float or another value with no canonical form |
| `malformed_delegation_chain` | `delegation_chain` is present but not an array |
| `broken_lineage` | A chain digest does not match its parent |
| `missing_parent` | A chain link could not be checked |

"Invalid" is not actionable. "The tool definition changed between approval and
execution" is, and a verifier that collapsed the two would discard the reason
somebody is reading a passport in the first place.

Codes are stable. Wording is not.

---

## 9. Conformance

`vectors/` contains documents with their expected finding codes. A third
implementation is conformant when it produces exactly those codes for every
vector.

The vectors deliberately include the cases implementers get wrong:

* non-ASCII (escaping divergence)
* explicit `null` (dropped-key divergence)
* deep nesting (canonicalisers that sort only the top level)
* a 2⁵³+1 integer (verifiers that parse numbers as doubles)
* a correctly signed document that is missing a required field

`tests_arch/test_passport_standard.py` runs every vector against the reference
verifier, and separately checks that this project's producer and the reference
verifier compute **identical canonical bytes** — not merely that both accept
the result. Two signatures agreeing could still hide a divergence that happens
not to matter for one document.

---

## 10. What a passport does not tell you

* **That the action was correct.** It records the decision that was made, not
  whether it was the right one.
* **That the agent is trustworthy.** It attributes; it does not vouch.
* **That the log is complete.** A passport proves something happened. Nothing
  in this format proves nothing *else* did. Completeness is a property of the
  ledger the passports live in, not of any passport.
* **That the signer is who they claim.** The format binds a document to a key.
  Binding that key to an organisation is somebody else's problem, and the
  reason `key_id` is an opaque string rather than a name.

---

## Passport field groups

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

## Canonical and digest verifier procedure

A conforming verifier MUST perform these checks and MUST report which it could
**not** perform.

1. **Canonicalisation.** Re-serialise the supplied document using the canonical form and confirm
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

## Canonicalization and digest conformance vectors

`vectors/canonical/` holds the test corpus. Each file is:

```json
{
  "name": "...",
  "why": "what this vector is for",
  "document": { ... },
  "expect": { "digest": "...", "defects": ["..."] }
}
```

`vectors/canonical/malicious/` is the half that matters. A verifier that passes only the
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

`verify_canonical.mjs` is an independent verifier in dependency-free JavaScript. It exists
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
node standard/execution-passport-v1/verify_canonical.mjs --vectors standard/execution-passport-v1/vectors/canonical
```
