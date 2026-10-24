# Security notes (current hexagonal tree)

**Status:** pre-production.

## Authentication and authorisation

- Bearer API keys; optional OIDC JWT (RS256/ES256, tenant claim required).
- API-key and OIDC authentication; the unused SAML validator was removed in Phase 2.
- SCIM 2.0 Users (`/scim/v2/Users`) and org APIs (`/v1/orgs*`) behind `MANAGE_USERS`.
- Capability grants; ingest cannot read incidents.

## Protect (F-11 in-product)

- `POST /v1/tools/execute` is the only sanctioned remote tool side-effect path.
- Kill switch / budget / circuit via `ProtectControls`.
- SDK: `InterceptedToolClient` fails closed if misconstructed.
- Enrolled-agent silence → `possible_bypass` on `GET /v1/protect/bypass-signals`.
- Optional deployment-time enforcement (egress allowlist / mesh / eBPF): see
  `docs/PROTECT_ENFORCEMENT.md`. **Sentinel cannot see traffic that bypasses this.**
- Residual: processes that never call Sentinel (no transparent network interceptor
  unless a maintainer explicitly scopes that work).

## HTTP / console

- API CSP `default-src 'none'`.
- Analyst console at `/console` with `script-src 'self'`, Trusted Types policy name
  `sentinel-console`, DOM updates via `textContent` only (no `.innerHTML`).

## Tenancy

- FORCE RLS on Postgres; tenant required on UoW / directory / org writes.

## Known limitations

- Hosted SAML IdP and SAML assertion validation are not provided; the unused
  legacy validator was removed in Phase 2. SCIM Groups sync productization is incomplete.
- Remote GitHub branch protection UNVERIFIED until an operator runs
  `python scripts/apply_branch_protection.py OWNER/REPO --apply`.

<a id="adversarial_review"></a>
<a id="adversarial_review--core-adversarial-findings"></a>
## Core adversarial findings

<a id="adversarial_review--site-reliability-engineer--what-fills-up"></a>
#### Site Reliability Engineer — *"what fills up?"*
**Found: unbounded growth.** `work_queue` retained every completed row forever,
one per incident, on the hot path of every claim. `incident_transitions` and
exhausted dead letters likewise had a writer and no reaper.

**Fixed structurally — but only on the development engine, which took until
2026-08-18 to notice.** The sweep took a pooled connection and never established
a tenant. Every table it deletes from is under `FORCE ROW LEVEL SECURITY`, whose
policy is `tenant_id = current_setting('sentinel.tenant_id', true)`, so on
PostgreSQL that setting was NULL, every `DELETE` matched no rows, and the sweep
**reported zero rather than failing**:

```console
before: work_queue = 1  inbox = 1
sweep reported: {... 'retention_rows_deleted': 0}
after : work_queue = 1  inbox = 1
RESULT: DEFECT CONFIRMED
```

This is the same defect this document credits the Google SRE seat with finding in
another form, and the same one `tests_arch/conftest.py`'s own docstring holds up
as the reason the SQL suites are parametrised over both engines —
`test_retention_sweep.py` was the suite that was not. The sweep now runs per
tenant with `set_tenant` **and** an explicit `tenant_id = ?` predicate, every test
in that module runs on both engines, and the regression asserts
`before − after == reported` against a non-zero `before`, so a sweep that deletes
nothing can no longer satisfy a pair of agreeing zeroes.

**The declared-or-reaped gate now exists.** It was cited here as though it did;
it did not, and neither did `APPEND_ONLY_TABLES` (see the correction at the top).
Building it immediately found a table nobody had decided about:
`webauthn_challenges` ships `ix_challenges_issued(issued_at)` — an index whose
only possible purpose is an age purge — with no caller, exactly the signature of
`ix_inbox_age` and `ix_nonces_expiry` before this work started.

The evidence ledger is declared append-only on purpose: trimming a hash chain
destroys the non-repudiation it exists to provide, and a test asserts retention
never touches it — including the new incident-history sweep, which may delete an
incident while its ledger entry, evidence row and audit trail all remain.

<a id="adversarial_review--google-sre--does-a-skipped-test-look-like-a-passing-one"></a>
#### Google SRE — *"does a skipped test look like a passing one?"*
**Found: silent skip.** A stale PostgreSQL data directory turned 23 live tests
into "23 skipped" with exit code 0 — green CI, nothing verified. That is the same
shape as every silent failure this project has found.

**Fixed.** `SENTINEL_REQUIRE_LIVE=1` converts unavailable infrastructure into a
failure. CI must set it.
<a id="adversarial_review--enterprise-ciso--can-one-tenant-see-anothers-evidence"></a>
#### Enterprise CISO — *"can one tenant see another's evidence?"*
Every accessor is tenant-scoped — 27 distinct `tenant_id=?` predicates — and
`test_tenant_isolation_is_enforced_by_the_real_database` proves it against live
PostgreSQL with the same incident id under two tenants. (That test did not exist
when this paragraph was first written; see the correction at the top. It exists
now, in `tests_arch/test_tenant_isolation_rls.py`, and runs on both engines.)

**Residual concern CLOSED, 2026-08-18.** The concern as written — "isolation is
enforced in application SQL, not by PostgreSQL row-level security" — was **already
false when it was written**. `sentinel/infrastructure/sql/schema.py::rls_statements`
issues `ENABLE`/`FORCE ROW LEVEL SECURITY` plus a `USING`/`WITH CHECK` policy for
every one of the 19 tables in `PROTECTED_TABLES`, and `migrate.py` applies it at
versions 2, 4, 6, 8 and 10. What was genuinely missing was any test that could
tell RLS apart from the application predicate, because every existing isolation
test still carried `WHERE tenant_id = ?` and so would have passed with the
policies dropped entirely.

That is now closed by tests that **deliberately remove the application
predicate** — the exact situation a forgotten `WHERE` creates in production:

| Statement issued, no `WHERE` at all | PostgreSQL | SQLite |
|---|---|---|
| `SELECT tenant_id, incident_id FROM incidents` | 1 row, tenant A only | 3 rows, both tenants |
| `UPDATE incidents SET state='failed'` | 1 row; tenant B untouched | 3 rows; tenant B corrupted |
| `DELETE FROM incidents` | 1 row; tenant B's 2 rows survive | 3 rows; tenant B wiped |
| `INSERT` labelled with another tenant's id | refused by the policy | permitted |

The SQLite column is asserted, not skipped: SQLite has no row-level security, so
on the development engine the application predicate really is the only thing
between tenants, and a reader should not have to infer that.

Two further assertions stop the file from becoming decorative:
`test_the_application_role_is_not_a_superuser` (a superuser bypasses FORCE RLS,
which would make every row above pass vacuously), and
`test_every_protected_table_actually_carries_a_forced_policy`, which asks
`pg_class`/`pg_policy` whether the server agrees the DDL ran, rather than trusting
that an `IF NOT EXISTS` migration did something.

**Evidence:** `tests_arch/test_tenant_isolation_rls.py`, 18 tests, 14 passed +
4 skipped (the PostgreSQL-only assertions under the SQLite parametrisation),
0 failed.

---
<a id="adversarial_review--what-a-fifth-council-would-have-to-find"></a>
### What a fifth council would have to find

**The claim that used to open this section is withdrawn.** It read: "Every
failure class from V1–V4 is now enforced mechanically
(`tests/test_failure_classes_are_structural.py`)", followed by a list of thirteen
classes. There is no `tests/` directory in this repository and no such file. The
thirteen classes may well each be covered somewhere in `tests_arch/`, but no
single artifact enforces them as a set, and nothing here should be read as saying
one does. Re-establishing that claim means writing that file; until someone does,
this section makes no blanket assertion.



1. ~~**Application-enforced tenant isolation** — one missing SQL predicate bleeds
   data. PostgreSQL row-level security would make it structural.~~
   **CLOSED 2026-08-18.** RLS was already implemented and applied; what was
   missing was a test that could distinguish it from the application predicate.
   `tests_arch/test_tenant_isolation_rls.py` removes the predicate entirely and
   shows SELECT, UPDATE and DELETE all still bounded to one tenant on PostgreSQL,
   with a non-superuser assertion so the result cannot be vacuous. See the
   Enterprise CISO section.

2. ~~**A single-node evidence ledger head** — the append protocol is not proven
   safe under concurrent multi-replica writes, so the chain could fork.~~
   **CLOSED 2026-08-18 — and it was (a), structurally impossible, not (b).**
   `tests_arch/test_ledger_multi_replica.py` runs two INDEPENDENT
   `ConnectionPool`s — separate connections, separate transaction state, no
   shared Python object, so every protection under test is server-side — with
   twelve threads released together on a `threading.Barrier`, on both engines.
   It then reads the chain back and checks four properties rather than checking
   that nothing raised: no two entries share a predecessor, `seq` is dense from
   1, every link recomputes from its own predecessor and payload, and every
   append either committed or raised a **retryable** error (so a loser retries
   and the evidence still lands, rather than being dropped). A fifth test inserts
   a deliberate fork directly, bypassing `append()`, and confirms the database
   refuses it on `ux_ledger_chain` — without which all of the above would be
   consistent with a unique index that had never been created.

   The mechanisms differ per engine, which is why running on one would not have
   settled it: SQLite serialises writers at `BEGIN IMMEDIATE`, PostgreSQL at the
   transaction-scoped advisory lock in `Connection.serialise_tenant`. Only the
   second is production.

   **Limit, stated:** the two pools share an interpreter, so a real cluster's
   interleavings are a superset of those reachable here. What is established is
   that the server-side protocol holds when two independent pools contend.

A fifth review would now have to find a class outside all of these.

<a id="adversarial_review--the-class-the-fifth-review-actually-found-gates-that-execute-nothing"></a>
### The class the fifth review actually found: gates that execute nothing

Written up on 2026-08-19, because it is a *class* and not a list of bugs.

Four separate gates were found in one pass that looked healthy from the outside
and were doing no work at all:

| Gate | How it looked | What it was doing |
|---|---|---|
| Operational retention sweep | `pass` — 110,000 rows swept, DB halved | deleted **zero** rows on PostgreSQL and reported zero |
| `dynamic-api-security` (DAST) | a job that ran and failed at 31s | timed out waiting for a schema the app is configured not to serve; **0 operations tested** |
| PostgreSQL test parametrisation | green locally on Windows | **every** `[postgres]` test errored on connect in CI |
| Independent-English promotion floor | a test in the suite | asserts a file under a **gitignored** directory; never once ran in CI |

A fifth, `bandit`, was running but permanently red on 99 false positives — with
the same practical effect, because nobody read the output. **It was concealing a
real pre-authentication XML denial of service in the SAML path.**

<a id="adversarial_review--what-they-have-in-common"></a>
#### What they have in common

Not a shared root cause — an unscoped connection, an unset feature flag, a
string-sliced DSN and a gitignored path have nothing technical in common. What
they share is a **shape**: each produced a result indistinguishable from success
while doing nothing.

- A sweep that deletes nothing satisfies "no old rows remain".
- A fuzzer that tests nothing reports no failures.
- An erroring parametrisation is invisible if you read only the local exit code.
- A file assertion that never runs never fails.

This is the same shape as the F-4 retraction that this project already treats as
its worst mistake — *a claim of coverage with nothing behind it* — and it turns
out to be the dominant defect class in the repository, well ahead of anything on
the V1–V4 list.

<a id="adversarial_review--what-was-done-about-it"></a>
#### What was done about it

Each fix now carries a **positive** assertion that work happened, rather than an
absence of failure:

- the retention regression asserts `before − after == reported` against a
  non-zero `before`, so agreeing zeroes fail;
- the DSN helpers are tested against both DSN shapes as pure strings, so a
  Windows developer catches a Linux-only regression without a Linux machine;
- the DAST job's schema endpoint is asserted to return 200 and 18,124 bytes;
- the classifier promotion-floor check was retired with the classifier;
  deterministic evaluation remains a separate retained check.

<a id="adversarial_review--what-was-not-done-and-is-the-honest-residual"></a>
#### What was NOT done, and is the honest residual

The retained `tests_arch/test_documentation_cites_real_tests.py` checks that
documented test names resolve to collected cases. It does not prove every gate
performed meaningful work: retain each gate's positive denominator and mutation
checks rather than treating the existence of a named test as assurance.


<a id="asi_threat_control_matrix"></a>
<a id="asi_threat_control_matrix--asi--owasp-threatcontrol-matrix-honest-coverage"></a>
## ASI / OWASP threat–control matrix (honest coverage)

Coverage levels: **none** | **partial** | **implemented** | **verified**.
No 10/10 claims. Policy rules may carry `owasp_asi` / `mitre` tags in
`config/default_policy.json`; tags are traceability, not completeness.

| Threat theme (illustrative ASI) | Control in tree | Coverage | Evidence |
|---|---|---|---|
| Prompt injection / instruction override | Deterministic rules + fenced model inputs | partial | policy rules; `test_security_prompt_injection.py` |
| Sensitive file / secret path access | Policy rules (`.env`, keys, kubeconfig, …) | partial | `default_policy.json`; metrics recall_by_category |
| Dangerous code execution | Regex rules on subprocess actions | partial | policy; metrics |
| Unverified identity privilege | Trust cap (79); verified-only rules | implemented | domain `Severity.capped_for`; architecture tests |
| Cross-tenant data bleed | FORCE RLS + required tenant UoW | verified (suite) | `test_sql_infrastructure.py` RLS tests |
| Tool abuse pre-action | ProtectGate + ProtectedToolRunner | partial | in-repo only; F-11 |
| Supply-chain / dependency | pip-audit, SBOM, gitleaks, trivy | implemented (CI) | `.github/workflows/ci.yml` |
| Attestation forgery / skip | Fail-closed dispositions; hydration | verified (suite) | chaos + mutation |
| SSRF / token theft via redirect | HardenedHttpClient refuses redirects | verified (suite) | `test_security_outbound.py` |

Gaps deliberately open: full ASI taxonomy mapping, multilingual injection,
novel C2 without feeds, inline protect for non-integrating agents.


<a id="pentest_package"></a>
<a id="pentest_package--penetration-test-package"></a>
## Penetration test package

Everything a testing firm needs to scope and run an engagement against
Sentinel, and an honest account of where we already know the soft ground is.

**This document is an input to a penetration test. It is not evidence of one.**
The `independent_pentest` gate stays `UNVERIFIED` until a third-party report and
a remediation **retest** exist. A scan this project runs against itself is not
an independent assessment, and the retest is the half people skip.

---

<a id="pentest_package--1-what-sentinel-is-in-one-paragraph"></a>
### 1. What Sentinel is, in one paragraph

An authorization and evidence plane that sits between autonomous AI agents and
the systems they act on. An agent's proposed action is identified, authorized
against a deterministic policy, enforced, and recorded as a signed artefact
that a third party can verify without trusting Sentinel. The security claim is
not "we detect bad prompts" — it is *no consequential action happens without a
decision, and every decision leaves evidence somebody else can check*.

<a id="pentest_package--2-attack-surface"></a>
### 2. Attack surface

Machine-readable and generated from the code, not hand-maintained:

```bash
python -c "import json; from scripts.dev.route_inventory import collect; print(json.dumps(collect(), indent=2))"
```

The inventory lists every route, its method, the capability it
declares, whether it mutates state, and its path parameters.

Six routes require no capability, all reviewed:

| Route | Why |
|---|---|
| `GET /console`, `/console/app.js`, `/console/app.css` | SPA shell; must load before anyone can type a token. Audited to disclose no credentials, hostnames or tenant identifiers |
| `GET /health/live`, `/health/ready` | A probe that needs a credential reports the health of the credential path, not the process |
| `GET /metrics/prometheus` | **Not unauthenticated** — checks a scrape token inside the handler, because Prometheus holds no principal |

`tests_arch/test_attack_surface.py` pins that set. A seventh appearing fails the
build, and `test_no_mutating_route_is_public` is a rule no exemption can satisfy.

<a id="pentest_package--3-roles-and-capabilities"></a>
### 3. Roles and capabilities

Authorization is by **explicit capability grant**, never by role ordering.
There is no "admin implies everything" — a role holds a set, and the set is
checked.

| Role | Holds |
|---|---|
| `ingest` | `INGEST_EVENT` only — can write events and **read nothing** |
| `viewer` | read capabilities; cannot decide an approval |
| `analyst` | read + `DECIDE_APPROVAL` |
| `admin` | management capabilities |

Two invariants worth attacking directly:

- **An agent credential can read nothing.** `test_the_ingest_role_can_read_nothing`.
- **Approval is a separate capability and a separate state transition.** A
  viewer cannot decide one, and an unapproved action cannot execute.

<a id="pentest_package--4-tenant-isolation"></a>
### 4. Tenant isolation

Enforced in two independent layers, and the second is the one to test:

1. An application predicate on every query.
2. PostgreSQL row-level security with `FORCE`, `USING` **and** `WITH CHECK`.

The suite deletes the application predicate and requires RLS alone to block the
leak — for reads, updates and deletes. It also connects as a **non-superuser**,
because a superuser bypasses RLS entirely and every assertion would pass
vacuously.

**The tenant comes from the credential, never from the request.** Any path where
a caller can name their own tenant is a finding.

<a id="pentest_package--5-test-deployment"></a>
### 5. Test deployment

```bash
docker build -t sentinel:pentest .
python -m sentinel.interface.cli migrate
```

Configuration is fail-closed: production **refuses to boot** on wildcard CORS,
exposed API docs, a missing metrics token, keys under 32 characters, or SQLite.
Expect a test deployment to run with `SENTINEL_ENV=development` — say so in the
report if a finding depends on that.

Provide the tester with:

- a dedicated tenant and credentials at each role
- a second tenant, so cross-tenant attempts are testable
- the OpenAPI document from the running service (`/openapi.json`)

**Do not** give a tester production credentials. There is nothing to learn from
them that a test tenant does not show.

<a id="pentest_package--6-where-we-already-know-the-ground-is-soft"></a>
### 6. Where we already know the ground is soft

Stated because a report that rediscovers a documented limitation wastes the
engagement.

| Area | Known state |
|---|---|
| **A2A streaming** | The security guard exists; the transport is not wired. Nothing streams today |
| **Per-server MCP usage** | No usage table, so shadow-server detection cannot fire. The endpoint says so in its response rather than reporting zero |
| **Asset declarations** | No persistent store; blast radius takes declarations per request and reports `coverage` so a low score over low coverage cannot read as "safe" |
| **ECDSA recovery** | The secp256k1 recovery primitive is unaudited |
| **`/health/ready` throttling** | Exempt from rate limiting, which is only safe because the probe is memoised for 1s. Attack the cache, not just the endpoint |
| **Detection model** | Advisory only. It cannot move a triage state or authorize anything. If you find a path where an ML score alone causes a destructive action, that is a critical finding and it is the single most valuable thing you could find |

<a id="pentest_package--7-what-we-have-already-tested-ourselves"></a>
### 7. What we have already tested ourselves

Do not spend the engagement here unless you can beat it:

- **Schema-driven fuzzing**: 45/45 operations, 1,880 cases, `not_a_server_error`
  and `ignored_auth`. The second re-sends every request without credentials and
  fails if the response is unchanged.
- **SAST** (bandit), **secret scanning** (gitleaks over full history),
  **dependency scanning** (pip-audit), **container scanning** (trivy).
- **Prompt injection, SSRF, bounds, audit trail, throttling** — dedicated
  suites. SSRF alone has 44 tests: post-resolution address validation, one
  pinned lookup, redirects refused.

<a id="pentest_package--8-scope"></a>
### 8. Scope

**In scope:** the HTTP API, the console bundle, the MCP proxy, the A2A gateway,
authorization logic, tenant isolation, the evidence chain, the container image.

**Out of scope unless agreed:** denial of service against shared
infrastructure; social engineering of the team; the upstream cloud providers;
physical access.

**Please do attempt:** authorization bypass, tenant escape, evidence forgery,
delegation laundering, replay, approval bypass, and any path that lets model
output reach a control decision.

<a id="pentest_package--9-reporting"></a>
### 9. Reporting

For each finding we need: reproduction steps, the affected route or component,
the capability held when it worked, and impact. Severity by your own scale.

A finding is not closed until the **retest** confirms the fix. The readiness
gate reads the retest, not the report.

---

<a id="pentest_package--related"></a>
### Related

- [`scripts/dev/route_inventory.py`](../scripts/dev/route_inventory.py) — retained route inventory collector
- [`SECURITY.md`](SECURITY.md#threat_model)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`STATUS.md`](STATUS.md#release_gates) — how evidence is bound to a build


<a id="security_assurance"></a>
<a id="security_assurance--assurance-methods-and-limits"></a>
## Assurance methods and limits

<a id="security_assurance--automated-assurance-and-its-limits"></a>
### Automated assurance, and its limits

| Check | Tool | What it cannot see |
| --- | --- | --- |
| SAST | bandit `-ll` | Logic flaws; anything requiring cross-file reasoning |
| DAST | schemathesis 4.23 | Anything absent from the OpenAPI document |
| Dependency | pip-audit | Vulnerabilities with no published advisory |
| Secrets | gitleaks, full history | A secret that does not match a pattern |
| Container | trivy `vuln,secret,misconfig` | Application logic; anything newer than its database |
| Types | mypy on `sentinel/domain` | The rest of the tree, which carries known errors |
| Architecture | fitness suite | Whether the boundaries are the *right* ones |
| Tenant isolation | RLS suite on real PostgreSQL | Isolation in systems Sentinel does not own |

Two of those deserve expansion.

**`ignored_auth` is the DAST check worth having.** It re-sends every request
*without* credentials and fails if the answer is unchanged. That catches a route
declaring a capability it does not enforce — which no amount of reading the
decorator can prove, because the decorator is the thing being doubted.

**The RLS suite deletes the application predicate** and requires row-level
security alone to block the leak, for reads, updates *and* deletes. It connects
as a **non-superuser**, because a superuser bypasses RLS entirely and every
assertion would pass vacuously. That distinction is the whole test.

<a id="security_assurance--deterministic-authority"></a>
### Deterministic authority

No ML or LLM output can authorize anything.

- `ModelAdvice` **cannot express a decision** — the type has no field for one.
- Model output carries an `[unverified-model-output]` prefix that survives
  copying.
- `stops_action` uses an allowlist of what *proceeds*, so a new decision type
  stops by default rather than being forgotten into `allow`.
- Detection findings cannot move a triage state.

If a path is ever found where a model score alone causes a destructive action,
that is a critical finding — and the most valuable single thing an external
tester could report.
<a id="security_assurance--unaudited-primitive"></a>
### Unaudited primitive

The **secp256k1 ECDSA recovery** primitive is unaudited. It is the only source
of an `Address`, so a flaw there is an identity-forgery path. Stated here
because a pentest report that rediscovers a documented limitation has spent the
engagement badly.

---


<a id="threat_model"></a>
<a id="threat_model--http-and-outbound-security-findings"></a>
## HTTP and outbound security findings

<a id="threat_model--2-findings"></a>
### 2. Findings

Each was reproduced before being fixed. Severity is impact × how little the
attacker needs.

<a id="threat_model--f-1--bearer-token-exfiltrates-through-a-redirect--critical"></a>
#### F-1 — Bearer token exfiltrates through a redirect · **critical**

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

<a id="threat_model--f-2--a-read-only-credential-could-forge-evidence--high"></a>
#### F-2 — A read-only credential could forge evidence · **high**

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

<a id="threat_model--f-3--full-api-schema-disclosed-to-unauthenticated-callers--medium"></a>
#### F-3 — Full API schema disclosed to unauthenticated callers · **medium**

Proof: `/docs`, `/redoc` and `/openapi.json` each returned `200` with no
credential, disclosing all nine routes with their request shapes.

Two distinct problems. The reconnaissance, and the fact that Swagger UI is a
**browser page that loads script from a third-party CDN** — the only browser
surface this service had, unauthenticated, with remote script.

These cannot be fixed with a dependency: FastAPI serves them before any dependency
runs. The only control is not mounting them.

**Fixed** — off unless `SENTINEL_EXPOSE_API_DOCS` is set, and configuration
**refuses to start** if it is set in production.

<a id="threat_model--f-4--no-security-response-headers--medium"></a>
#### F-4 — No security response headers · **medium**

Proof: on `GET /v1/incidents` with valid auth, every one of
`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`,
`Referrer-Policy`, `Cache-Control`, `X-Frame-Options` and `Permissions-Policy` was
absent. Tenant incident data was returned with no `no-store`, so any intermediary
could cache it.

**Fixed** — applied to every response including errors. A 401 body cached by a
proxy is still a leak.

<a id="threat_model--f-5--unbounded-structure-in-metadata--medium"></a>
#### F-5 — Unbounded structure in `metadata` · **medium**

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

<a id="threat_model--f-6--readiness-leaked-internal-infrastructure--low"></a>
#### F-6 — Readiness leaked internal infrastructure · **low**

`/health/ready` returned `database_error` containing the driver's exception text —
DSN, internal hostname, driver version — to an **unauthenticated** caller.

**Fixed** — readiness returns `{"ready": bool}` and nothing else. The detail moved
to `/health/diagnostics` behind `read_diagnostics`. Withholding it from operators
was never the goal; requiring a credential is.

<a id="threat_model--f-7--environmentkeyprovider-read-osenviron-by-default--low"></a>
#### F-7 — `EnvironmentKeyProvider` read `os.environ` by default · **low**

Found by a fitness rule written during this pass, not by reading. The constructor
accepted an `environ` mapping *and defaulted it to `os.environ`* — dependency
injection with an ambient escape hatch, which is not dependency injection. It also
meant encryption keys could be obtained by any caller anywhere with no visible
wiring.

**Fixed** — the argument is required.

<a id="threat_model--f-8--pre-authentication-xml-denial-of-service-in-the-saml-path--high"></a>
#### F-8 — Pre-authentication XML denial of service in the SAML path · **high**

Historical finding in an unused SAML validator, removed in Phase 2. Its parser
hardening and regression evidence remain recoverable from `archive/pre-cleanup`.
It was not on the service authentication path. Current authentication uses
API keys or OIDC; this section does not claim a shipped SAML capability.

<a id="threat_model--structural-controls"></a>
### Structural controls

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

<a id="threat_model--audit-and-credential-primitives"></a>
### Audit and credential primitives

| Control | Boundary |
|---|---|
| Audit Trails | `security_audit` added to the live schema (migrations v5/v6, forced RLS), `SecurityAudit` port, `SqlSecurityAudit` adapter reusing the existing hash-chain value objects. Wired to authentication failures, authorization denials and approval decisions. Tamper detection verified through the live engine | `test_security_audit_trail.py` (19) |

<a id="threat_model--residual-advisory-risk"></a>
### Residual advisory risk

Output cannot move triage. It is stored and returned to analysts, so the residual target is whatever an analyst pastes it into. Preserve the provenance stamp and shape validation.

<a id="threat_model--6-reproducing-the-findings"></a>
### 6. Reproducing the findings

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


## Eighth Review lifecycle and execution findings

These IDs belong to a separate review from the HTTP findings above.

| ID | Finding | Retained control or boundary |
|---|---|---|
| F-1 | Resume drops artifacts | Hydration; COMPLETED_* facts; chaos+mutation |
| F-2 | Unfenced fail/terminalise | Required Fence; architecture + mutation |
| F-3 | Stored XSS | No `.innerHTML`; console CSP `script-src 'self'`; Trusted Types policy |
| F-4 | No VCS | In-repo version control and CI guards do not establish remote branch protection; remote enforcement requires independent verification. |
| F-5 | Idempotency / fence-before-publish | Gateway key; `assert_holds`; tests |
| F-6 | Unsalted correlation hash | Redact NULLs body |
| F-7 | Fake MONITORING LIVE | Opaque `/health/*`; console LIVE/STALE/DISCONNECTED from poll age |
| F-8 | O(tenants) queue | SqlWorkQueue sharding + tests |
| F-9 | TERMINAL_ERRORS builtins | `failure_is_retryable`; mutation |
| F-11 | Protect mode | Inline `POST /v1/tools/execute` + kill switch + SDK `require_enrolled` refuse path + pageable enrolled `possible_bypass` + NetworkPolicy default-deny/`enrolled=true` allowlist + ValidatingAdmissionPolicy Fail/Deny (`deploy/agent-egress/admission/`) + fail-closed egress-proxy stub + in-repo `admit_agent_workload` (`tests_arch/test_security_bypass_detection.py`). Non-enrolled/off-SDK/silent agents are preventably or detectably fail-closed under the documented contract; wire-level OS transparent intercept **not claimed** (operator breach to leave contract). See `docs/PROTECT_ENFORCEMENT.md`. |
| F-12 | Narrow mutation harness | Critical invariants covered by behavioural probes (fence, epoch, UNAVAILABLE, hydration, idempotency, kill switch, enforce honesty, errors, tool proxy); campaign floor remains |

## Domain state vocabulary (Phase 2)

Current `IncidentState` values (do not invent SEALED/RECORDED/TAMPERED names):

`received`, `validated`, `identity_checked`, `replay_checked`, `policy_evaluated`,
`detected`, `investigated`, `evidence_stored`, `reported`, `awaiting_approval`,
`attested`, `attestation_unavailable`, `completed_attested`, `completed_unattested`,
`failed`, `closed_no_action`.

Terminal: `completed_attested`, `completed_unattested`, `failed`, `closed_no_action`.
`attestation_unavailable` is **not** terminal. Evidence redaction is a ledger
operation (body NULL, commitment retained), not a separate IncidentState.
