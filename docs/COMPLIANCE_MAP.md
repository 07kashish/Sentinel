# Control mapping: OWASP, ASI, SOC 2, ISO 27001, NIST

> ## Correction — the evidence column was unbacked, and now is not
>
> **Retracted 2026-08-19 by an automated check. Repaired 2026-09-01.**
>
> `tests_arch/test_documentation_cites_real_tests.py` scans every document for
> test identifiers and requires each to resolve to a test `pytest` actually
> collects. It found this document citing `test_rls_is_actually_enforced` in a
> `tests/` directory that does not exist here — a name inherited from the
> predecessor implementation this codebase replaced. The whole Evidence column
> was retracted on that basis.
>
> **What was actually wrong was one citation.** Re-measured on 2026-09-01, 37
> of this document's 38 distinct citations resolved; the single exception was
> that inherited name. Row A01 now cites
> `test_tenant_isolation_rls.py`, which is where tenant isolation is really
> proven — eight tests including
> `test_no_tenant_owned_table_was_left_out_of_the_protected_set`, a catalogue
> query that fails if any table with a `tenant_id` column lacks a forced
> policy.
>
> Those tests were **executed against a real PostgreSQL server on 2026-09-01**,
> as a non-superuser role, against schema v29. That matters: a superuser
> bypasses row-level security entirely, so running them as one would make every
> assertion pass vacuously.
>
> The retraction is corrected rather than deleted. A blanket retraction over a
> single stale name is itself a miscalibrated claim, and quietly removing the
> banner would destroy the record of both errors — the original citation and
> the overcorrection.
>
> **This document still does not certify anything.** See *Read this first*.

---


Every row names the code that implements a control and the test that proves it. A
row with no test column is not a control, it is an intention, and it is marked as
one.

## Read this first

**SOC 2, ISO 27001 and NIST certify an organisation, not a codebase.** SOC 2 Type 2
is an auditor's opinion on whether controls *operated effectively over a period* —
typically 3 to 12 months of evidence. ISO 27001 certifies a management system:
scope, risk assessment, internal audit, management review. NIST 800-53 and the SSDF
are control catalogues an organisation adopts.

No code change produces any of them. Access reviews, onboarding and offboarding,
vendor management, incident response drills, business continuity testing, background
checks, and change-management approvals are all organisational and all in scope for
those audits. They are not in this repository and cannot be.

What follows is the **technical control coverage an audit would sample**, with
evidence. Presenting it as anything more would be the kind of claim this document
exists to avoid.

---

## OWASP Top 10 (2021)

| # | Category | Status | Implementation | Evidence |
|---|---|---|---|---|
| A01 | Broken Access Control | **Covered** | Explicit capability grants, no ordering. Tenant from credential, never from request. Forced RLS with `USING` + `WITH CHECK` | `test_security_edge.py::test_a_viewer_cannot_ingest_events`, `test_one_tenant_cannot_read_another_tenants_incident`, `test_tenant_isolation_rls.py::test_rls_alone_blocks_the_leak_with_the_application_predicate_removed`, `test_no_tenant_owned_table_was_left_out_of_the_protected_set` |
| A02 | Cryptographic Failures | **Covered** | AES-256-GCM envelope encryption, per-record DEK wrapped by KEK, AAD bound to (tenant, type, id). TLS ≥1.2 with verification, never disabled | `test_persistence_crypto_audit.py`, `test_security_rules.py::test_tls_verification_is_never_disabled` |
| A03 | Injection | **Covered** | Parameterised SQL throughout; identifiers composed, never formatted. Prompt injection controlled structurally | `test_security_rules.py::test_sql_strings_interpolate_only_placeholders_and_safe_constants`, `test_security_prompt_injection.py` |
| A04 | Insecure Design | **Covered** | Client cannot assert severity — the field does not exist. Advisory model has no path to a decision. Saga pivot validated at construction | `test_security_prompt_injection.py::test_model_output_carries_no_authority_over_triage`, `test_execution_properties.py` |
| A05 | Security Misconfiguration | **Covered** | Fail-closed configuration; production refuses to boot on wildcard CORS, exposed docs, missing keys, or SQLite. Full security header set. Strict boolean parsing | `test_security_edge.py::test_production_refuses_to_start_with_docs_enabled`, `test_every_security_header_is_present_on_a_data_response` |
| A06 | Vulnerable Components | **Partial** | Runtime dependencies reduced to 7, each justified in `requirements.txt`. `pip-audit` in CI | CI job; **no SBOM, no signed provenance** |
| A07 | Identification & Authentication Failures | **Mostly covered** | Fail-closed auth, constant-time comparison with no early exit, duplicate key material refused, ≥32-char keys in production, durable single-use nonce replay guard | `test_end_to_end.py`, `test_security_edge.py::test_malformed_or_absent_credentials_are_refused`. TOTP MFA (RFC vectors), overlapping secret rotation, and three-bucket edge rate limiting are now implemented |
| A08 | Software & Data Integrity Failures | **Covered** | Hash-chained audit entries; identity-bound Merkle leaves; migration checksums refuse a modified applied migration; no `pickle`/`yaml.load` | `test_persistence_crypto_audit.py`, `test_persistence_benchmarks.py`, `test_security_rules.py::test_no_module_deserialises_with_pickle_or_unsafe_yaml` |
| A09 | Logging & Monitoring Failures | **Partial** | Hash-chained `security_audit` wired to authentication failures, authorization denials and approval decisions; tamper detection verified. Detections derived from the chain, each citing the audit sequences it used | `test_security_audit_trail.py` (19), `test_security_threat_detection.py` (16) |
| A10 | SSRF | **Covered** | Post-resolution address validation, one pinned lookup, redirects refused, every resolved address checked, bounded response | `test_security_outbound.py` (44 tests) |

---

## OWASP Agentic Security Initiative

The threat classes specific to agent systems, which is what this product watches.

| ID | Threat | Status | Implementation | Evidence |
|---|---|---|---|---|
| ASI01 | Agent Authorisation & Control Hijacking | **Covered** | Capabilities not ordering; agent credentials hold `INGEST_EVENT` and can read nothing; no human credential can ingest | `test_security_edge.py::test_the_ingest_role_can_read_nothing` |
| ASI02 | Tool Misuse | **Covered** | Remediation requires an explicit approval by a distinct capability; `NullRemediationExecutor` raises rather than returning a success-shaped receipt | `test_application_pipeline.py`, `test_security_edge.py::test_a_viewer_cannot_decide_an_approval` |
| ASI03 | Identity & Impersonation | **Covered** | secp256k1 recovery is the only source of an `Address`; unenrolled recovered addresses are INVALID; unsigned events capped at severity 79 | `test_domain_incident.py`, `test_end_to_end.py`. **The ECDSA recovery primitive remains unaudited** |
| ASI04 | Supply Chain | **Partial** | Dependencies minimised and justified | **No SBOM, no signature verification** |
| ASI05 | Memory & Context Poisoning | **Covered** | Bounded metadata refusing depth, breadth and size; floats and non-string keys refused so the canonical form is stable; refuse rather than truncate | `test_security_bounds.py` (15 tests) |
| ASI06 | Cascading Failures | **Covered** | Advisory model cannot move triage; saga compensation ordered with a validated pivot; transient vs permanent failure distinguished at the adapter | `test_execution_chaos.py`, `test_execution_model.py` |
| ASI07 | Human-in-the-Loop Bypass | **Covered** | Approval is a separate capability and a separate state transition; an unapproved action cannot execute | `test_domain_incident.py` |
| ASI08 | Prompt Injection | **Controlled structurally** | `ModelAdvice` cannot express a decision; spotlighting; fence-stripping; output shape validation; provenance stamped into the string | `test_security_prompt_injection.py` (16 tests) |
| ASI09 | Insecure Output Handling | **Covered** | Control characters stripped from stored model output; markup-heavy output discarded; `[unverified-model-output]` prefix survives copying | `test_security_prompt_injection.py::test_control_characters_are_stripped_from_stored_output` |
| ASI10 | Overreliance / Unverifiable Claims | **Covered** | `NOT_ANCHORABLE` and `UNAVAILABLE` are distinct dispositions; a deployment with no gateway completes incidents as `completed_unattested` rather than claiming attestation | `test_domain_incident.py`, `test_application_pipeline.py` |

---

## SOC 2 — Trust Services Criteria

Technical coverage only. The organisational half of every one of these is out of
scope for a code change.

| TSC | Criterion | Technical coverage | Evidence | Organisational half (absent) |
|---|---|---|---|---|
| CC6.1 | Logical access — authorisation | Capability grants, deny by default, `roles_holding()` answers "who can do X" in one call | `test_security_edge.py` | Access review cadence, approval records |
| CC6.1 | Logical access — authentication | Fail-closed bearer auth, constant-time, unique material, TOTP MFA (RFC 6238 vectors), overlapping secret rotation | `test_end_to_end.py`, `test_security_mfa.py`, `test_security_secrets.py` | Joiner/leaver process, rotation cadence, **no human login flow yet** |
| CC6.6 | Boundary protection | TLS ≥1.2 verified; SSRF controls; no ambient credentials | `test_security_outbound.py` | Firewall/WAF configuration records |
| CC6.7 | Data in transit and at rest | AES-256-GCM at rest with per-record DEKs; TLS in transit; KEKs fetched from a KMS over the hardened client with a bounded cache | `test_persistence_crypto_audit.py`, `test_security_secrets.py` | Key custody procedure; **no request has reached a real KMS** |
| CC6.8 | Malicious software prevention | No code-execution primitives; no unsafe deserialisation | `test_security_rules.py` | Endpoint management |
| CC7.1 | Detection of anomalies | **Covered** — stuffing, privilege probing and enumeration derived from the audit chain | `test_security_threat_detection.py` | Alerting, on-call rotation |
| CC7.2 | Monitoring and audit trail | **Covered** — append-only hash-chained trail on every authn/authz decision and every approval | `test_security_audit_trail.py` | SIEM ingestion, retention policy |
| CC7.3 | Incident evaluation | Incident lifecycle with legal-only transitions; durable journal | `test_execution_model.py` | IR plan, post-incident review |
| CC8.1 | Change management | Checksummed reversible migrations; fitness functions failing the build | `test_persistence_benchmarks.py`, `test_architecture_rules.py` | Change approval records |
| A1.2 | Availability — recovery | **PITR verified by an actual restore to a chosen instant** | `test_persistence_backup_pitr.py` (19 tests) | RTO/RPO commitments, DR exercise records |
| C1.1 | Confidentiality — tenant isolation | Forced RLS verified as a non-superuser; envelope AAD binds ciphertext to tenant | `test_sql_infrastructure.py`, `test_persistence_crypto_audit.py` | Data classification policy |

---

## ISO/IEC 27001:2022 — Annex A

| Control | Technical coverage | Evidence |
|---|---|---|
| A.5.15 Access control | Capability model, deny by default | `test_security_edge.py` |
| A.5.16 Identity management | API-key bindings, unique material enforced. **No human identity lifecycle** | `test_end_to_end.py` |
| A.5.17 Authentication information | Keys held only as SHA-256 digests; raw material never stored on the binding object | `settings.py::ApiKey` |
| A.8.2 Privileged access | `admin` explicitly excludes `INGEST_EVENT`; `read_diagnostics` is admin-only | `test_security_edge.py::test_admin_cannot_forge_telemetry` |
| A.8.3 Information access restriction | Forced RLS, tenant from credential | `test_sql_infrastructure.py` |
| A.8.5 Secure authentication | Fail-closed, constant-time, durable replay guard, TOTP second factor with per-step replay defence | `test_end_to_end.py`, `test_security_mfa.py` |
| A.8.7 Protection against malware | No code-execution or unsafe-deserialisation primitives | `test_security_rules.py` |
| A.8.9 Configuration management | Immutable validated settings; production refuses unsafe configuration | `test_security_edge.py` |
| A.8.12 Data leakage prevention | No credential or settings object may reach a logger; readiness carries no internal detail | `test_security_rules.py::test_no_logger_call_passes_a_credential_or_a_whole_settings_object` |
| A.8.13 Information backup | Base backups with manifests, compression, verified restore | `test_persistence_backup_pitr.py` |
| A.8.15 Logging | Structured logging plus a tamper-evident audit trail with dense per-tenant sequencing, so deletion is detectable as a gap | `test_security_audit_trail.py` |
| A.8.16 Monitoring activities | Detections derived from the hash-chained trail, each citing the audit sequences it was computed from | `test_security_threat_detection.py` |
| A.8.24 Use of cryptography | AES-256-GCM, envelope, KEK rotation via `rewrap` without touching plaintext | `test_persistence_crypto_audit.py` |
| A.8.25 Secure development lifecycle | Architecture and security rules as executable fitness functions | `test_architecture_rules.py`, `test_security_rules.py` |
| A.8.26 Application security requirements | This document plus `THREAT_MODEL.md`, both with test references | — |
| A.8.28 Secure coding | Property-based, chaos, concurrency, mutation and model-checking suites | `tests_arch/` |

---

## NIST

### SP 800-218 (SSDF)

| Practice | Coverage | Evidence |
|---|---|---|
| PW.4 Reuse secure software | Dependencies minimised to 7 runtime packages, each justified | `requirements.txt` |
| PW.5 Create source code securely | Executable security rules; deny-by-default authorisation | `test_security_rules.py` |
| PW.7 Review code | Fitness functions enforce what review would otherwise have to remember | `test_architecture_rules.py` |
| PW.8 Test executable code | 370+ tests including property, chaos, concurrency, mutation, model checking, and an adversarial security suite | `tests_arch/` |
| PW.9 Configure securely by default | Docs off by default; `fail_open` has no default; production refuses unsafe configuration | `test_security_edge.py` |
| RV.1 Identify vulnerabilities | This pass: four proven findings with PoCs, each now a regression test | `THREAT_MODEL.md` |

### SP 800-53 control families

| Family | Coverage |
|---|---|
| AC — Access Control | **Covered** (AC-2, AC-3, AC-6 least privilege) |
| AU — Audit and Accountability | **Partial.** AU-2/AU-3/AU-9 covered (events selected, content recorded, protected against tampering). AU-6 review absent |
| CM — Configuration Management | **Covered** (CM-2, CM-6, CM-7 least functionality) |
| CP — Contingency Planning | **Covered technically** (CP-9, CP-10 — restore verified) |
| IA — Identification and Authentication | **Partial.** IA-2 has TOTP MFA but no human login flow to attach it to; IA-5 rotation implemented |
| SC — System and Communications Protection | **Covered** (SC-8 transit, SC-13 cryptography, SC-28 at rest) |
| SI — System and Information Integrity | **Covered.** SI-10 input validation bounded and refusing; SI-4 monitoring derived from the audit chain |

---

## The honest summary

**Covered with evidence:** access control, SSRF, injection, cryptography at rest and
in transit, tenant isolation, input validation and bounds, backup and recovery,
secure configuration, supply-chain minimisation, and the agent-specific classes
including prompt injection and memory poisoning.

**Not covered, in priority order:**

1. **A human login flow.** TOTP MFA is implemented and verified against the RFC's
   vectors, and there is nothing to attach it to: authentication is a bearer API key
   bound to `(tenant, role)`, with no user, session or login ceremony. MFA without a
   login flow is a correct primitive with no caller. This is the prerequisite for
   passkeys, SAML and SCIM, and it is a product decision before it is an
   implementation -- human principals may belong in a gateway in front of this
   service rather than in it.
2. **Passkeys (WebAuthn).** Needs a browser origin and a registration ceremony,
   both of which need item 1.
3. **SAML.** Sentinel ships an **assertion validator** (`sentinel/infrastructure/saml.py`)
   that verifies RSA signatures against a configured IdP certificate, audience,
   issuer, expiry, and tenant claim. That is **not** a hosted IdP and must not be
   presented as one. Evidence: `tests_arch/test_gap_closures.py`
   (`test_saml_validator_rejects_assertion_signed_by_untrusted_idp_cert`). Full SP
   login ceremony still needs a human identity product decision (item 1). Prefer
   OIDC for new deployments; see `THREAT_MODEL.md` §4 on hand-rolled XML signature risk.
4. **SCIM.** Users API is in-tree behind `MANAGE_USERS`; Groups productization and
   IdP-driven lifecycle remain incomplete without a broader human-identity product.
5. **A real KMS round trip.** Adapter is logic-complete; no request has reached a
   real KMS in this workspace. Redis and MinIO live CI jobs are wired
   (`live-redis`, `live-minio`); local runs skip without env.
6. **SBOM and signed provenance** -- A06, ASI04.

An auditor sampling items 1-4 would find that human authentication is not
implemented, and would be right to. Nothing in this document claims otherwise.
