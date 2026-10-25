# Compliance

<a id="compliance_map"></a>
<a id="compliance_map--technical-control-mappings"></a>
## Technical control mappings

<a id="compliance_map--read-this-first"></a>
### Read this first

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

<a id="compliance_map--owasp-top-10-2021"></a>
### OWASP Top 10 (2021)

| # | Category | Status | Implementation | Evidence |
|---|---|---|---|---|
| A01 | Broken Access Control | **Covered** | Explicit capability grants, no ordering. Tenant from credential, never from request. Forced RLS with `USING` + `WITH CHECK` | `test_security_edge.py::test_a_viewer_cannot_ingest_events`, `test_one_tenant_cannot_read_another_tenants_incident`, `test_tenant_isolation_rls.py::test_rls_alone_blocks_the_leak_with_the_application_predicate_removed`, `test_no_tenant_owned_table_was_left_out_of_the_protected_set` |
| A02 | Cryptographic Failures | **Covered** | AES-256-GCM envelope encryption, per-record DEK wrapped by KEK, AAD bound to (tenant, type, id). TLS ≥1.2 with verification, never disabled | `test_persistence_crypto_audit.py`, `test_security_rules.py::test_tls_verification_is_never_disabled` |
| A03 | Injection | **Covered** | Parameterised SQL throughout; identifiers composed, never formatted. Prompt injection controlled structurally | `test_security_rules.py::test_sql_strings_interpolate_only_placeholders_and_safe_constants`, `test_security_prompt_injection.py` |
| A04 | Insecure Design | **Covered** | Client cannot assert severity — the field does not exist. Advisory model has no path to a decision. Saga pivot validated at construction | `test_security_prompt_injection.py::test_model_output_carries_no_authority_over_triage`, `test_execution_properties.py` |
| A05 | Security Misconfiguration | **Covered** | Fail-closed configuration; production refuses to boot on wildcard CORS, exposed docs, missing keys, or SQLite. Full security header set. Strict boolean parsing | `test_security_edge.py::test_production_refuses_to_start_with_docs_enabled`, `test_every_security_header_is_present_on_a_data_response` |
| A06 | Vulnerable Components | **Partial** | Runtime dependencies each justified in `requirements.txt`. `pip-audit` in CI | CI job; `scripts/build_sbom_and_licenses.py`; signed provenance requires CI evidence |
| A07 | Identification & Authentication Failures | **Mostly covered** | Fail-closed auth, constant-time comparison with no early exit, duplicate key material refused, ≥32-char keys in production, durable single-use nonce replay guard | `test_end_to_end.py`, `test_security_edge.py::test_malformed_or_absent_credentials_are_refused`. Three-bucket edge rate limiting remains; unused TOTP and overlapping-secret helpers were removed in Phase 2 |
| A08 | Software & Data Integrity Failures | **Covered** | Hash-chained audit entries; identity-bound Merkle leaves; no `pickle`/`yaml.load` | `test_persistence_crypto_audit.py`, `test_persistence_benchmarks.py`, `test_security_rules.py::test_no_module_deserialises_with_pickle_or_unsafe_yaml` |
| A09 | Logging & Monitoring Failures | **Partial** | Hash-chained `security_audit` wired to authentication failures, authorization denials and approval decisions; tamper detection verified. The unused audit-derived detector was removed in Phase 2 | `test_security_audit_trail.py` |
| A10 | SSRF | **Covered** | Post-resolution address validation, one pinned lookup, redirects refused, every resolved address checked, bounded response | `test_security_outbound.py` (44 tests) |

---
<a id="compliance_map--isoiec-270012022--annex-a"></a>
### ISO/IEC 27001:2022 — Annex A

| Control | Technical coverage | Evidence |
|---|---|---|
| A.5.15 Access control | Capability model, deny by default | `test_security_edge.py` |
| A.5.16 Identity management | API-key bindings, unique material enforced. | `test_end_to_end.py` |
| A.5.17 Authentication information | Keys held only as SHA-256 digests; raw material never stored on the binding object | `settings.py::ApiKey` |
| A.8.2 Privileged access | `admin` explicitly excludes `INGEST_EVENT`; `read_diagnostics` is admin-only | `test_security_edge.py::test_admin_cannot_forge_telemetry` |
| A.8.3 Information access restriction | Forced RLS, tenant from credential | `test_sql_infrastructure.py` |
| A.8.5 Secure authentication | Fail-closed API-key/OIDC authentication, constant-time key comparison and durable replay guard; no built-in TOTP login flow | `test_end_to_end.py`, `test_security_edge.py` |
| A.8.7 Protection against malware | No code-execution or unsafe-deserialisation primitives | `test_security_rules.py` |
| A.8.9 Configuration management | Immutable validated settings; production refuses unsafe configuration | `test_security_edge.py` |
| A.8.12 Data leakage prevention | No credential or settings object may reach a logger; readiness carries no internal detail | `test_security_rules.py::test_no_logger_call_passes_a_credential_or_a_whole_settings_object` |
| A.8.13 Information backup | Base backups with manifests, compression, verified restore | `test_persistence_backup_pitr.py` |
| A.8.15 Logging | Structured logging plus a tamper-evident audit trail with dense per-tenant sequencing, so deletion is detectable as a gap | `test_security_audit_trail.py` |
| A.8.16 Monitoring activities | Hash-chained audit events remain; automatic audit-derived threat detection is not shipped | `test_security_audit_trail.py` |
| A.8.24 Use of cryptography | AES-256-GCM, envelope, KEK rotation via `rewrap` without touching plaintext | `test_persistence_crypto_audit.py` |
| A.8.25 Secure development lifecycle | Architecture and security rules as executable fitness functions | `test_architecture_rules.py`, `test_security_rules.py` |
| A.8.26 Application security requirements | This document plus `SECURITY.md`, both with test references | — |
| A.8.28 Secure coding | Property-based, chaos, concurrency, mutation and model-checking suites | `tests_arch/` |

---

<a id="compliance_map--nist"></a>
### NIST

<a id="compliance_map--sp-800-218-ssdf"></a>
#### SP 800-218 (SSDF)

| Practice | Coverage | Evidence |
|---|---|---|
| PW.4 Reuse secure software | Dependencies minimised, each justified | `requirements.txt` |
| PW.5 Create source code securely | Executable security rules; deny-by-default authorisation | `test_security_rules.py` |
| PW.7 Review code | Fitness functions enforce what review would otherwise have to remember | `test_architecture_rules.py` |
| PW.8 Test executable code | 370+ tests including property, chaos, concurrency, mutation, model checking, and an adversarial security suite | `tests_arch/` |
| PW.9 Configure securely by default | Docs off by default; `fail_open` has no default; production refuses unsafe configuration | `test_security_edge.py` |
| RV.1 Identify vulnerabilities | This pass: four proven findings with PoCs, each now a regression test | `SECURITY.md` |

<a id="compliance_map--sp-800-53-control-families"></a>
#### SP 800-53 control families

| Family | Coverage |
|---|---|
| AC — Access Control | **Covered** (AC-2, AC-3, AC-6 least privilege) |
| AU — Audit and Accountability | **Partial.** AU-2/AU-3/AU-9 covered (events selected, content recorded, protected against tampering). AU-6 review absent |
| CM — Configuration Management | **Covered** (CM-2, CM-6, CM-7 least functionality) |
| CP — Contingency Planning | **Covered technically** (CP-9, CP-10 — restore verified) |
| IA — Identification and Authentication | **Partial.** API-key/OIDC authentication is supported; unused TOTP and overlapping-secret helpers were removed in Phase 2 |
| SC — System and Communications Protection | **Covered** (SC-8 transit, SC-13 cryptography, SC-28 at rest) |
| SI — System and Information Integrity | **Partial.** SI-10 input validation is bounded and refusing; audit events are recorded, but the unused audit-derived monitoring helper was removed |

---


<a id="compliance_matrix"></a>
<a id="compliance_matrix--compliance-matrix"></a>
## Compliance matrix

**Mapping is not certification.** Every row below states which of six distinct
things is true, because collapsing them is how a compliance dashboard becomes
a liability.

| State | Means |
|---|---|
| `IMPLEMENTED` | The control exists in code |
| `TESTED` | A test pytest collects exercises it |
| | A release gate produces a bound artifact for it |
| `MAPPED` | Somebody has asserted it satisfies a framework requirement |
| `AUDITED` | An external party examined it |
| `CERTIFIED` | An accredited body issued an attestation |

**Nothing here is `AUDITED` or `CERTIFIED`.** No external party has examined
this system. A matrix that showed those columns green would be the most
consequential false claim in the repository.

---

<a id="compliance_matrix--what-frameworks-certify-and-what-they-do-not"></a>
### What frameworks certify, and what they do not

**SOC 2, ISO 27001 and ISO 42001 certify an organisation, not a codebase.**
SOC 2 Type 2 is an auditor's opinion on whether controls *operated effectively
over a period* — typically 3 to 12 months of evidence. ISO 27001 certifies a
management system: scope, risk assessment, internal audit, management review.

No code change produces any of them. Access reviews, onboarding and
offboarding, vendor management, incident-response drills, business-continuity
testing, background checks and change-management approvals are all
organisational, all in scope, and none is in this repository.

What follows is the **technical control coverage an audit would sample.**

---

<a id="compliance_matrix--owasp-top-10-for-llm-applications-2025"></a>
### OWASP Top 10 for LLM Applications (2025)

| # | Requirement | Sentinel control | State | Evidence |
|---|---|---|---|---|
| LLM01 | Prompt injection | Structural, not filtered: `ModelAdvice` **has no field for a decision**, so injected text cannot authorize | `IMPLEMENTED` `TESTED` `MAPPED` | `test_security_prompt_injection` (16), `security_tests` gate |
| LLM02 | Sensitive information disclosure | Bounded metadata; readiness returns booleans only; exception text never returned | `IMPLEMENTED` `TESTED` `MAPPED` | `test_security_bounds` (15), `test_readiness_probe_cache` |
| LLM03 | Supply chain | SBOM, pip-audit, gitleaks over full history, trivy on the image | `IMPLEMENTED` `TESTED` `MAPPED` | `sbom`, `dependency_scanning`, `secret_scanning`, `container_scanning` gates |
| LLM04 | Data and model poisoning | MCP definition pinning and drift checks | `IMPLEMENTED` `TESTED` `MAPPED` | `test_mcp_registry` |
| LLM05 | Improper output handling | Control characters stripped; `[unverified-model-output]` prefix survives copying; console has **no HTML sink** | `IMPLEMENTED` `TESTED` `MAPPED` | `test_console_bundle` (27) |
| LLM06 | Excessive agency | Deterministic authorization; approval is a separate capability *and* a separate state transition | `IMPLEMENTED` `TESTED` `MAPPED` | `test_security_edge`, `test_red_team_suite` |
| LLM07 | System prompt leakage | Prompts are commitments in passports, not stored content | `IMPLEMENTED` `TESTED` `MAPPED` | `test_passport_standard` |
| LLM08 | Vector/embedding weaknesses | **NOT APPLICABLE** — Sentinel operates no vector store | `NOT_APPLICABLE` | — |
| LLM09 | Misinformation | Advisory only; cannot move a triage state | `IMPLEMENTED` `TESTED` `MAPPED` | `test_security_prompt_injection` |
| LLM10 | Unbounded consumption | Rate limits per credential and per address; bounded payloads | `IMPLEMENTED` `TESTED` `MAPPED` | `test_security_throttle` |

<a id="compliance_matrix--owasp-agentic-ai"></a>
### OWASP Agentic AI

| ID | Requirement | State | Evidence |
|---|---|---|---|
| ASI01 | Authorization hijacking | `IMPLEMENTED` `TESTED` `MAPPED` | Capability grants, never role ordering. An agent credential **can read nothing** |
| ASI02 | Tool misuse | `IMPLEMENTED` `TESTED` `MAPPED` | `NullRemediationExecutor` **raises** rather than returning a success-shaped receipt |
| ASI03 | Identity and impersonation | `IMPLEMENTED` `TESTED` `MAPPED` | secp256k1 recovery is the only source of an `Address`. **The primitive is unaudited** |
| ASI04 | Supply chain | `IMPLEMENTED` `TESTED` `MAPPED` | SBOM + 4 scanners |
| ASI05 | Memory and context poisoning | `IMPLEMENTED` `TESTED` `MAPPED` | Bounded metadata; floats and non-string keys refused so the canonical form is stable |
| ASI06 | Cascading failures | `IMPLEMENTED` `TESTED` `MAPPED` | Advisory model cannot move triage; saga compensation with a validated pivot |
| ASI07 | Human-in-the-loop bypass | `IMPLEMENTED` `TESTED` `MAPPED` | An unapproved action cannot execute |
| ASI08 | Prompt injection | `IMPLEMENTED` `TESTED` `MAPPED` | Structural; see LLM01 |
| ASI09 | Insecure output handling | `IMPLEMENTED` `TESTED` `MAPPED` | See LLM05 |

<a id="compliance_matrix--nist-ai-rmf"></a>
### NIST AI RMF

| Function | Sentinel contribution | State |
|---|---|---|
| **GOVERN** | Policy-as-code, versioned, signed, with rollback | `IMPLEMENTED` `TESTED` `MAPPED` |
| **MAP** | Agent inventory; `MANAGED` / `UNMANAGED` / `REVOKED_BUT_ACTIVE`; blast radius with **coverage stated** | `IMPLEMENTED` `TESTED` `MAPPED` |
| **MEASURE** | Detection evaluation with **Wilson confidence intervals**; `MIN_SAMPLES_TO_QUOTE = 30` | `IMPLEMENTED` `TESTED` `MAPPED` |
| **MANAGE** | Containment, approval, kill switch — all attributed and audited | `IMPLEMENTED` `TESTED` `MAPPED` |

The MEASURE row is the one worth reading. `evaluation/intervals.py` refuses to
quote a proportion from fewer than 30 samples, because 11/11 is not certainty —
it is a wide interval that looks like a fact.

<a id="compliance_matrix--mitre-atlas"></a>
### MITRE ATLAS

| Technique | Control | State |
|---|---|---|
| Prompt injection (AML.T0051) | Structural separation | `IMPLEMENTED` `TESTED` `MAPPED` |
| LLM plugin compromise (AML.T0053) | MCP pinning, drift, collision detection | `IMPLEMENTED` `TESTED` `MAPPED` |
| Exfiltration via inference (AML.T0057) | Egress allowlist; SSRF validation post-resolution | `IMPLEMENTED` `TESTED` `MAPPED` |
| ML supply chain (AML.T0010) | SBOM, dependency and container scanning | `IMPLEMENTED` `TESTED` `MAPPED` |

<a id="compliance_matrix--soc-2-trust-services-criteria--technical-subset-only"></a>
### SOC 2 Trust Services Criteria — technical subset only

| Criterion | Control | State | The gap |
|---|---|---|---|
| CC6.1 Logical access | Capability grants; tenant from credential, never request | `IMPLEMENTED` `TESTED` | **No access review process.** Organisational |
| CC6.6 External threats | WAF, rate limits, SSRF validation (44 tests) | `IMPLEMENTED` `TESTED` | Deployment-dependent |
| CC7.2 Monitoring | OpenTelemetry; hash-chained security audit | `IMPLEMENTED` `TESTED` | **No 24/7 monitoring rota.** Organisational |
| CC7.3 Incident evaluation | Causal execution graph | `IMPLEMENTED` `TESTED` | **No documented IR process.** Organisational |
| CC8.1 Change management | Signed policy bundles; migration gate | `IMPLEMENTED` `TESTED` | **No approval workflow evidence.** Organisational |
| A1.2 Availability | Multi-AZ architecture | `IMPLEMENTED` | **`UNVERIFIED`** — 99.9%/30d needs 30 days |
| A1.3 Recovery testing | PITR drills, RPO ≈ 57s measured | `IMPLEMENTED` `TESTED` | **`UNVERIFIED`** — the archive is on the same host and disk |

Five of seven gaps are **organisational, not technical.** That is the honest
shape of SOC 2 readiness for a codebase: the code can be ready and the company
can be nowhere near an audit.

<a id="compliance_matrix--iso-42001-ai-management"></a>
### ISO 42001 (AI management)

| Requirement | State |
|---|---|
| AI system inventory | `IMPLEMENTED` `TESTED` `MAPPED` |
| Impact assessment | `MAPPED` — blast radius supports it; no assessment template |
| Human oversight | `IMPLEMENTED` `TESTED` `MAPPED` |
| Transparency | `IMPLEMENTED` `TESTED` `MAPPED` — the passport *is* the record |
| **Management system** | **NOT IMPLEMENTED** — a management system is an organisation, not software |

<a id="compliance_matrix--eu-ai-act"></a>
### EU AI Act

Applicability depends on the deployer's use case and risk classification, not
on Sentinel. Where a customer's agents fall in scope, Sentinel supports:

- **Art. 12 record-keeping** — the Execution Passport, independently verifiable
- **Art. 14 human oversight** — approval as a separate capability and state transition
- **Art. 15 accuracy and robustness** — evaluation with confidence intervals

Sentinel makes no claim about a customer's own compliance. It provides records
a customer can use in theirs.

---
