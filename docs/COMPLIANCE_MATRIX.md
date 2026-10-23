# Compliance matrix

**Mapping is not certification.** Every row below states which of six distinct
things is true, because collapsing them is how a compliance dashboard becomes
a liability.

| State | Means |
|---|---|
| `IMPLEMENTED` | The control exists in code |
| `TESTED` | A test pytest collects exercises it |
| `EVIDENCE` | A release gate produces a bound artifact for it |
| `MAPPED` | Somebody has asserted it satisfies a framework requirement |
| `AUDITED` | An external party examined it |
| `CERTIFIED` | An accredited body issued an attestation |

**Nothing here is `AUDITED` or `CERTIFIED`.** No external party has examined
this system. A matrix that showed those columns green would be the most
consequential false claim in the repository.

---

## What frameworks certify, and what they do not

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

## OWASP Top 10 for LLM Applications (2025)

| # | Requirement | Sentinel control | State | Evidence |
|---|---|---|---|---|
| LLM01 | Prompt injection | Structural, not filtered: `ModelAdvice` **has no field for a decision**, so injected text cannot authorize | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_security_prompt_injection` (16), `security_tests` gate |
| LLM02 | Sensitive information disclosure | Bounded metadata; readiness returns booleans only; exception text never returned | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_security_bounds` (15), `test_readiness_probe_cache` |
| LLM03 | Supply chain | SBOM, pip-audit, gitleaks over full history, trivy on the image | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `sbom`, `dependency_scanning`, `secret_scanning`, `container_scanning` gates |
| LLM04 | Data and model poisoning | MCP definition pinning + drift; skill contract analysis | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_mcp_estate`, `test_detonation` |
| LLM05 | Improper output handling | Control characters stripped; `[unverified-model-output]` prefix survives copying; console has **no HTML sink** | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_console_bundle` (27) |
| LLM06 | Excessive agency | Deterministic authorization; approval is a separate capability *and* a separate state transition | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_security_edge`, `test_red_team_suite` |
| LLM07 | System prompt leakage | Prompts are commitments in passports, not stored content | `IMPLEMENTED` `TESTED` `MAPPED` | `test_passport_standard` |
| LLM08 | Vector/embedding weaknesses | **NOT APPLICABLE** — Sentinel operates no vector store | `NOT_APPLICABLE` | — |
| LLM09 | Misinformation | Advisory only; cannot move a triage state | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_security_prompt_injection` |
| LLM10 | Unbounded consumption | Rate limits per credential and per address; bounded payloads | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `test_security_throttle` |

## OWASP Agentic AI

| ID | Requirement | State | Evidence |
|---|---|---|---|
| ASI01 | Authorization hijacking | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | Capability grants, never role ordering. An agent credential **can read nothing** |
| ASI02 | Tool misuse | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | `NullRemediationExecutor` **raises** rather than returning a success-shaped receipt |
| ASI03 | Identity and impersonation | `IMPLEMENTED` `TESTED` `MAPPED` | secp256k1 recovery is the only source of an `Address`. **The primitive is unaudited** |
| ASI04 | Supply chain | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | SBOM + 4 scanners |
| ASI05 | Memory and context poisoning | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | Bounded metadata; floats and non-string keys refused so the canonical form is stable |
| ASI06 | Cascading failures | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | Advisory model cannot move triage; saga compensation with a validated pivot |
| ASI07 | Human-in-the-loop bypass | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | An unapproved action cannot execute |
| ASI08 | Prompt injection | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | Structural; see LLM01 |
| ASI09 | Insecure output handling | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` | See LLM05 |

## NIST AI RMF

| Function | Sentinel contribution | State |
|---|---|---|
| **GOVERN** | Policy-as-code, versioned, signed, with rollback | `IMPLEMENTED` `TESTED` `MAPPED` |
| **MAP** | Agent inventory; `MANAGED` / `UNMANAGED` / `REVOKED_BUT_ACTIVE`; blast radius with **coverage stated** | `IMPLEMENTED` `TESTED` `MAPPED` |
| **MEASURE** | Detection evaluation with **Wilson confidence intervals**; `MIN_SAMPLES_TO_QUOTE = 30` | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` |
| **MANAGE** | Containment, approval, kill switch — all attributed and audited | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` |

The MEASURE row is the one worth reading. `evaluation/intervals.py` refuses to
quote a proportion from fewer than 30 samples, because 11/11 is not certainty —
it is a wide interval that looks like a fact.

## MITRE ATLAS

| Technique | Control | State |
|---|---|---|
| Prompt injection (AML.T0051) | Structural separation | `IMPLEMENTED` `TESTED` `MAPPED` |
| LLM plugin compromise (AML.T0053) | MCP pinning, drift, collision detection | `IMPLEMENTED` `TESTED` `MAPPED` |
| Exfiltration via inference (AML.T0057) | Egress allowlist; SSRF validation post-resolution | `IMPLEMENTED` `TESTED` `MAPPED` |
| ML supply chain (AML.T0010) | SBOM, dependency and container scanning | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` |

## SOC 2 Trust Services Criteria — technical subset only

| Criterion | Control | State | The gap |
|---|---|---|---|
| CC6.1 Logical access | Capability grants; tenant from credential, never request | `IMPLEMENTED` `TESTED` `EVIDENCE` | **No access review process.** Organisational |
| CC6.6 External threats | WAF, rate limits, SSRF validation (44 tests) | `IMPLEMENTED` `TESTED` `EVIDENCE` | Deployment-dependent |
| CC7.2 Monitoring | OpenTelemetry; hash-chained security audit | `IMPLEMENTED` `TESTED` `EVIDENCE` | **No 24/7 monitoring rota.** Organisational |
| CC7.3 Incident evaluation | Causal execution graph | `IMPLEMENTED` `TESTED` | **No documented IR process.** Organisational |
| CC8.1 Change management | Signed policy bundles; migration gate | `IMPLEMENTED` `TESTED` `EVIDENCE` | **No approval workflow evidence.** Organisational |
| A1.2 Availability | Multi-AZ architecture | `IMPLEMENTED` | **`UNVERIFIED`** — 99.9%/30d needs 30 days |
| A1.3 Recovery testing | PITR drills, RPO ≈ 57s measured | `IMPLEMENTED` `TESTED` | **`UNVERIFIED`** — the archive is on the same host and disk |

Five of seven gaps are **organisational, not technical.** That is the honest
shape of SOC 2 readiness for a codebase: the code can be ready and the company
can be nowhere near an audit.

## ISO 42001 (AI management)

| Requirement | State |
|---|---|
| AI system inventory | `IMPLEMENTED` `TESTED` `MAPPED` |
| Impact assessment | `MAPPED` — blast radius supports it; no assessment template |
| Human oversight | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` |
| Transparency | `IMPLEMENTED` `TESTED` `EVIDENCE` `MAPPED` — the passport *is* the record |
| **Management system** | **NOT IMPLEMENTED** — a management system is an organisation, not software |

## EU AI Act

Applicability depends on the deployer's use case and risk classification, not
on Sentinel. Where a customer's agents fall in scope, Sentinel supports:

- **Art. 12 record-keeping** — the Execution Passport, independently verifiable
- **Art. 14 human oversight** — approval as a separate capability and state transition
- **Art. 15 accuracy and robustness** — evaluation with confidence intervals

Sentinel makes no claim about a customer's own compliance. It provides records
a customer can use in theirs.

---

## Where evidence lives

| Claim | Artifact |
|---|---|
| Gate statuses | `release/readiness.json` (bound to commit + tree digest) |
| Category scores | `release/scoreboard.json` |
| Release verdict | `release/scorecard.json` |
| Per-capability state | [`engineering/CURRENT_STATE_AUDIT.md`](engineering/CURRENT_STATE_AUDIT.md) — generated |
| Attack surface | `docs/attack_surface.json` — 47 routes, generated |
| Container exposure | `release/gates/gate_container_scanning.json` |

An unbound artifact is `UNVERIFIED`, never `PASS`. Every citation above
resolves to a test pytest collects — enforced by
`test_documentation_cites_real_tests.py`, which exists because this document's
predecessor cited a `tests/` directory that does not exist in this repository.

---

## Related

- [`SECURITY.md`](SECURITY.md#security_assurance)
- [`COMPLIANCE_MAP.md`](COMPLIANCE_MAP.md) — the OWASP/ASI detail
- [`RELEASE_READINESS.md`](RELEASE_READINESS.md)
