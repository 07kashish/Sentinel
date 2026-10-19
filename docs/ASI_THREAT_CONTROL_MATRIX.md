# ASI / OWASP threat–control matrix (honest coverage)

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
| XSS in analyst console | HTML UI removed; CSP none | verified (sink-removed) | F-3 |
| SSRF / token theft via redirect | HardenedHttpClient refuses redirects | verified (suite) | `test_security_outbound.py` |

Gaps deliberately open: full ASI taxonomy mapping, multilingual injection,
novel C2 without feeds, inline protect for non-integrating agents.
