# Current state audit



- commit: `08c2ef35f418d50494bb6a0c32dabc0b6cf8dd6e`
- generated: 2026-09-02T13:21:50.548306+00:00
- tests collected: **2617**
- gates: **21 PASS** of 26

## How to read the columns

| Column | Derived from | Means |
|---|---|---|
| Implemented | The module existing on disk | The code is there. Not that it is complete |
| Tested | Tests **pytest actually collects** | Not a `def test_` count — an uncollected test is not a test |
| Production proven | The release gate, from `readiness.json` | Evidence it works on the engine production uses |
| Gap | **Hand-written** | No script can derive completeness |

Those first three are different claims. A capability can be implemented, thoroughly tested, and still have no evidence it works on PostgreSQL. A single "done" column collapses that distinction, which is why there are three.

## Capabilities

| Capability | Implemented | Tested | Production proven | Gap | Priority |
|---|---|---|---|---|---|
| **Deterministic authorization** | yes (2 modules, 474 lines) | 34 collected | yes — `security_tests` PASS | None known. `stops_action` uses an allowlist of what proceeds, so a new decision type stops by default. | P0 |
| **Tenant isolation** | yes (1 module, 647 lines) | 72 collected | yes — `postgres_tests` PASS | Proven for database, RLS and S3 prefixes. Cross-tenant isolation of metrics labels and trace attributes is asserted by convention rather than by a test. | P0 |
| **Execution Passport** | yes (2 modules, 787 lines) | 24 collected | yes — `unit_tests` PASS | Signed, chained, independently verifiable. No transparency log, so deletion of a whole passport is undetectable without an external commitment. | P0 |
| **Independent verifier** | yes (1 module, 425 lines) | 24 collected | yes — `unit_tests` PASS | None. Byte-identical canonicalisation proven against the producer. | P0 |
| **MCP trust gateway** | yes (2 modules, 614 lines) | 115 collected | yes — `security_tests` PASS | Shadow-server detection CANNOT FIRE: there is no per-server usage table, and the endpoint says so rather than reporting zero. | P1 |
| **A2A trust gateway** | yes (2 modules, 1053 lines) | 80 collected | yes — `security_tests` PASS | Streaming transport is NOT WIRED. The guard exists; nothing streams. | P1 |
| **Delegation lineage** | yes (2 modules, 675 lines) | 45 collected | yes — `unit_tests` PASS | Constraint kinds and transitive reach are modelled. No integration with SPIFFE/SPIRE or STS session tags. | P1 |
| **Blast radius** | yes (1 module, 260 lines) | 44 collected | yes — `unit_tests` PASS | No persistent asset-declaration store. Declarations are per-request and `coverage` is reported, so a low score over low coverage cannot read as safe. | P1 |
| **Policy simulation** | yes (1 module, 298 lines) | 20 collected | yes — `unit_tests` PASS | Replays immutable history and never executes. No business-impact estimate, which the specification asks for. | P1 |
| **Skill detonation** | yes (2 modules, 935 lines) | 50 collected | yes — `security_tests` PASS | CONTRACT ONLY. `RefusingDetonator` refuses rather than pretending. No Firecracker/gVisor isolation, so no untrusted code is ever executed. | P2 |
| **Threat intelligence** | yes (1 module, 440 lines) | 41 collected | yes — `unit_tests` PASS | Publication decision only. No feed, client or server, and no reputation service. | P2 |
| **Cloud discovery** | yes (2 modules, 721 lines) | 142 collected | yes — `unit_tests` PASS | AWS adapters and a connector interface exist. NO Microsoft, Google, Salesforce, Databricks or developer-agent connectors. Coverage is reported per connector so partial discovery cannot read as complete. | P1 |
| **Release assurance** | yes (2 modules, 1336 lines) | 54 collected | yes — `architecture_tests` PASS | `artifact_signing` needs a CI OIDC identity. Everything else a build can decide is measured. | P0 |
| **Enterprise console** | yes (1 module, 1157 lines) | 27 collected | yes — `unit_tests` PASS | 9 data-backed views against 16 of 17 GET endpoints. The specification asks for 20 pages; the remaining endpoints do not exist to back them. | P1 |
| **AWS identity** | yes (1 module, 368 lines) | **NONE** | **NOT APPLICABLE** — no gate covers it | Terraform validated and NOT APPLIED. No AWS resource exists. UNTESTED: there is no automated test for the IAM policy documents. | P0 |

## What this audit found

**Untested capabilities (1):** `AWS identity`

**No production evidence (1):** `AWS identity`

The AWS identity layer is the honest example of both. The Terraform validates and no AWS resource has been created, so it is implemented, untested and unproven — three separate facts, and a matrix that reported it as "done" because the file exists would be the security theatre this repository is built to avoid.

## Related

- [`../STATUS.md`](../STATUS.md#release_readiness) — the two scoreboards
- [`../SECURITY.md`](../SECURITY.md#security_assurance)
