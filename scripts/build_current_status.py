#!/usr/bin/env python3
"""Generate docs/current/RELEASE_STATUS.{md,json} and render the risk register.

FIVE TIERS, NOT ONE COLUMN
--------------------------
Every capability is placed on the highest tier for which evidence EXISTS in
this tree at this commit:

    implemented          the modules are on disk
    unit_tested          mapped tests passed in a verified current run
    integration_tested   mapped PostgreSQL cases passed in that run
    production_observed  reserved for verified real-tenant observation
    externally_verified  reserved for verified independent assessment

Tiers are computed, never typed. The top two tiers have no evidence in this
repository today and the document says so for every row rather than leaving
the column out.

BOUND TO A COMMIT AND TO ARTIFACT DIGESTS
-----------------------------------------
The JSON records the commit, whether the tree was dirty, the source-tree
digest from `scripts/release_binding.py`, and the sha256 of every artifact it
was given. A reader can therefore tell which build a status describes. The
committed copy is a snapshot taken on a development machine; the copy CI
regenerates and stamps is the one to cite.

WHAT IT REFUSES
---------------
A collection that finds fewer than 100 tests (a broken environment would
otherwise place everything on the `implemented` tier and the document would
understate coverage everywhere), and a risk register whose entries lack a
closing-evidence statement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_binding import release_identity_from_git  # noqa: E402
from scripts.current_test_evidence import identity as test_identity, read_verified  # noqa: E402

CURRENT = ROOT / "docs" / "current"
RISKS = CURRENT / "RISK_REGISTER.json"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
TIERS = ("implemented", "unit_tested", "integration_tested", "production_observed", "externally_verified")
FORBIDDEN_CLAIMS = ("production-ready", "production ready", "market-leading", "market leading",
                    "enterprise-grade", "fully compliant", "battle-tested")


class Capability(NamedTuple):
    key: str
    name: str
    modules: tuple[str, ...]
    #: test module stems; those whose nodes carry the `postgres` param count
    #: toward the integration tier
    tests: tuple[str, ...]
    ci_jobs: tuple[str, ...]
    #: hand-written; the one column no script can derive
    limits: str


CAPABILITIES: tuple[Capability, ...] = (
    Capability("authorization", "Execution authorization and binding",
               ("sentinel/domain/execution_binding.py", "sentinel/application/tool_runner.py",
                "sentinel/infrastructure/sql/authorization_store.py", "sentinel/infrastructure/sql/nonce_ledger.py"),
               ("test_execution_binding", "test_execution_contract", "test_authorization_routes", "test_execution_concurrency", "test_shared_process_controls", "test_kubernetes_live_contract"),
               ("test", "live-postgres"),
               "Bound to tenant, agent, tool, action, resource, parameter digest, policy digest, expiry and single-use nonce. The agent can be an attested workload (see Workload identity); that is off until a customer issuer is registered."),
    Capability("approval", "Approval semantics under enforcement",
               ("sentinel/application/protect_gate.py", "sentinel/interface/authorizations.py"),
               ("test_execution_contract", "test_protect_gate", "test_kubernetes_live_contract", "test_approval_experience"),
               ("test", "live-postgres"),
               "A recorded approval satisfies require_approval only; never step_up_auth, block or contain. Approvers see a redacted structural view of the change. A quorum of distinct approvers and requester/approver separation are enforced. No integration with an external ticketing or paging system."),
    Capability("operations", "Durable intent and outcome, reconcilable unknown state",
               ("sentinel/domain/operations.py", "sentinel/infrastructure/sql/operation_store.py",
                "sentinel/interface/operations_routes.py"),
               ("test_operation_store", "test_execution_contract", "test_execution_uncertainty", "test_kubernetes_outcome", "test_adapter_outcomes"),
               ("test", "live-postgres"),
               "A definitive target rejection is a recorded failure; a lost response is unknown and is reconciled from the target automatically for the Kubernetes tool, with bounded attempts and a quiescence window. GitHub contents writes and deletes are reconciled from the blob sha without attribution; AWS operations run under a brokered role session are reconciled from CloudTrail by session name, where absence of an event is never read as failure; GitHub POSTs, other PUTs, AWS data events and AWS without a brokered role still need a human (RISK R-012). For GitHub and AWS a 4xx is now a recorded failure instead of a succeeded operation."),
    Capability("controls", "Shared, tenant-scoped budget and circuit breaker",
               ("sentinel/infrastructure/sql/protect_controls_store.py",),
               ("test_operation_store", "test_execution_contract", "test_protect_controls"),
               ("test", "live-postgres"),
               "State lives in the database with a row lock; fails closed when the store is unavailable. Not yet load-tested across more than two pools."),
    Capability("identity", "Workload identity for agents",
               ("sentinel/infrastructure/agent_identity_providers.py", "sentinel/interface/principals.py"),
               ("test_workload_identity", "test_agent_identity_providers", "test_protected_change_journey", "test_tenant_directory"),
               ("test",),
               "SPIFFE JWT-SVIDs and pod-bound Kubernetes service-account tokens are verified against registered keys; SENTINEL_REQUIRE_WORKLOAD_IDENTITY refuses API keys on the agent path. Keys are pinned or fetched from a stated or DISCOVERED https jwks_uri (OIDC metadata, which is how SPIRE, Okta and Entra publish keys) with rate-limited rotation that keeps the last good keys; the SPIRE Workload API itself is not spoken. A pod-bound token was accepted from a real agent pod on a local cluster. Default is off (DECISION_LOG FCX-006). No customer identity provider has been integrated."),
    Capability("credentials", "Constrained credentials and bypass prevention",
               ("sentinel/infrastructure/platforms/kubernetes.py", "sentinel/infrastructure/platforms/kubernetes_outcome.py",
                "sentinel/infrastructure/platforms/aws_outcome.py", "sentinel/infrastructure/platforms/github_app.py",
                "deploy/protected-changes/admission-policy.yaml", "deploy/protected-changes/rbac.yaml"),
               ("test_kubernetes_outcome", "test_protected_changes_manifests", "test_protected_change_journey", "test_kubernetes_live_contract", "test_adapter_outcomes"),
               ("test",),
               "Sentinel holds a broker token that can only mint ten-minute tokens for one executor account; the API server refuses agent writes and unstamped executor writes in protected namespaces. Deletes are stamped on the object and admission requires the stamp. Proven in-process against a real API server and DEPLOYED (two pods, production mode, pod-bound agent token, kindnet enforcing the agent egress policy) by scripts/run_deployed_journey.py on one local node. The deployed run uses TLS between agent and Sentinel under a private CA. A cloud cluster, another CNI, mutual TLS and a customer are unverified. AWS gets a fifteen-minute role session per operation and GitHub a per-call App installation token scoped to one repository and permission family; both are tested against fakes only, never against the real services, and neither has a target-side bypass control like the Kubernetes admission policy."),
    Capability("measurement", "Workflow measurement",
               ("sentinel/infrastructure/sql/workflow_metrics.py",),
               ("test_workflow_metrics", "test_component_status"),
               ("test",),
               "Approval latency, interruptions, refusals and unknown outcomes are counted from records with sample sizes. Gateway overhead, refusal legitimacy and onboarding effort are not derivable from records and are named as such. scripts/run_workflow_loadtest.py measures the bound path on one machine as a regression baseline, not a capacity claim. No customer data exists."),
    Capability("tenancy", "Tenant isolation in storage",
               ("sentinel/infrastructure/sql/schema.py", "sentinel/infrastructure/sql/engine.py"),
               ("test_tenant_isolation_rls", "test_security_edge", "test_sql_infrastructure"),
               ("test", "live-postgres", "live-postgres-service"),
               "Forced row-level security on PostgreSQL; explicit tenant predicates on SQLite. Operational telemetry omits tenant/agent identifiers; durable records are tenant-scoped. Per-pod aggregation and soak remain unverified (RISK R-008)."),
    Capability("receipts", "Execution receipts and Execution Passport",
               ("sentinel/domain/passport.py", "sentinel/infrastructure/passport_signing.py",
                "sentinel/infrastructure/sql/receipt_store.py", "sentinel/infrastructure/sql/evidence_commitments.py",
                "standard/execution-passport-v1/verify_evidence_bundle.py"),
               ("test_passport_standard", "test_execution_passport", "test_receipt_store", "test_evidence_commitments", "test_evidence_recovery", "test_evidence_encryption"),
               ("test", "verification"),
               "Receipts are committed to the tenant transparency log by the maintenance loop and export as a bundle that verifies offline with the standard library. Commitment is asynchronous; the export reports the uncommitted count. Evidence BODIES are sealed per record (AES-256-GCM envelope, bound to tenant and incident) when a data key is configured, production refuses to start without a key or an explicit opt-out, and rotation rewraps without decrypting payloads; keys come from the environment or a Kubernetes secret, not yet from a KMS. A customer can witness roots with a standalone tool that verifies consistency locally, and a drill restores evidence into a new database and verifies an old bundle against the customer-held root. One host: not an independent failure domain (RISK R-003); no customer runs the witness (RISK R-018)."),
    Capability("coverage", "Coverage model (observed vs routed vs enforced)",
               ("sentinel/infrastructure/sql/coverage.py", "sentinel/interface/operations_routes.py"),
               ("test_execution_contract",),
               ("test",),
               "Reports counts per tenant and refuses to combine them into a percentage. Bypass signals depend on the endpoint sensor being deployed."),
    Capability("policy", "Deterministic policy and policy versions",
               ("sentinel/infrastructure/detection.py", "sentinel/domain/policy_as_code.py"),
               ("test_security_rules", "test_policy_diff_and_blast_radius", "test_detection_mode"),
               ("test",),
               "Deterministic rule contents and active tenant policy bind authorizations. Tenant policy can tighten the baseline; ML remains advisory. The optional classifier is repository-only (RISK R-010) and its corpus is curated (RISK R-005)."),
    Capability("mcp", "MCP tool gateway",
               ("sentinel/domain/mcp.py", "sentinel/domain/mcp_estate.py", "sentinel/interface/mcp_proxy_routes.py"),
               ("test_mcp_attacks", "test_mcp_estate", "test_mcp_wire_proxy", "test_mcp_http_seam", "test_mcp_streaming"),
               ("test",),
               "Pinned tool definitions and drift detection. Shadow and unused servers are derived from the proxy's audit rows, which include refused calls to unenrolled servers; traffic that bypasses the proxy is invisible to it. With SENTINEL_MCP_PROXY_STREAMING (off by default) progress and log notifications are relayed incrementally on tools/call, each inspected before release and bounded per event, in total and in time; server-initiated requests (sampling, elicitation, roots) and the standalone GET stream are never relayed. Streaming has been exercised against scripted upstreams only, not a third-party MCP server."),
    Capability("siem", "SIEM export",
               ("sentinel/infrastructure/siem.py",),
               ("test_tenant_integrations", "test_connectors"),
               ("test",),
               "Syslog, OTLP and webhook sinks with per-tenant configuration. No named-vendor certification; no real tenant has consumed the export (RISK R-001)."),
    Capability("dr", "Backup, restore and point-in-time recovery",
               ("scripts/run_dr_postgres_wal_pitr_drill.py", "deploy/wal-archive/wal_s3.py"),
               ("test_dr_postgres_wal_pitr_drill", "test_persistence_backup_pitr", "test_cross_region_dr"),
               ("test",),
               "Local test and historical drill evidence does not establish independent failure-domain recovery (RISK R-003)."),
    Capability("deploy", "Deployment configuration and operational telemetry",
               ("Dockerfile", "deploy/helm/sentinel/Chart.yaml", "deploy/terraform/aws", "sentinel/infrastructure/trace_export.py"),
               ("test_helm_postgres_archive", "test_runtime_topology", "test_deployment_environment_is_canonical", "test_config_alignment", "test_trace_export", "test_observability_bounds"),
               ("docker", "kind-helm-smoke", "deployment-validation"),
               "Local chart/settings, OTLP HTTP and separately retained two-pod kind smoke evidence. The image moved to a minimal digest-pinned base and the local vulnerability gate reports no HIGH or CRITICAL findings; CI and a published, signed image have not confirmed it (RISK R-015). scripts/run_cloud_proof.py ran the whole deployed journey on an AWS EC2 host (ap-south-1, Ubuntu 24.04, k3s with containerd, flannel plus kube-router policy) and removed it; that is a real cloud host and a second Kubernetes distribution and network plugin, NOT the declared topology: no managed PostgreSQL or Redis, load balancer, object store, second node or IAM integration. Collector TLS, the Terraform topology and soak remain unverified. Actions held until 2026-10-02."),
    Capability("packaging", "Release hygiene",
               ("scripts/build_release_artifact.py", "scripts/scan_release_for_secrets.py",
                "scripts/smoke_clean_install.py", "requirements.lock"),
               ("test_release_packaging", "test_release_hygiene", "test_release_binding"),
               ("release-hygiene", "security"),
               "Allowlisted artifact contents, secret scan that never echoes, hash-pinned lock, clean-install smoke with a thin SDK. Image signing is opt-in and unverified until publishing is enabled."),
)


# ── Evidence readers ─────────────────────────────────────────────────────────


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True, check=False).stdout.strip()  # noqa: S603,S607


def _collected() -> tuple[Counter, Counter]:
    """(tests per module stem, postgres-parametrised tests per stem)."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "--no-header", "-p", "no:cacheprovider", "tests_arch"],
        cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode != 0:
        raise SystemExit("pytest collection failed; no readiness status generated")
    total: Counter = Counter()
    postgres: Counter = Counter()
    for line in result.stdout.splitlines():
        match = re.match(r"tests_arch/(test_[a-z0-9_]+)\.py::", line.strip())
        if not match:
            continue
        total[match.group(1)] += 1
        if "postgres" in line:
            postgres[match.group(1)] += 1
    return total, postgres


def _ci_jobs() -> set[str]:
    if not CI_WORKFLOW.exists():
        return set()
    jobs: set[str] = set()
    in_jobs = False
    for line in CI_WORKFLOW.read_text(encoding="utf-8").splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^  [a-zA-Z0-9_-]+:\s*$", line):
            jobs.add(line.strip().rstrip(":"))
    return jobs


def _bound_evidence(kind: str) -> dict[str, list[str]]:
    """Reserve production and independent tiers for a verified intake process."""
    # An unsigned local JSON plus a sidecar cannot establish a real tenant,
    # an independent assessor, or an observed production window. Keep these
    # tiers unverified until a reviewer-identity/attestation intake exists.
    return {}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tier(cap: Capability, *, total: Counter, postgres: Counter, jobs: set[str],
          production: dict[str, list[str]], external: dict[str, list[str]], executed: dict | None = None) -> tuple[str, dict]:
    present = [m for m in cap.modules if (ROOT / m).exists()]
    unit = sum(total.get(t, 0) for t in cap.tests)
    integration = sum(postgres.get(t, 0) for t in cap.tests)
    ci = [j for j in cap.ci_jobs if j in jobs]
    executed = executed or {}
    verified = [executed[t] for t in cap.tests if t in executed]
    passed = sum(c.get("passed", 0) for c in verified)
    pg_passed = sum(c.get("postgres_passed", 0) for c in verified)
    detail = {
        "tests_passed": passed,
        "postgres_tests_passed": pg_passed,
        "modules_present": present,
        "modules_missing": [m for m in cap.modules if m not in present],
        "tests_collected": unit,
        "tests_on_postgresql": integration,
        "ci_jobs": ci,
        "ci_jobs_missing": [j for j in cap.ci_jobs if j not in jobs],
        "production_evidence": production.get(cap.key, []),
        "external_evidence": external.get(cap.key, []),
    }
    if not present:
        return "not_implemented", detail
    tier = "implemented"
    if passed:
        tier = "unit_tested"
    if pg_passed:
        tier = "integration_tested"
    if tier == "integration_tested" and detail["production_evidence"]:
        tier = "production_observed"
    if tier == "production_observed" and detail["external_evidence"]:
        tier = "externally_verified"
    return tier, detail


# ── Risk register ────────────────────────────────────────────────────────────


def load_risks() -> dict:
    register = json.loads(RISKS.read_text(encoding="utf-8"))
    for risk in register["risks"]:
        for field in ("id", "title", "severity", "status", "owner", "description", "impact",
                      "mitigation", "closing_evidence", "review_by"):
            if not str(risk.get(field, "")).strip():
                raise SystemExit(f"risk {risk.get('id', '?')} lacks {field!r}; every risk names how it closes")
        if risk["status"] not in register["status_values"]:
            raise SystemExit(f"risk {risk['id']} has unknown status {risk['status']!r}")
        if risk["severity"] not in register["severity_scale"]:
            raise SystemExit(f"risk {risk['id']} has unknown severity {risk['severity']!r}")
    return register


def render_risks(register: dict, *, generated_at: str, commit: str) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    risks = sorted(register["risks"], key=lambda r: (order[r["severity"]], r["id"]))
    counts = Counter((r["severity"], r["status"]) for r in risks)
    lines = [
        "# Risk register",
        "",
        "**Generated by `scripts/build_current_status.py` from `RISK_REGISTER.json`. Edit the JSON.**",
        "",
        f"- commit: `{commit}`",
        f"- generated: {generated_at}",
        f"- risks: {len(risks)} ({', '.join(f'{k[0]}/{k[1]}: {v}' for k, v in sorted(counts.items()))})",
        "",
        "Severity: " + "; ".join(f"**{k}** = {v}" for k, v in register["severity_scale"].items()),
        "",
        "| id | severity | status | title | owner | closing evidence | review by |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in risks:
        lines.append(f"| {r['id']} | {r['severity']} | {r['status']} | {r['title']} | {r['owner']} | {r['closing_evidence']} | {r['review_by']} |")
    lines += ["", "## Detail", ""]
    for r in risks:
        lines += [f"### {r['id']} — {r['title']}", "",
                  f"- **Severity / likelihood / status:** {r['severity']} / {r.get('likelihood', 'n/a')} / {r['status']}",
                  f"- **Owner:** {r['owner']}",
                  f"- **Description:** {r['description']}",
                  f"- **Impact:** {r['impact']}",
                  f"- **Mitigation:** {r['mitigation']}",
                  f"- **Closes when:** {r['closing_evidence']}",
                  f"- **Review by:** {r['review_by']}", ""]
    return "\n".join(lines) + "\n"


# ── Status document ──────────────────────────────────────────────────────────


def build(artifacts: list[Path], evidence: list[Path] | None = None) -> dict:
    total, postgres = _collected()
    collected = sum(total.values())
    if collected < 100:
        raise SystemExit(f"pytest collected only {collected} tests; refusing to write a status that would understate every row")
    jobs = _ci_jobs()
    production = _bound_evidence("production")
    external = _bound_evidence("external")
    identity = release_identity_from_git(ROOT)
    dirty = bool(_git("status", "--porcelain"))
    inputs = test_identity()
    executed = {}
    accepted = []
    for path in evidence or []:
        result = read_verified(path, inputs)
        if not result:
            raise SystemExit(f"test evidence is invalid or belongs to different inputs: {path.name}")
        executed.update(result)
        accepted.append({"path": str(path), "sha256": _sha256(path)})
    rows = []
    for cap in CAPABILITIES:
        tier, detail = _tier(cap, total=total, postgres=postgres, jobs=jobs, production=production, external=external, executed=executed)
        rows.append({"key": cap.key, "name": cap.name, "tier": tier, "limits": cap.limits, **detail})
    tier_counts = Counter(r["tier"] for r in rows)
    return {
        "schema": "sentinel.release-status/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs_identity": inputs,
        "accepted_test_evidence": accepted,
        "commit": identity.commit,
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "working_tree_dirty": dirty,
        "source_tree_sha256": identity.source_tree_sha256,
        "tests_collected": collected,
        "tests_on_postgresql": sum(postgres.values()),
        "ci_jobs": sorted(jobs),
        "artifacts": [{"path": str(a), "sha256": _sha256(a), "size_bytes": a.stat().st_size} for a in artifacts],
        "tiers": TIERS,
        "tier_counts": {t: tier_counts.get(t, 0) for t in ("not_implemented", *TIERS)},
        "capabilities": rows,
        "external_gates_unverified": [
            "independent security assessment (RISK R-002)",
            "production observation by a real tenant (RISK R-001)",
            "independent-failure-domain disaster recovery (RISK R-003)",
            "applied cloud environment (RISK R-004)",
            "blind detection evaluation (RISK R-005)",
        ],
        "claims_not_made": ["production-ready", "market-leading", "compliant", "secure", "superior to a named competitor"],
    }


def render(status: dict) -> str:
    dirty = " (DIRTY working tree: this snapshot describes uncommitted changes)" if status["working_tree_dirty"] else ""
    lines = [
        "# Release status",
        "",
        "**Generated by `scripts/build_current_status.py`. Do not edit by hand.** This snapshot binds the listed evidence to its recorded inputs and artifacts. Local results are not CI, production or independent-assessment evidence.",
        "",
        f"- commit: `{status['commit']}` on `{status['branch']}`{dirty}",
        f"- legacy Python-source sha256: `{status['source_tree_sha256']}`",
        f"- release inputs sha256 (code, tests, policy, packages, deployment): `{status['inputs_identity']['inputs_sha256']}`",
        f"- accepted test reports: {len(status['accepted_test_evidence'])}; collected counts alone grant no tier",
        f"- generated: {status['generated_at']}",
        f"- tests collected: **{status['tests_collected']}** ({status['tests_on_postgresql']} parametrised on PostgreSQL)",
        "",
        "## What this document will not say",
        "",
        "It will not say " + ", ".join(f"*{c}*" for c in status["claims_not_made"]) + ". Each of those needs evidence that does not exist in this repository at this commit. The tiers below are the evidence that does.",
        "",
        "## Evidence tiers",
        "",
        "| Tier | Means | Evidence source |",
        "|---|---|---|",
        "| implemented | the modules exist | file on disk |",
        "| unit_tested | mapped tests executed successfully on these exact inputs | verified JSON + JUnit digest from `current_test_evidence.py` |",
        "| integration_tested | mapped PostgreSQL cases executed and passed on these inputs | verified JSON + JUnit outcomes; does not certify a deployment |",
        "| production_observed | verified real-tenant observation | unverified; unsigned sidecars do not qualify |",
        "| externally_verified | verified independent assessment | unverified; assessor identity and attestation intake required |",
        "",
        "| Tier | Capabilities |",
        "|---|---:|",
    ]
    for tier, count in status["tier_counts"].items():
        lines.append(f"| {tier} | {count} |")
    lines += ["", "## Capabilities", "",
              "| Capability | Tier | Collected (PG) | Passed (PG) | CI jobs configured | Limits |", "|---|---|---|---|---|---|"]
    for row in status["capabilities"]:
        missing = f" — missing: {', '.join(row['modules_missing'])}" if row["modules_missing"] else ""
        ci = ", ".join(row["ci_jobs"]) or "none"
        if row["ci_jobs_missing"]:
            ci += f" (not in ci.yml: {', '.join(row['ci_jobs_missing'])})"
        lines.append(f"| **{row['name']}**{missing} | {row['tier']} | {row['tests_collected']} ({row['tests_on_postgresql']}) | {row['tests_passed']} ({row['postgres_tests_passed']}) | {ci} | {row['limits']} |")
    lines += ["", "## External gates with no evidence at this commit", ""]
    lines += [f"- {g}" for g in status["external_gates_unverified"]]
    lines += ["", "## Artifacts this status was generated against", ""]
    if status["artifacts"]:
        lines += ["| Artifact | sha256 | bytes |", "|---|---|---:|"]
        lines += [f"| `{a['path']}` | `{a['sha256']}` | {a['size_bytes']} |" for a in status["artifacts"]]
    else:
        lines.append("None were passed. Run with `--artifact dist/<wheel>` in the release job to bind the status to what shipped.")
    lines += ["", "## Historical documents", "",
              "Everything under `docs/` outside `docs/current/` predates this status and is not bound to a commit. Treat it as history: useful for why a decision was made, not for what is true now. `docs/current/README.md` lists what is current.", ""]
    return "\n".join(lines)


def _check_claims(text: str, where: str) -> None:
    lowered = text.lower()
    for claim in FORBIDDEN_CLAIMS:
        for match in re.finditer(re.escape(claim), lowered):
            window = lowered[max(0, match.start() - 60): match.start()]
            if "not " in window or "will not say" in window or "*" == lowered[match.start() - 1: match.start()]:
                continue
            raise SystemExit(f"{where} asserts {claim!r}; that claim needs evidence this program did not create")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--artifact", action="append", default=[], type=Path)
    parser.add_argument("--out", type=Path, default=CURRENT)
    parser.add_argument("--test-evidence", action="append", default=[], type=Path)
    args = parser.parse_args(argv)

    status = build([a.resolve() for a in args.artifact], args.test_evidence)
    register = load_risks()
    status_md = render(status)
    risks_md = render_risks(register, generated_at=status["generated_at"], commit=status["commit"])
    _check_claims(status_md, "RELEASE_STATUS.md")
    _check_claims(risks_md, "RISK_REGISTER.md")

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "RELEASE_STATUS.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    (args.out / "RELEASE_STATUS.md").write_text(status_md, encoding="utf-8")
    (args.out / "RISK_REGISTER.md").write_text(risks_md, encoding="utf-8")
    print(f"commit {status['commit'][:12]} dirty={status['working_tree_dirty']} tests={status['tests_collected']} tiers={status['tier_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
