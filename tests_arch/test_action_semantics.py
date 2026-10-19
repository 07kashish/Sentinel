"""Semantic classification of platform actions, and its seam into policy.

Two layers under test. The DOMAIN layer (`classify_action`) must read each
platform's own verb grammar correctly — `iam:AttachUserPolicy` is privilege
escalation, `iam:ListUsers` is inventory, and nothing outside the recognised
grammars gets a label at all. The SEAM (`DeterministicPolicy.evaluate`) must
see the classification as an ordinary matchable field, and must NOT see one a
caller asserted — `metadata.semantics` is an input to policy, so the caller
writing it would be the caller pre-classifying its own actions.
"""

from __future__ import annotations

import pytest

from sentinel.domain.action_semantics import classify_action, enrich_payload
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DEFAULT_POLICY_PATH, DeterministicPolicy


def _payload(action: str, resource: str = "", **metadata) -> dict:
    return {
        "eventType": "tool_call",
        "action": action,
        "resource": resource,
        "agentId": "agent-1",
        "metadata": metadata,
    }


# ── AWS: the action grammar is canonical, so exactness is cheap ──────────────


@pytest.mark.parametrize(
    ("action", "category", "tier"),
    [
        ("iam:CreateAccessKey", "credential", "critical"),
        ("iam:AttachUserPolicy", "privilege", "critical"),
        ("secretsmanager:GetSecretValue", "credential", "critical"),
        ("cloudtrail:StopLogging", "destructive", "critical"),
        ("s3:PutBucketPolicy", "privilege", "critical"),
        ("ec2:TerminateInstances", "destructive", "high"),
        ("s3:PutObject", "write", "moderate"),
        ("s3:GetObject", "read", "low"),
        ("iam:ListUsers", "read", "low"),
    ],
)
def test_aws_actions_are_read_by_their_own_grammar(action, category, tier):
    semantics = classify_action(_payload(action))
    assert semantics is not None, action
    assert semantics.platform == "aws"
    assert (semantics.category, semantics.tier) == (category, tier), (
        f"{action}: {semantics}"
    )


# ── Kubernetes: exec is not logs, RBAC writes are not deployments ────────────


@pytest.mark.parametrize(
    ("action", "resource", "category", "tier"),
    [
        ("kubectl exec -it payments -- /bin/sh", "", "execution", "critical"),
        ("kubectl get secrets -n prod", "", "credential", "high"),
        ("kubectl apply", "clusterrolebinding admin-binding", "privilege", "critical"),
        ("kubectl delete deployment payments -n prod", "", "destructive", "high"),
        ("kubectl delete pod kube-proxy -n kube-system", "", "destructive", "critical"),
        ("kubectl get pods -n prod", "", "read", "low"),
        ("kubectl apply", "deployment payments", "write", "moderate"),
    ],
)
def test_kubernetes_verbs_and_kinds_are_distinguished(action, resource, category, tier):
    semantics = classify_action(_payload(action, resource))
    assert semantics is not None, action
    assert semantics.platform == "kubernetes"
    assert (semantics.category, semantics.tier) == (category, tier), (
        f"{action}: {semantics}"
    )


def test_a_bare_english_verb_is_not_a_kubernetes_call():
    """`list` with no kind anywhere must classify as nothing, not as k8s."""
    assert classify_action(_payload("list", "the quarterly report")) is None


# ── GitHub: reading an issue is not rewriting branch protection ──────────────


@pytest.mark.parametrize(
    ("action", "resource", "category", "tier"),
    [
        ("delete", "https://api.github.com/repos/acme/api", "destructive", "critical"),
        (
            "put",
            "https://api.github.com/repos/acme/api/branches/main/protection",
            "privilege",
            "critical",
        ),
        (
            "put",
            "https://api.github.com/repos/acme/api/actions/secrets/DEPLOY_KEY",
            "credential",
            "critical",
        ),
        (
            "put",
            "https://api.github.com/repos/acme/api/pulls/12/merge",
            "write",
            "high",
        ),
        ("get", "https://api.github.com/repos/acme/api/issues/7", "read", "low"),
        ("merge_pull_request", "github.com/acme/api", "write", "high"),
        ("update_branch_protection", "github.com/acme/api", "privilege", "critical"),
        ("create_issue", "github.com/acme/api", "write", "low"),
    ],
)
def test_github_operations_are_distinguished(action, resource, category, tier):
    semantics = classify_action(_payload(action, resource))
    assert semantics is not None, action
    assert semantics.platform == "github"
    assert (semantics.category, semantics.tier) == (category, tier), (
        f"{action}: {semantics}"
    )


def test_a_content_write_into_workflows_is_ci_code_not_content():
    semantics = classify_action(
        _payload(
            "create_or_update_file",
            "github.com/acme/api",
            path=".github/workflows/deploy.yml",
        )
    )
    assert semantics is not None
    assert (semantics.category, semantics.tier) == ("privilege", "critical")


def test_a_bare_tool_name_without_github_context_is_not_classified():
    """`delete_file` could belong to anything; without github in sight, no label."""
    assert classify_action(_payload("delete_file", "reports/q3.txt")) is None


# ── SQL: DROP is not SELECT, and an unbounded UPDATE is its own thing ────────


@pytest.mark.parametrize(
    ("statement", "category", "tier"),
    [
        ("SELECT * FROM customers WHERE id = 4", "read", "low"),
        ("DROP TABLE customers", "destructive", "critical"),
        ("GRANT ALL ON customers TO intern", "privilege", "critical"),
        ("CREATE USER backdoor WITH PASSWORD 'x'", "privilege", "critical"),
        ("UPDATE customers SET tier = 'gold' WHERE id = 4", "write", "moderate"),
        ("DELETE FROM customers", "write", "high"),
        ("COPY customers TO '/tmp/dump.csv'", "export", "high"),
        ("ALTER TABLE customers DROP COLUMN ssn", "destructive", "high"),
    ],
)
def test_sql_statements_are_classified_by_consequence(statement, category, tier):
    semantics = classify_action(_payload(statement))
    assert semantics is not None, statement
    assert semantics.platform == "sql"
    assert (semantics.category, semantics.tier) == (category, tier), (
        f"{statement}: {semantics}"
    )


def test_a_smuggled_second_statement_raises_the_tier():
    semantics = classify_action(
        _payload("SELECT 1; DROP TABLE customers")
    )
    assert semantics is not None
    assert semantics.tier in {"high", "critical"}
    assert any("multiple statements" in r for r in semantics.reasons)


def test_sql_in_metadata_query_is_found_when_action_is_generic():
    semantics = classify_action(
        _payload("db_query", query="DROP TABLE customers")
    )
    assert semantics is not None
    assert semantics.operation == "DROP"


def test_sql_in_arguments_is_found_when_action_is_generic():
    payload = _payload("query")
    payload["arguments"] = {"sql": "DROP TABLE users"}

    semantics = classify_action(payload)

    assert semantics is not None
    assert semantics.operation == "DROP"


@pytest.mark.parametrize(
    ("action", "arguments", "resource", "operation", "tier"),
    [
        ("delete_namespace", {}, "prod", "delete namespace", "high"),
        ("k8s.delete.secret", {}, "prod/api-token", "delete secret", "high"),
        ("kubectl delete ns prod", {}, "", "delete namespace", "high"),
        ("patch", {"kind": "daemonset", "resource": "node-agent"}, "", "patch daemonset", "moderate"),
    ],
)
def test_kubernetes_kind_can_come_from_action_or_arguments(
    action, arguments, resource, operation, tier
):
    payload = _payload(action, resource)
    payload["tool"] = "kubernetes_api"
    payload["arguments"] = arguments

    semantics = classify_action(payload)

    assert semantics is not None
    assert semantics.platform == "kubernetes"
    assert semantics.operation == operation
    assert semantics.tier == tier


# ── The seam: enrichment feeds policy, and only enrichment can ───────────────


def test_enrichment_discards_a_caller_asserted_classification():
    """The caller pre-labelling itself `low` must be overwritten; a label on an
    unclassifiable action must be removed, not echoed."""
    relabelled = enrich_payload(
        _payload("iam:AttachUserPolicy", semantics={"tier": "low"})
    )
    assert relabelled["metadata"]["semantics"]["tier"] == "critical"

    echoed = enrich_payload(
        _payload("just some words", semantics={"tier": "critical"})
    )
    assert "semantics" not in echoed["metadata"], (
        "a caller-asserted label survived on an action nothing classified"
    )


def test_the_policy_engine_fires_on_the_derived_tier():
    policy = DeterministicPolicy.from_file(DEFAULT_POLICY_PATH)
    verdict = policy.evaluate(
        payload=_payload("iam:AttachUserPolicy", "arn:aws:iam::1:user/agent"),
        trust=TrustLevel.VERIFIED,
    )
    assert verdict.fired, "the critical-tier rule never saw the enrichment"
    assert "critical-platform-operation" in verdict.matched_rules
    assert int(verdict.severity.value) >= 85


def test_a_benign_read_does_not_fire_the_platform_rules():
    policy = DeterministicPolicy.from_file(DEFAULT_POLICY_PATH)
    verdict = policy.evaluate(
        payload=_payload("s3:GetObject", "arn:aws:s3:::reports/q3.pdf"),
        trust=TrustLevel.VERIFIED,
    )
    fired = set(verdict.matched_rules)
    assert "critical-platform-operation" not in fired
    assert "high-impact-platform-operation" not in fired


def test_a_caller_cannot_reach_the_rule_by_asserting_the_field():
    """End to end: the engine must enrich (and therefore strip) before matching."""
    policy = DeterministicPolicy.from_file(DEFAULT_POLICY_PATH)
    verdict = policy.evaluate(
        payload=_payload(
            "read the quarterly report", semantics={"tier": "critical"}
        ),
        trust=TrustLevel.VERIFIED,
    )
    assert "critical-platform-operation" not in set(verdict.matched_rules), (
        "a caller-asserted semantics label reached the policy engine"
    )
