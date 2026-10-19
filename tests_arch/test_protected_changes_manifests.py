"""The bypass-prevention manifests say what the adapter does, and fail closed.

These are structural checks: a CEL expression is evaluated by the API server,
not here, and the live behaviour is exercised by `scripts/run_local_kind_smoke.py`
against a real cluster. What can be held fixed without one is that the policy
cannot be weakened quietly and that its stamp format is the adapter's.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from sentinel.infrastructure.platforms.kubernetes_outcome import field_manager

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "deploy" / "protected-changes"


def _documents(name: str) -> list[dict]:
    return [d for d in yaml.safe_load_all((DIR / name).read_text(encoding="utf-8")) if d]


def _one(documents: list[dict], kind: str, name: str = "") -> dict:
    found = [d for d in documents if d["kind"] == kind and (not name or d["metadata"]["name"] == name)]
    assert len(found) == 1, f"expected one {kind} {name}, found {len(found)}"
    return found[0]


def test_the_policy_fails_closed_and_denies():
    documents = _documents("admission-policy.yaml")
    policy = _one(documents, "ValidatingAdmissionPolicy")
    binding = _one(documents, "ValidatingAdmissionPolicyBinding")
    assert policy["spec"]["failurePolicy"] == "Fail"
    assert "Deny" in binding["spec"]["validationActions"]
    assert binding["spec"]["paramRef"]["parameterNotFoundAction"] == "Deny"
    rules = policy["spec"]["matchConstraints"]["resourceRules"][0]
    assert set(rules["operations"]) == {"CREATE", "UPDATE", "DELETE"}
    assert rules["resources"] == ["*"] and rules["apiGroups"] == ["*"]


def test_the_stamp_the_policy_requires_is_the_stamp_the_adapter_sends():
    policy = _one(_documents("admission-policy.yaml"), "ValidatingAdmissionPolicy")
    expressions = " ".join(v["expression"] for v in policy["spec"]["validations"])
    pattern = re.search(r"matches\('([^']+)'\)", expressions)
    assert pattern, "the executor rule no longer checks the field manager"
    for operation_id in ("op-auth-abc", "op-" + "x" * 300):
        assert re.fullmatch(pattern.group(1), field_manager(operation_id)), (
            "the adapter's field manager would be refused by its own admission policy"
        )
    assert not re.fullmatch(pattern.group(1), "kubectl-client-side-apply")


def test_agents_are_refused_by_namespace_and_the_executor_is_named_once():
    documents = _documents("admission-policy.yaml")
    params = _one(documents, "ConfigMap")["data"]
    policy = _one(documents, "ValidatingAdmissionPolicy")
    text = " ".join(v["expression"] for v in policy["spec"]["validations"])
    assert "variables.callerNamespace in variables.agentNamespaces" in text
    assert "params.data.executorUsername" in text
    executor = params["executorUsername"]
    assert executor.startswith("system:serviceaccount:")
    assert executor.split(":")[2] not in params["agentNamespaces"].split(","), (
        "the executor lives in an agent namespace; rule 1 would refuse every protected change"
    )


def test_the_broker_can_only_mint_tokens_for_the_executor():
    documents = _documents("rbac.yaml")
    role = _one(documents, "Role", "sentinel-mint-executor-tokens")
    assert role["rules"] == [{
        "apiGroups": [""], "resources": ["serviceaccounts/token"],
        "resourceNames": ["sentinel-executor"], "verbs": ["create"],
    }]
    bound_to_broker = [
        d["roleRef"]["name"] for d in documents if d["kind"] in {"RoleBinding", "ClusterRoleBinding"}
        and any(s.get("name") == "sentinel-broker" for s in d["subjects"])
    ]
    assert bound_to_broker == ["sentinel-mint-executor-tokens"], "the broker holds a right beyond minting"


def test_agents_hold_no_write_verb_and_the_executor_no_wildcard():
    documents = _documents("rbac.yaml")
    agents = _one(documents, "Role", "agents-read-only")
    assert {v for r in agents["rules"] for v in r["verbs"]} <= {"get", "list", "watch"}
    executor = _one(documents, "Role", "sentinel-protected-change")
    for rule in executor["rules"]:
        assert "*" not in rule["resources"] + rule["verbs"] + rule["apiGroups"]
    account = _one(documents, "ServiceAccount", "sentinel-executor")
    assert account["automountServiceAccountToken"] is False, "the executor must never run as a pod identity"


def test_an_executor_delete_needs_the_mark_the_adapter_writes():
    from sentinel.infrastructure.platforms.kubernetes_outcome import DELETE_MARK

    policy = _one(_documents("admission-policy.yaml"), "ValidatingAdmissionPolicy")
    variables = {v["name"]: v["expression"] for v in policy["spec"]["variables"]}
    assert DELETE_MARK in variables["deleteMark"] and "oldObject" in variables["deleteMark"]
    rule = " ".join(v["expression"] for v in policy["spec"]["validations"])
    assert "request.operation == 'DELETE' ? variables.deleteMark : variables.fieldManager" in rule

