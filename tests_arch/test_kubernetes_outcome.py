"""Constrained credentials, target correlation and automatic reconciliation.

A fake API server stands in for the cluster so every boundary can be cut: the
token request refused, the mutation rejected, the response lost after the
write landed, the process dying before the outcome is recorded. The properties:

  * the broker token is presented ONLY to the TokenRequest endpoint;
  * a definitive 4xx is a FAILED operation, never an unknown one;
  * a lost response is unknown, and the reconciler settles it from the target;
  * reconciliation never writes, never guesses, and gives up after a bound.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.application.operation_context import operation_scope
from sentinel.application.protect_gate import ProtectGate
from sentinel.application.reconciliation import OperationReconciler, ReconcileVerdict
from sentinel.application.tool_proxy import InlineToolProxy
from sentinel.application.tool_runner import ProtectedToolRunner
from sentinel.domain.execution_binding import issue_authorization
from sentinel.domain.operations import OperationState, OutcomeUnknown
from sentinel.domain.primitives import TrustLevel
from sentinel.infrastructure.detection import DeterministicPolicy
from sentinel.infrastructure.platforms.kubernetes import KubernetesCredentials, kubernetes_api_adapter
from sentinel.infrastructure.platforms.kubernetes_outcome import field_manager, kubernetes_hint
from sentinel.infrastructure.sql.nonce_ledger import SqlNonceLedger
from sentinel.infrastructure.sql.operation_store import SqlOperationStore
from sentinel.infrastructure.sql.protect_controls_store import SqlProtectControls
from sentinel.infrastructure.tool_adapters import ToolAdapterNotAttempted, ToolAdapterRejectedByTarget
from tests_arch.doubles import FakeClock

NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
TENANT = "acme"
SERVER = "https://k8s.internal.example"
BROKER = "broker-token-value"
MINTED = "minted-token-value"
UID = "0f4c1d1e-1111-4222-8333-444455556666"


@dataclass
class _Response:
    status: int
    body: bytes
    headers: dict = field(default_factory=dict)
    peer: str = "10.0.0.1:443"


class FakeCluster:
    """One configmap, a TokenRequest endpoint, and switches for each failure."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []  # (method, path, bearer)
        self.object: dict | None = {"metadata": {"name": "app", "namespace": "prod", "uid": UID,
                                                 "resourceVersion": "41", "managedFields": []}}
        self.token_status = 201
        self.mutation_status: int | None = None   # force a status for the mutation
        self.lose_response_after_write = False

    def request(self, *, method, url, headers, body, idempotent):
        path = url[len(SERVER):]
        bearer = headers.get("authorization", "").removeprefix("Bearer ")
        self.calls.append((method, path, bearer))
        if path.endswith("/serviceaccounts/executor/token"):
            payload = {"status": {"token": MINTED, "expirationTimestamp": "2026-09-19T12:10:00Z"}}
            return _Response(self.token_status, json.dumps(payload if self.token_status < 300 else {}).encode())
        if method == "GET":
            return _Response(200, json.dumps(self.object).encode()) if self.object else _Response(404, b"{}")
        if self.mutation_status is not None:
            return _Response(self.mutation_status, b"{}")
        manager = path.partition("fieldManager=")[2]
        if method == "PUT":
            sent = json.loads(body)
            if sent["metadata"]["resourceVersion"] != self.object["metadata"]["resourceVersion"]:
                return _Response(409, b"{}")
            self.object["metadata"]["resourceVersion"] = "42"
            self.object["metadata"]["managedFields"] = [{"manager": manager}]
            self.object["metadata"]["annotations"] = sent["metadata"].get("annotations") or {}
            if self.lose_response_after_write:
                raise ConnectionResetError("response lost")
            return _Response(200, json.dumps(self.object).encode())
        elif method == "DELETE":
            wanted = (json.loads(body or b"{}").get("preconditions") or {}).get("resourceVersion")
            if self.object is None or wanted != self.object["metadata"]["resourceVersion"]:
                return _Response(409, b"{}")
            self.deleted_with_mark = (self.object["metadata"].get("annotations") or {}).get("sentinel.io/delete-operation")
            self.object = None
        if self.lose_response_after_write:
            raise ConnectionResetError("response lost")
        return _Response(200, b"{}")


def _adapter(cluster: FakeCluster, *, brokered: bool = True):
    credentials = KubernetesCredentials(
        api_server=SERVER, token=BROKER,
        executor_service_account="executor" if brokered else "",
        executor_namespace="sentinel" if brokered else "",
        token_audience="https://kubernetes.default.svc" if brokered else "",
    )
    return kubernetes_api_adapter(client=cluster, credentials=credentials, ceiling="high")


def _update(version: str = "41") -> dict:
    return {"verb": "update", "kind": "configmap", "namespace": "prod", "name": "app",
            "body": {"metadata": {"name": "app", "namespace": "prod", "uid": UID, "resourceVersion": version},
                     "data": {"flag": "on"}}}


# ── Constrained credentials ──────────────────────────────────────────────────


def test_the_broker_token_only_ever_reaches_the_token_request_endpoint():
    cluster = FakeCluster()
    result = _adapter(cluster).runner(_update())
    assert result["credential"]["mode"] == "token_request"
    assert result["credential"]["service_account"] == "sentinel/executor"
    assert MINTED not in json.dumps(result) and BROKER not in json.dumps(result)
    for method, path, bearer in cluster.calls:
        if path.endswith("/token"):
            assert bearer == BROKER
        else:
            assert bearer == MINTED, f"{method} {path} was sent with the broker credential"


def test_a_refused_token_request_means_nothing_was_attempted():
    cluster = FakeCluster()
    cluster.token_status = 403
    with pytest.raises(ToolAdapterNotAttempted):
        _adapter(cluster).runner(_update())
    assert [c for c in cluster.calls if c[0] != "POST"] == [], "a mutation was sent without a credential"


def test_a_static_token_still_works_and_says_so():
    cluster = FakeCluster()
    assert _adapter(cluster, brokered=False).runner(_update())["credential"] == {"mode": "static"}


@pytest.mark.parametrize("kwargs", [
    {"executor_service_account": "executor"},
    {"executor_service_account": "executor", "executor_namespace": "sentinel", "token_ttl_seconds": 60},
    {"executor_service_account": "Bad_Name", "executor_namespace": "sentinel"},
])
def test_malformed_executor_settings_are_refused(kwargs):
    with pytest.raises(Exception):
        KubernetesCredentials(api_server=SERVER, token=BROKER, **kwargs)


# ── Known absent versus unknown ──────────────────────────────────────────────


def test_a_conflict_with_the_approved_version_is_a_definitive_rejection():
    cluster = FakeCluster()
    with pytest.raises(ToolAdapterRejectedByTarget):
        _adapter(cluster).runner(_update(version="40"))
    assert cluster.object["metadata"]["resourceVersion"] == "41"


def test_the_operation_is_stamped_on_the_target_without_touching_the_body():
    cluster = FakeCluster()
    with operation_scope("op-auth-1"):
        _adapter(cluster).runner(_update())
    assert cluster.object["metadata"]["managedFields"] == [{"manager": field_manager("op-auth-1")}]
    assert len(field_manager("op-" + "x" * 500)) < 128


def test_the_hint_carries_identifiers_and_never_the_body():
    hint = kubernetes_hint(_update())
    assert hint == {"verb": "update", "kind": "configmap", "namespace": "prod", "name": "app",
                    "uid": UID, "resourceVersion": "41"}
    assert kubernetes_hint({"verb": "get", "kind": "configmap"}) == {}


def _delete(version: str = "41") -> dict:
    return {"verb": "delete", "kind": "configmap", "namespace": "prod", "name": "app",
            "body": {"preconditions": {"uid": UID, "resourceVersion": version}}}


def test_a_protected_delete_marks_the_approved_version_then_deletes_exactly_that():
    cluster = FakeCluster()
    with operation_scope("op-auth-del"):
        _adapter(cluster).runner(_delete())
    assert cluster.object is None
    assert cluster.deleted_with_mark == field_manager("op-auth-del")
    methods = [method for method, path, _ in cluster.calls if not path.endswith("/token")]
    assert methods == ["GET", "PUT", "DELETE"]


def test_a_protected_delete_of_a_changed_object_deletes_nothing():
    cluster = FakeCluster()
    with operation_scope("op-auth-del"), pytest.raises(ToolAdapterRejectedByTarget):
        _adapter(cluster).runner(_delete(version="40"))
    assert cluster.object is not None
    assert [m for m, _, _ in cluster.calls if m in {"PUT", "DELETE"}] == [], "a stale approval wrote to the target"


def test_an_unbrokered_delete_is_a_single_call_as_before():
    cluster = FakeCluster()
    with operation_scope("op-auth-del"):
        _adapter(cluster, brokered=False).runner(_delete())
    assert [m for m, _, _ in cluster.calls] == ["DELETE"]


# ── End to end: lost response, then the target answers ───────────────────────


def _proxy(pool, cluster, clock):
    runner = ProtectedToolRunner(
        gate=ProtectGate(policy=DeterministicPolicy.default(), enforce=True),
        controls=SqlProtectControls(pool=pool, clock=clock), clock=clock,
        operations=SqlOperationStore(pool=pool),
    )
    proxy = InlineToolProxy(tool_runner=runner)
    proxy.register(_adapter(cluster))
    return proxy


def _execute(proxy, pool, args, auth_id="auth-1"):
    authorization = issue_authorization(
        authorization_id=auth_id, nonce=f"nonce-{auth_id}", tenant_id=TENANT, actor_identity="key:test",
        agent_identity="agent-1", tool_identity="kubernetes_api", action="kubernetes_api",
        target_resource="configmaps/prod/app", parameters=args, now=NOW, policy_decision="allow",
    )
    return proxy.execute(
        agent_id="agent-1", tool="kubernetes_api", arguments=args, trust=TrustLevel.VERIFIED,
        resource="configmaps/prod/app", authorization=authorization,
        nonces=SqlNonceLedger(pool=pool), now=NOW, tenant_id=TENANT,
    )


def _reconciler(pool, proxy, **kwargs):
    return OperationReconciler(store=SqlOperationStore(pool=pool), reconcilers=proxy.reconciler_for, **kwargs)


def test_a_lost_response_is_settled_as_succeeded_from_the_target(migrated_pool):
    cluster, clock = FakeCluster(), FakeClock(NOW)
    cluster.lose_response_after_write = True
    proxy = _proxy(migrated_pool, cluster, clock)
    with pytest.raises(OutcomeUnknown) as caught:
        _execute(proxy, migrated_pool, _update())
    store = SqlOperationStore(pool=migrated_pool)
    op = store.get(TENANT, caught.value.operation_id)
    assert op.state is OperationState.UNKNOWN_AFTER_EFFECT
    assert op.attributes["reconcile_hint"]["resourceVersion"] == "41"
    assert "flag" not in json.dumps(op.attributes), "the approved body leaked into the intent"

    writes_before = [c for c in cluster.calls if c[0] in {"PUT", "DELETE"}]
    totals = _reconciler(migrated_pool, proxy).run(TENANT, now=NOW + timedelta(seconds=5))
    assert totals["succeeded"] == 1
    assert [c for c in cluster.calls if c[0] in {"PUT", "DELETE"}] == writes_before, "reconciliation wrote to the target"
    settled = store.get(TENANT, op.operation_id)
    assert settled.state is OperationState.SUCCEEDED
    assert settled.reconciled_by == "reconciler:kubernetes_api" and "field manager" in settled.reconciliation_note


def test_a_server_error_is_unknown_then_failed_only_after_quiescence(migrated_pool):
    cluster, clock = FakeCluster(), FakeClock(NOW)
    cluster.mutation_status = 503
    proxy = _proxy(migrated_pool, cluster, clock)
    with pytest.raises(OutcomeUnknown) as caught:
        _execute(proxy, migrated_pool, _update())
    store = SqlOperationStore(pool=migrated_pool)
    reconciler = _reconciler(migrated_pool, proxy)
    early = reconciler.run(TENANT, now=NOW + timedelta(seconds=10))
    assert early["failed"] == 0 and early["still_unknown"] == 1, "failed was accepted while a write could be in flight"
    late = reconciler.run(TENANT, now=NOW + timedelta(seconds=300))
    assert late["failed"] == 1
    assert "did not land" in store.get(TENANT, caught.value.operation_id).reconciliation_note


def test_a_rejection_by_the_target_is_a_failed_operation_not_an_unknown(migrated_pool):
    cluster, clock = FakeCluster(), FakeClock(NOW)
    proxy = _proxy(migrated_pool, cluster, clock)
    with pytest.raises(Exception) as caught:
        _execute(proxy, migrated_pool, _update(version="40"))
    assert not isinstance(caught.value, OutcomeUnknown)
    ops = SqlOperationStore(pool=migrated_pool).list(TENANT)
    assert [o.state for o in ops] == [OperationState.FAILED]


def test_an_unattributable_change_stays_unknown_and_is_bounded(migrated_pool):
    cluster, clock = FakeCluster(), FakeClock(NOW)
    cluster.mutation_status = 503
    proxy = _proxy(migrated_pool, cluster, clock)
    with pytest.raises(OutcomeUnknown) as caught:
        _execute(proxy, migrated_pool, _update())
    cluster.object["metadata"]["resourceVersion"] = "99"          # someone else wrote
    cluster.object["metadata"]["managedFields"] = [{"manager": "kubectl"}]
    reconciler = _reconciler(migrated_pool, proxy, max_attempts=2)
    for minute in (10, 20):
        assert reconciler.run(TENANT, now=NOW + timedelta(minutes=minute))["still_unknown"] == 1
    assert reconciler.run(TENANT, now=NOW + timedelta(minutes=30))["exhausted"] == 1
    op = SqlOperationStore(pool=migrated_pool).get(TENANT, caught.value.operation_id)
    assert op.state is OperationState.UNKNOWN_AFTER_EFFECT and op.attributes["reconcile_attempts"] == 2


def test_a_verdict_needs_evidence_and_a_legal_state():
    with pytest.raises(ValueError):
        ReconcileVerdict(OperationState.SUCCEEDED, " ")
    with pytest.raises(ValueError):
        ReconcileVerdict(OperationState.PENDING, "x")
