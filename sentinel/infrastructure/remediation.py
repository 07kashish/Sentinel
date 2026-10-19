"""Executing remediation against real systems, with the six required properties.

    Every action must support:
    dry run / authorization / audit / idempotency / rollback where possible /
    failure handling

WHY THOSE SIX LIVE IN A WRAPPER AND NOT IN EACH INTEGRATION
-------------------------------------------------------------
There are fourteen actions across six providers. Implementing dry run,
authorization, audit and idempotency inside each one means writing them
fourteen times, and the thirteenth will differ from the first in some small way
that nobody notices until an auditor asks why one action has no audit row.

`GuardedRemediationExecutor` implements all six once and wraps whatever actually
talks to AWS, Kubernetes or GitHub. An integration is then responsible for
exactly one thing: making the call and reporting what happened. Adding a
provider cannot forget an audit row, because the provider never had the
opportunity to write one.

THE DEFECT THIS IS SHAPED AGAINST, RESTATED
---------------------------------------------
`executors.py` records it: the predecessor returned `status="simulated",
executed=false` from what looked like a success path, "which reads as success to
any caller that only checks for an exception".

Dry run reintroduces exactly that risk, because a dry run IS a successful call
that did nothing. So `executed` and `dry_run` are separate fields on the
receipt, `executed` is False whenever nothing happened, and the tests assert a
dry-run receipt can never be mistaken for a real one. A receipt that says
`executed: true` means a real system changed.

AN UNCONFIGURED INTEGRATION REFUSES, IT DOES NOT PRETEND
----------------------------------------------------------
The same principle as `NullRemediationExecutor`. If a tenant has no AWS
credentials wired, `revoke_cloud_session` is unsupported and says so. It does
not quietly succeed, and it does not quietly dry-run -- a dry run nobody asked
for is a failed remediation that reports success.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, MutableMapping, Protocol, runtime_checkable

from sentinel.domain.errors import DomainRuleViolated, TransientFailure
from sentinel.infrastructure.executors import NullRemediationExecutor
from sentinel.domain.primitives import IdempotencyKey
from sentinel.domain.remediation import (
    RemediationAction,
    UnknownRemediationAction,
    action_named,
    rollback_for,
)

__all__ = [
    "ActionAuthorizer",
    "AllowListAuthorizer",
    "ApprovalPathAuthorizer",
    "build_remediation_executor",
    "GuardedRemediationExecutor",
    "HttpRemediationIntegration",
    "IdempotencyStore",
    "InMemoryIdempotencyStore",
    "RemediationIntegration",
    "RemediationAuditFailed",
    "RemediationReceipt",
    "SqlRemediationIdempotencyStore",
    "RemediationUnauthorized",
]


class RemediationUnauthorized(DomainRuleViolated):
    """The actor may not perform this action.

    Distinct from "unsupported": unsupported means nothing can do it, this means
    this caller may not. Conflating them tells an operator to go configure an
    integration that is already configured.
    """

    is_retryable = False


class RemediationAuditFailed(TransientFailure):
    """A remediation side effect completed but its audit row could not be written."""

    def __init__(self, message: str, *, receipt: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.receipt = dict(receipt)


@dataclass(frozen=True, slots=True)
class RemediationReceipt:
    """What actually happened. The only truth about an executed action.

    `executed` and `dry_run` are independent on purpose. A caller asking "did
    something change in the real world" reads `executed` and gets a straight
    answer whether or not a dry run was requested.
    """

    action: str
    target: str
    provider: str
    #: True only when an external system changed. Never true for a dry run.
    executed: bool
    dry_run: bool
    idempotency_key: str
    at: str = ""
    #: Set when this receipt was returned from the idempotency store rather than
    #: from a fresh call. An operator seeing two receipts for one action needs to
    #: know the second did not double-execute.
    replayed: bool = False
    #: The action that would undo this one, carried so a rollback does not need
    #: to re-derive it from the catalogue at the moment it is needed most.
    rollback_action: str = ""
    detail: str = ""
    provider_response: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "provider": self.provider,
            "executed": self.executed,
            "dry_run": self.dry_run,
            "replayed": self.replayed,
            "idempotency_key": self.idempotency_key,
            "at": self.at,
            "rollback_action": self.rollback_action,
            "detail": self.detail,
            "provider_response": dict(self.provider_response),
        }


@runtime_checkable
class RemediationIntegration(Protocol):
    """One outbound system that can perform one action.

    Deliberately narrow. An integration makes the call and reports the result;
    it does not authorize, audit, dedupe or decide about dry runs, because the
    wrapper does all four and doing them twice is how they diverge.
    """

    @property
    def provider(self) -> str: ...

    def execute(self, *, target: str, idempotency_key: IdempotencyKey) -> Mapping[str, Any]: ...

    #: An integration MAY additionally declare a `tenant: str` keyword. Ones that
    #: do are called with it; ones that do not are called exactly as before.
    #:
    #: WHY IT IS OPTIONAL RATHER THAN REQUIRED. An outbound webhook does not need
    #: the tenant -- the endpoint an operator configured already belongs to one
    #: estate, and the target names the thing. An integration that acts on
    #: SENTINEL'S OWN state cannot work without it: every table here is
    #: tenant-scoped, and an integration that guessed would be a cross-tenant
    #: write dressed as a containment. Making it required would break every
    #: existing integration to serve the new ones; making it invisible would let
    #: a Sentinel-owned action silently operate on the wrong estate.


class ActionAuthorizer(Protocol):
    """Decides whether an actor may perform an action on a target."""

    def assert_permitted(self, *, action: str, target: str, actor: str) -> None: ...


class AllowListAuthorizer:
    """Authorization by explicit per-actor grant.

    Default deny. An actor with no entry may do nothing, which is the correct
    behaviour for a component that disables production agents: the failure mode
    of a missing grant is a refused remediation, and the failure mode of a
    default-allow is anyone with API access disabling anything.
    """

    __slots__ = ("_grants",)

    def __init__(self, *, grants: Mapping[str, frozenset[str]]) -> None:
        self._grants = {actor: frozenset(actions) for actor, actions in grants.items()}

    def assert_permitted(self, *, action: str, target: str, actor: str) -> None:
        permitted = self._grants.get(actor, frozenset())
        if action not in permitted and "*" not in permitted:
            raise RemediationUnauthorized(
                f"actor {actor!r} is not authorized to perform {action!r}"
            )


class IdempotencyStore(Protocol):
    """Remembers which idempotency keys have already produced a receipt."""

    def get(self, key: str, *, tenant: str = "") -> Mapping[str, Any] | None: ...

    def put(self, key: str, receipt: Mapping[str, Any], *, tenant: str = "") -> None: ...


class InMemoryIdempotencyStore:
    """Process-local dedupe.

    Honest about its limits: it dedupes retries within one process and does
    nothing across replicas. Real cross-replica idempotency is the approval
    claim in `DecideApprovalHandler`, which is a conditional UPDATE in the
    database and therefore actually exclusive. This is a second layer for the
    paths that do not go through an approval, not the primary defence.
    """

    __slots__ = ("_seen",)

    def __init__(self) -> None:
        self._seen: MutableMapping[str, Mapping[str, Any]] = {}

    def get(self, key: str, *, tenant: str = "") -> Mapping[str, Any] | None:
        return self._seen.get(key)

    def put(self, key: str, receipt: Mapping[str, Any], *, tenant: str = "") -> None:
        self._seen[key] = dict(receipt)


class SqlRemediationIdempotencyStore:
    """Tenant-scoped, durable remediation receipt dedupe."""

    __slots__ = ("_pool",)

    def __init__(self, *, pool: Any) -> None:
        self._pool = pool

    def get(self, key: str, *, tenant: str = "") -> Mapping[str, Any] | None:
        if not tenant.strip():
            return None
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            row = conn.one(
                f"SELECT receipt_json FROM remediation_idempotency "
                f"WHERE tenant_id={conn.p} AND idempotency_key={conn.p}",
                (tenant, key),
            )
            conn.commit()
        return json.loads(row["receipt_json"]) if row else None

    def put(self, key: str, receipt: Mapping[str, Any], *, tenant: str = "") -> None:
        if not tenant.strip():
            raise DomainRuleViolated(
                "SQL remediation idempotency is tenant-scoped; tenant is required"
            )
        with self._pool.acquire() as conn:
            conn.begin()
            conn.set_tenant(tenant)
            conn.execute_rowcount(
                f"INSERT INTO remediation_idempotency "
                f"(tenant_id, idempotency_key, receipt_json, created_at) "
                f"VALUES ({conn.p},{conn.p},{conn.p},{conn.p}) "
                f"ON CONFLICT (tenant_id, idempotency_key) DO UPDATE "
                f"SET receipt_json={conn.p}",
                (
                    tenant,
                    key,
                    json.dumps(dict(receipt), sort_keys=True, default=str),
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(dict(receipt), sort_keys=True, default=str),
                ),
            )
            conn.commit()


class HttpRemediationIntegration:
    """A provider reached over HTTPS through the hardened outbound client.

    Uses the existing `HardenedHttpClient` rather than a fresh requests session,
    so remediation calls inherit the SSRF protections, destination validation and
    header rules that every other outbound call in this system already has. A
    remediation endpoint is operator-configured, which makes it exactly the kind
    of URL an attacker would like to point at the metadata service.
    """

    __slots__ = ("_provider", "_client", "_url", "_headers", "_method")

    def __init__(
        self,
        *,
        provider: str,
        client: Any,
        url: str,
        headers: Mapping[str, str] | None = None,
        method: str = "POST",
    ) -> None:
        self._provider = provider
        self._client = client
        self._url = url
        self._headers = dict(headers or {})
        self._method = method

    @property
    def provider(self) -> str:
        return self._provider

    def execute(
        self, *, target: str, idempotency_key: IdempotencyKey
    ) -> Mapping[str, Any]:
        body = json.dumps(
            {"target": target, "idempotency_key": idempotency_key.value}
        ).encode("utf-8")
        headers = {
            "content-type": "application/json",
            # Passed to the provider as well as enforced locally: a provider that
            # honours it gives real cross-process idempotency, and one that
            # ignores it costs nothing.
            "idempotency-key": idempotency_key.value,
            **self._headers,
        }
        response = self._client.request(
            method=self._method,
            url=self._url,
            headers=headers,
            body=body,
            idempotent=True,
        )
        status = int(getattr(response, "status", 0))
        if status >= 500:
            # Transient: the provider may have applied it or may not have. Raised
            # rather than returned, so the caller releases its claim and retries
            # under the same idempotency key instead of recording a false failure.
            raise TransientFailure(
                f"{self._provider} returned {status} for target {target!r}"
            )
        if status >= 400:
            raise DomainRuleViolated(
                f"{self._provider} refused the action for target {target!r} "
                f"with status {status}"
            )
        return {"status": status, "provider": self._provider}


class GuardedRemediationExecutor:
    """Adds the six required properties around any set of integrations.

    Order matters and is the whole design:

      1. catalogue lookup -- an unknown action never reaches a provider
      2. authorization    -- before anything, including before a dry run, since
                             "what would this do" is itself information
      3. idempotency      -- a replayed key returns the prior receipt and makes
                             no call
      4. dry run          -- returns a receipt with executed=False
      5. execute          -- the only path that can produce executed=True
      6. audit            -- written for every outcome above, including refusals
    """

    __slots__ = ("_integrations", "_authorizer", "_store", "_audit", "_clock", "_dry_run")

    def __init__(
        self,
        *,
        integrations: Mapping[str, RemediationIntegration],
        authorizer: ActionAuthorizer,
        idempotency: IdempotencyStore,
        audit: Any,
        clock: Any,
        dry_run: bool = False,
    ) -> None:
        self._integrations = dict(integrations)
        self._authorizer = authorizer
        self._store = idempotency
        self._audit = audit
        self._clock = clock
        self._dry_run = dry_run

    def supports(self, action: str) -> bool:
        """An integration exists AND the action is in the catalogue.

        Both halves matter. `DecideApprovalHandler` calls this before executing
        and turns False into a clear `unsupported_action` refusal. Without the
        catalogue check, an integration registered under a name the catalogue
        does not know would pass `supports`, then raise
        `UnknownRemediationAction` inside `execute` -- where the handler's
        blanket `except Exception` converts it into a `TransientFailure`.

        That is the wrong answer twice over: it reads as "the provider is having
        trouble" when the real problem is a misconfigured deployment, and
        `TransientFailure` is retryable, so the approval would be retried for
        ever against a name that can never work.
        """
        if action not in self._integrations:
            return False
        try:
            action_named(action)
        except UnknownRemediationAction:
            return False
        return True

    @staticmethod
    def _invoke(
        integration: RemediationIntegration,
        *,
        target: str,
        idempotency_key: IdempotencyKey,
        tenant: str,
    ) -> Mapping[str, Any]:
        """Call an integration, passing `tenant` only to ones that declare it.

        INSPECTED, NOT TRY/EXCEPT. Calling with the keyword and catching
        `TypeError` would also swallow a `TypeError` raised INSIDE a correct
        integration, silently retrying it without the tenant -- which for a
        Sentinel-owned action means retrying it against no estate at all. The
        signature is a fact available before the call; reading it is cheaper
        than guessing from an exception raised after one.

        An integration that declares `tenant` and is handed an empty one is
        refused here rather than left to decide. It cannot act correctly without
        it, and the failure an operator needs to see is "no tenant reached the
        containment", not a row written somewhere unexpected.
        """
        parameters: Mapping[str, Any]
        try:
            parameters = inspect.signature(integration.execute).parameters
        except (TypeError, ValueError):  # pragma: no cover - exotic callables
            # Empty is the RIGHT fallback, not a degraded one: the check below
            # refuses when `tenant` is absent, so a callable we cannot inspect
            # is refused rather than trusted. Typed as a plain Mapping because
            # `signature().parameters` is a MappingProxyType and this is not.
            parameters = {}

        if "tenant" not in parameters:
            return integration.execute(
                target=target, idempotency_key=idempotency_key
            )
        if not tenant.strip():
            raise DomainRuleViolated(
                f"{type(integration).__name__} acts on tenant-scoped state and "
                "was given no tenant. Refusing: an integration that guessed the "
                "estate would be a cross-tenant write dressed as a containment."
            )
        # `tenant` is DELIBERATELY optional on the protocol -- see the long
            # note on `RemediationIntegration` -- and this line is reached only
            # after the signature check above confirmed the integration accepts
            # it, refusing otherwise. The runtime check IS the guard; mypy has
            # no way to express "an implementation may declare one more
            # keyword", so the call is narrowly ignored rather than the
            # documented design being changed to satisfy the checker.
        return integration.execute(  # type: ignore[call-arg]
            target=target, idempotency_key=idempotency_key, tenant=tenant
        )

    def execute(
        self,
        *,
        action: str,
        target: str,
        idempotency_key: IdempotencyKey,
        actor: str = "system",
        dry_run: bool | None = None,
        tenant: str = "",
    ) -> Mapping[str, Any]:
        catalogued: RemediationAction = action_named(action)
        inverse = rollback_for(action)
        rollback_name = inverse.name if inverse else ""
        effective_dry_run = self._dry_run if dry_run is None else dry_run

        # 2. Authorization, before the dry run. Knowing what an action WOULD do
        #    to a named target is itself information about the estate.
        try:
            self._authorizer.assert_permitted(action=action, target=target, actor=actor)
        except RemediationUnauthorized:
            self._record(
                action=action, target=target, actor=actor, outcome="unauthorized"
            )
            raise

        integration = self._integrations.get(action)
        if integration is None:
            self._record(
                action=action, target=target, actor=actor, outcome="unsupported"
            )
            raise NotImplementedError(
                f"no integration is registered for action {action!r}"
            )

        # 3. Idempotency. A replayed key returns the earlier receipt untouched
        #    except for the flag saying it is a replay.
        prior = self._store.get(idempotency_key.value, tenant=tenant)
        if prior is not None:
            self._record(
                action=action, target=target, actor=actor, outcome="replayed"
            )
            return {**dict(prior), "replayed": True}

        now = self._now()

        # 4. Dry run. A successful call that changed nothing, and says so in the
        #    one field callers actually check.
        if effective_dry_run:
            receipt = RemediationReceipt(
                action=action,
                target=target,
                provider=catalogued.provider,
                executed=False,
                dry_run=True,
                idempotency_key=idempotency_key.value,
                at=now,
                rollback_action=rollback_name,
                detail=f"dry run: {catalogued.summary} was NOT performed",
            )
            self._record(action=action, target=target, actor=actor, outcome="dry_run")
            # Deliberately NOT stored against the idempotency key. A dry run must
            # not satisfy a later real attempt with the same key, which would turn
            # "preview it, then do it" into "preview it, then think you did it".
            return receipt.as_dict()

        # 5. Execute. The only path that yields executed=True.
        try:
            response = self._invoke(
                integration, target=target, idempotency_key=idempotency_key, tenant=tenant
            )
        except Exception as exc:
            self._record(
                action=action,
                target=target,
                actor=actor,
                outcome="failed",
                detail=f"{type(exc).__name__}: {exc}",
            )
            # Re-raised unchanged. Classification (transient vs refusal) is the
            # integration's judgement, and flattening it here would lose the
            # distinction the caller needs to decide about retrying.
            raise

        receipt = RemediationReceipt(
            action=action,
            target=target,
            provider=getattr(integration, "provider", catalogued.provider),
            executed=True,
            dry_run=False,
            idempotency_key=idempotency_key.value,
            at=now,
            rollback_action=rollback_name,
            detail=catalogued.summary,
            provider_response=dict(response),
        )
        saved = receipt.as_dict()
        self._store.put(idempotency_key.value, saved, tenant=tenant)
        try:
            self._record(action=action, target=target, actor=actor, outcome="executed")
        except Exception as exc:  # noqa: BLE001 - side effect already happened
            failed = {
                **saved,
                "detail": f"{saved['detail']} (audit_failed)",
                "provider_response": {
                    **dict(saved.get("provider_response") or {}),
                    "audit_failed": True,
                    "audit_error": f"{type(exc).__name__}: {exc}",
                },
            }
            self._store.put(idempotency_key.value, failed, tenant=tenant)
            raise RemediationAuditFailed(
                f"remediation {action!r} executed for {target!r}, but audit failed: "
                f"{type(exc).__name__}: {exc}",
                receipt=failed,
            ) from exc
        return saved

    def rollback(
        self,
        receipt: Mapping[str, Any],
        *,
        actor: str = "system",
        tenant: str = "",
    ) -> Mapping[str, Any]:
        """Undo an executed action, when the catalogue names an inverse.

        Refuses on a receipt that did not execute. Rolling back a dry run would
        perform a real action to undo one that never happened -- an inverse with
        nothing on the other side of it.
        """
        if not receipt.get("executed"):
            raise DomainRuleViolated(
                "nothing to roll back: this receipt records no executed action"
            )
        inverse_name = str(receipt.get("rollback_action") or "")
        if not inverse_name:
            raise DomainRuleViolated(
                f"action {receipt.get('action')!r} has no inverse; it cannot be "
                f"rolled back"
            )
        return self.execute(
            action=inverse_name,
            tenant=tenant,
            target=str(receipt.get("target") or ""),
            # A distinct key. Sharing the original would make the rollback look
            # like a replay of the action it is undoing, and return that receipt
            # instead of performing anything.
            idempotency_key=IdempotencyKey(
                f"rb-{receipt.get('idempotency_key') or 'unknown'}"
            ),
            actor=actor,
            dry_run=False,
        )

    # ── internals ────────────────────────────────────────────────────────────

    def _now(self) -> str:
        try:
            return str(self._clock.now())
        except Exception:  # noqa: BLE001 - a clock failure must not lose the audit
            return ""

    def _record(
        self, *, action: str, target: str, actor: str, outcome: str, detail: str = ""
    ) -> None:
        """Audit every outcome, including the ones that did nothing.

        Refusals are the rows an investigation wants most: "who tried to disable
        this agent and was told no" is a question an audit trail that only
        records successes cannot answer.

        Failures here are not swallowed. The caller decides how to surface the
        typed error, and the execution path stores an `audit_failed` receipt
        before raising so a retry cannot re-run the side effect.
        """
        self._audit.record(
            kind="remediation",
            action=action,
            target=target,
            actor=actor,
            outcome=outcome,
            detail=detail,
        )


class ApprovalPathAuthorizer:
    """Permits remediation that arrived through the human-approval gate.

    WHAT ACTUALLY AUTHORIZES A REMEDIATION IN THIS SYSTEM
    -------------------------------------------------------
    The `DECIDE_APPROVAL` capability, checked on `POST /v1/approvals/{id}` before
    the command is dispatched. By the time `DecideApprovalHandler` calls the
    executor, a credential holding that capability has already been verified and
    the decision recorded against it.

    So this authorizer's job is not to re-litigate that. It is to ensure nothing
    reaches the executor by ANY OTHER ROUTE. `DecideApprovalHandler` is the only
    caller that stamps the actor as `remediation:<who>`; anything else -- a new
    code path, a script importing the container, a future background job -- gets
    a different actor string and is refused until somebody grants it explicitly.

    That is the useful property. A default-allow authorizer would make the next
    code path that touches the executor silently privileged, and this is the
    component that disables production agents.

    `extra_grants` is for the paths that legitimately need it later, named one at
    a time.
    """

    __slots__ = ("_prefix", "_extra")

    #: The stamp `DecideApprovalHandler` applies. Matching on it is matching on
    #: "came through the approval gate".
    APPROVAL_ACTOR_PREFIX: str = "remediation:"

    def __init__(self, *, extra_grants: Mapping[str, frozenset[str]] | None = None) -> None:
        self._prefix = self.APPROVAL_ACTOR_PREFIX
        self._extra = {a: frozenset(v) for a, v in (extra_grants or {}).items()}

    def assert_permitted(self, *, action: str, target: str, actor: str) -> None:
        if actor.startswith(self._prefix) and len(actor) > len(self._prefix):
            return
        permitted = self._extra.get(actor, frozenset())
        if action in permitted or "*" in permitted:
            return
        raise RemediationUnauthorized(
            f"actor {actor!r} did not arrive through the approval gate and has "
            f"no explicit grant for {action!r}"
        )


def build_remediation_executor(
    *,
    endpoints: Mapping[str, str],
    client: Any,
    audit: Any,
    clock: Any,
    dry_run: bool = False,
    native: Mapping[str, Any] | None = None,
    pool: Any = None,
) -> Any:
    """Build the executor a deployment's configuration actually calls for.

    Returns `NullRemediationExecutor` when nothing is configured -- neither a
    webhook endpoint nor a native integration. That is not a fallback or a
    degraded mode: it is the correct executor for a deployment with no
    integrations, and it refuses every action with a reason instead of returning
    a success-shaped receipt. Keeping that decision here means the composition
    root cannot accidentally wire a real executor over an empty endpoint map and
    ship something that looks armed and is not.

    `native` holds integrations this process performs ITSELF -- deleting a pod,
    attaching an AWS deny-older-sessions policy -- built from the same platform
    credentials the tool adapters use. Before they existed, an operator who
    wanted containment had to run a webhook service that re-implemented the
    Kubernetes call and held a second copy of the cluster credential; most did
    not, so `NullRemediationExecutor` was what nearly every deployment got and
    the CRITICAL containment path ended in `unsupported_action`.

    AN EXPLICIT ENDPOINT WINS OVER A NATIVE INTEGRATION. An operator who
    configured a webhook for `kill_container` did so on purpose -- their cluster
    may need an approval workflow this process knows nothing about -- and
    silently preferring the native path would override a deliberate decision.
    """
    integrations: dict[str, Any] = dict(native or {})
    integrations.update(
        {
            action: HttpRemediationIntegration(
                provider=action_named(action).provider, client=client, url=url
            )
            for action, url in endpoints.items()
        }
    )
    if not integrations:
        return NullRemediationExecutor()

    return GuardedRemediationExecutor(
        integrations=integrations,
        authorizer=ApprovalPathAuthorizer(),
        idempotency=(
            SqlRemediationIdempotencyStore(pool=pool)
            if pool is not None
            else InMemoryIdempotencyStore()
        ),
        audit=audit,
        clock=clock,
        dry_run=dry_run,
    )
