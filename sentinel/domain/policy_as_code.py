"""Policies that live in version control, and what it takes to apply one safely.

    validation / versioning / diff / rollback / simulation / approval / deployment
    Never silently apply malformed policies.

THE ONE SENTENCE THAT SHAPES THIS MODULE
------------------------------------------
"Never silently apply malformed policies." Everything below follows from taking
that literally, because there are two ways to break it and only one is obvious.

The obvious one is accepting a policy that fails to parse. The subtle one --
and the one that actually happens -- is accepting a policy that parses fine and
matches nothing. A rule written for `read_sensitive_file` when agents emit
`read_file` is perfectly well-formed and completely inert, and it is the exact
defect this repository has found more often than any other: gates that execute
nothing. A validator that only checks syntax hands an operator a policy that
looks deployed and defends nothing.

So `validate` checks that every rule COULD match something -- known actions,
non-empty selectors, a severity that means anything -- and refuses the ones that
could not.

VERSIONS ARE IMMUTABLE, WHICH IS WHAT MAKES ROLLBACK REAL
-----------------------------------------------------------
A `PolicyVersion` is content-addressed by a digest over its canonical form. Two
consequences worth stating:

  * Rollback is "activate version N again", not "undo the edit". The bytes that
    were running last Tuesday still exist and can be re-activated exactly.
  * A diff between two versions is a fact, not a reconstruction. An operator
    reviewing a change is reviewing the change that will actually be applied.

Editing a version in place would break both, so `PolicyVersion` is frozen and
`activate` selects rather than mutates.

SIMULATION IS SECTION 30, AND IT IS THE PART ENTERPRISES ACTUALLY ASK FOR
---------------------------------------------------------------------------
    What would this policy have done during the last 7 days?

A policy that cannot be answered that question about is one nobody dares deploy.
`simulate` replays recorded events against a candidate version and reports what
it WOULD have done, without the candidate being active -- which is the only
honest way to estimate false positives before they page somebody.

The estimate is explicitly an estimate, and the module says so rather than
implying precision it does not have: an event that was blocked in the past may
not have recurred, and a workflow that changed since is not represented at all.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from sentinel.domain.errors import DomainRuleViolated

__all__ = [
    "MAX_RULES",
    "MalformedPolicy",
    "PolicyDiff",
    "PolicyEffect",
    "PolicyRule",
    "PolicyVersion",
    "SimulationResult",
    "diff_versions",
    "simulate",
    "validate",
]

#: Cap on rules in one version.
#:
#: Every rule is evaluated against every event, so an unbounded policy is a
#: denial of service an operator can inflict on themselves by pasting a
#: generated file. Large enough that no honest policy hits it.
MAX_RULES: int = 500


class MalformedPolicy(DomainRuleViolated):
    """A policy that would not do what its author believes it does.

    Covers both a policy that cannot be parsed and one that parses and could
    never match anything. The second is the dangerous case: it deploys cleanly
    and defends nothing.
    """

    is_retryable = False


class PolicyEffect(str, Enum):
    """What a matching rule asks for.

    Deliberately the same vocabulary as `Disposition` in `remediation.py` where
    they overlap, and deliberately NOT an integer severity: a rule author is
    stating an intent, and the mapping from intent to number belongs in one
    place rather than in every YAML file an operator writes.
    """

    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One rule. Selectors are exact or glob-prefixed, never regular expressions.

    NO REGULAR EXPRESSIONS, ON PURPOSE
    ------------------------------------
    A policy file is operator-supplied text evaluated against every event. A
    regex in that position is a catastrophic-backtracking denial of service that
    an operator can introduce by accident, in a file that reviews cleanly. Prefix
    globs cover what policies actually need and cannot blow up.
    """

    name: str
    effect: PolicyEffect
    #: Actions this rule applies to. `*` matches any; a trailing `*` is a prefix.
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    destinations: tuple[str, ...] = ()
    #: Only applies at or above this severity. 0 means "any".
    min_severity: int = 0
    description: str = ""

    def matches(
        self, *, action: str = "", resource: str = "", destination: str = "", severity: int = 0
    ) -> bool:
        if severity < self.min_severity:
            return False
        return (
            _selector_matches(self.actions, action)
            and _selector_matches(self.resources, resource)
            and _selector_matches(self.destinations, destination)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "effect": self.effect.value,
            "actions": list(self.actions),
            "resources": list(self.resources),
            "destinations": list(self.destinations),
            "min_severity": self.min_severity,
            "description": self.description,
        }


def _selector_matches(patterns: Sequence[str], value: str) -> bool:
    """An empty selector means "do not constrain on this axis".

    NOT "match nothing". The distinction decides whether a rule with only an
    action selector matches every resource or no resource, and getting it the
    other way round makes every such rule inert -- the failure this module's
    validator exists to catch.
    """
    if not patterns:
        return True
    for pattern in patterns:
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            if value.startswith(pattern[:-1]):
                return True
        elif value == pattern:
            return True
    return False


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    """An immutable, content-addressed policy document.

    `digest` is over the CANONICAL form, so two documents that differ only in
    key order or whitespace are the same version. Without that, a reformat in an
    editor produces a "new policy" for review and the diff an operator reads is
    noise.
    """

    version: int
    rules: tuple[PolicyRule, ...]
    created_by: str
    created_at: str
    note: str = ""

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            [rule.as_dict() for rule in self.rules], sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def rule_named(self, name: str) -> PolicyRule | None:
        return next((r for r in self.rules if r.name == name), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "digest": self.digest,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "note": self.note,
            "rules": [rule.as_dict() for rule in self.rules],
        }


def validate(
    rules: Sequence[PolicyRule], *, known_actions: Iterable[str] = ()
) -> tuple[PolicyRule, ...]:
    """Refuse a policy that is malformed OR that could never match anything.

    The second check is the one that matters. A rule naming an action no agent
    emits is syntactically perfect and permanently inert; deploying it tells an
    operator they are protected when they are not.

    `known_actions` is optional because a deployment may legitimately write a
    rule ahead of the action existing. When supplied, an unknown action is
    refused with the name spelled out, because the realistic cause is a typo and
    the realistic consequence is silence.
    """
    if not rules:
        raise MalformedPolicy(
            "a policy with no rules would replace the active one with nothing; "
            "to disable enforcement, change the protection mode instead"
        )
    if len(rules) > MAX_RULES:
        raise MalformedPolicy(
            f"policy has {len(rules)} rules, more than the {MAX_RULES} limit; "
            f"every rule is evaluated against every event"
        )

    seen: set[str] = set()
    known = {a.strip().lower() for a in known_actions if a.strip()}

    for rule in rules:
        if not rule.name.strip():
            raise MalformedPolicy("every rule needs a name; findings cite it")
        if rule.name in seen:
            # Two rules with one name make a finding ambiguous and a diff
            # meaningless -- `rule_named` would return whichever came first.
            raise MalformedPolicy(f"duplicate rule name {rule.name!r}")
        seen.add(rule.name)

        if not 0 <= rule.min_severity <= 100:
            raise MalformedPolicy(
                f"rule {rule.name!r} has min_severity {rule.min_severity}, "
                f"outside 0..100"
            )
        if rule.min_severity == 100 and rule.effect is not PolicyEffect.ALLOW:
            # Severity is capped at 100, so `>= 100` fires only on the single
            # highest possible score. Almost always a misunderstanding of the
            # scale, and inert in practice.
            raise MalformedPolicy(
                f"rule {rule.name!r} requires severity 100, which only the "
                f"maximum possible score reaches; it would effectively never fire"
            )

        if not (rule.actions or rule.resources or rule.destinations):
            # A rule with no selectors at all matches EVERY event. As a BLOCK
            # that is an estate-wide outage in a file that reviews cleanly.
            if rule.effect is not PolicyEffect.ALLOW:
                raise MalformedPolicy(
                    f"rule {rule.name!r} has no selectors, so it matches every "
                    f"event; a catch-all {rule.effect.value} would apply to the "
                    f"whole estate"
                )

        if known:
            for pattern in rule.actions:
                if pattern == "*" or pattern.endswith("*"):
                    continue
                if pattern.strip().lower() not in known:
                    raise MalformedPolicy(
                        f"rule {rule.name!r} names action {pattern!r}, which no "
                        f"agent in this deployment has ever emitted; it would "
                        f"never match. Check the spelling, or use a prefix."
                    )
    return tuple(rules)


@dataclass(frozen=True, slots=True)
class PolicyDiff:
    """What changed between two versions, in reviewable terms."""

    from_version: int
    to_version: int
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "from_version": self.from_version,
            "to_version": self.to_version,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
            "is_empty": self.is_empty,
        }


def diff_versions(before: PolicyVersion, after: PolicyVersion) -> PolicyDiff:
    """Rule-level diff, by name.

    By name rather than by position, so reordering a file is not reported as
    every rule changing. An operator who cannot trust a diff stops reading it.
    """
    before_by_name = {r.name: r for r in before.rules}
    after_by_name = {r.name: r for r in after.rules}
    added = tuple(sorted(set(after_by_name) - set(before_by_name)))
    removed = tuple(sorted(set(before_by_name) - set(after_by_name)))
    changed = tuple(
        sorted(
            name
            for name in set(before_by_name) & set(after_by_name)
            if before_by_name[name] != after_by_name[name]
        )
    )
    return PolicyDiff(
        from_version=before.version,
        to_version=after.version,
        added=added,
        removed=removed,
        changed=changed,
    )


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """What a candidate policy WOULD have done, over recorded history.

    Section 30's fields, and one the specification does not ask for:
    `is_estimate`. It is always true, and it is here because a number presented
    without it gets quoted in a change review as though it were a measurement.
    """

    events_evaluated: int = 0
    would_allow: int = 0
    would_block: int = 0
    would_require_approval: int = 0
    would_warn: int = 0
    #: Events this candidate would newly block that the active policy allowed
    #: and that produced no incident. The closest available proxy for a false
    #: positive, and a proxy is what it is: an event nobody complained about is
    #: not proof it was harmless.
    potential_false_positives: int = 0
    affected_agents: tuple[str, ...] = ()
    affected_workflows: tuple[str, ...] = ()
    #: Rule name -> how many events it matched. An operator's first question
    #: about a surprising total is which rule produced it.
    matches_by_rule: Mapping[str, int] = field(default_factory=dict)

    @property
    def is_estimate(self) -> bool:
        """Always true. See the class docstring."""
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "events_evaluated": self.events_evaluated,
            "would_allow": self.would_allow,
            "would_block": self.would_block,
            "would_require_approval": self.would_require_approval,
            "would_warn": self.would_warn,
            "potential_false_positives": self.potential_false_positives,
            "affected_agents": list(self.affected_agents),
            "affected_workflows": list(self.affected_workflows),
            "matches_by_rule": dict(self.matches_by_rule),
            "is_estimate": self.is_estimate,
            "estimate_caveat": (
                "Counts are over recorded history only. An event that was "
                "blocked before may not have recurred, and workflows that "
                "changed since are not represented."
            ),
        }


def simulate(
    candidate: PolicyVersion, events: Sequence[Mapping[str, Any]]
) -> SimulationResult:
    """Replay recorded events against a candidate policy.

    Pure, and takes the events rather than fetching them, so the answer can be
    checked against a fixed corpus. The candidate is never activated -- that is
    the entire point of asking the question.

    First match wins, in declaration order. Stated because the alternative
    (most-restrictive wins) is also defensible, and a policy language whose
    resolution order is undocumented produces surprises that operators read as
    bugs.
    """
    allow = block = approval = warn = false_positives = 0
    agents: set[str] = set()
    workflows: set[str] = set()
    by_rule: dict[str, int] = {}

    for event in events:
        action = str(event.get("action") or "")
        resource = str(event.get("resource") or "")
        destination = str(event.get("destination") or "")
        severity = int(event.get("severity") or 0)

        matched = next(
            (
                rule
                for rule in candidate.rules
                if rule.matches(
                    action=action,
                    resource=resource,
                    destination=destination,
                    severity=severity,
                )
            ),
            None,
        )
        if matched is None:
            allow += 1
            continue

        by_rule[matched.name] = by_rule.get(matched.name, 0) + 1
        if matched.effect is PolicyEffect.BLOCK:
            block += 1
        elif matched.effect is PolicyEffect.REQUIRE_APPROVAL:
            approval += 1
        elif matched.effect is PolicyEffect.WARN:
            warn += 1
        else:
            allow += 1
            continue

        if matched.effect in {PolicyEffect.BLOCK, PolicyEffect.REQUIRE_APPROVAL}:
            if event.get("agent_id"):
                agents.add(str(event["agent_id"]))
            if event.get("workflow"):
                workflows.add(str(event["workflow"]))
            # The proxy described on SimulationResult: newly restricted, and
            # nothing at the time thought it was worth an incident.
            if not event.get("incident_id"):
                false_positives += 1

    return SimulationResult(
        events_evaluated=len(events),
        would_allow=allow,
        would_block=block,
        would_require_approval=approval,
        would_warn=warn,
        potential_false_positives=false_positives,
        affected_agents=tuple(sorted(agents)),
        affected_workflows=tuple(sorted(workflows)),
        matches_by_rule=dict(by_rule),
    )
