"""Sequence rules: the risk that only exists in the ORDER of ordinary steps.

WHY THESE CANNOT BE EVENT RULES
---------------------------------
    read_sensitive_file -> compress_file -> external_upload

Every step is legitimate on its own and the deterministic policy is right not to
block any of them: reading a file is what agents do, compression is a feature,
and uploading is a feature. The exfiltration lives entirely in the order, so no
amount of per-event scrutiny finds it. That is the whole argument for the
execution graph -- and the spec states it directly: *sequence detection must
operate on the execution graph*.

GAPS ARE ALLOWED, ORDER IS NOT
--------------------------------
A rule matches a SUBSEQUENCE, not a contiguous run. An agent that reads a file,
does nine ordinary things, compresses it and uploads it has performed the same
attack as one that does the three steps back to back -- and an attacker who
knows the rule requires adjacency defeats it by inserting a no-op.

`max_gap` bounds how far apart the steps may be. Without a bound, a file read on
Monday and an upload on Friday would match, and a rule that fires on any two
unrelated actions in a long session is one operators learn to ignore -- the same
alert-fatigue failure this codebase measured when the detector fired on 51.7% of
ordinary tool calls.

DETERMINISTIC, AND SEPARATE FROM ENFORCEMENT
----------------------------------------------
No model, no scoring, no statistics: a rule either matched or it did not, and
the matched steps are returned so the finding can be checked rather than
believed. The specification is explicit that blocking must not rest on an LLM
alone, and this is the deterministic half of that.

These findings do NOT block. They raise severity and produce evidence for a
human, because a sequence rule reasons over self-reported correlation -- an
agent controls its own `parentEventId` and could, in principle, shape what the
graph looks like. Evidence, never authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence

from sentinel.domain.execution_graph import ExecutionGraph, ExecutionNode

__all__ = [
    "SequenceSeverity",
    "SequenceRule",
    "SequenceMatch",
    "SEQUENCE_RULES",
    "ACTION_ALIASES",
    "canonical_action",
    "detect_sequences",
    "TERMINAL_STEPS",
    "could_complete_a_sequence",
]


class SequenceSeverity(str, Enum):
    """How bad a matched sequence is. Named, not numeric, at this layer.

    A rule author reasons in "this is critical", not in "this is 85". The
    mapping to a number happens once, below, so two rules cannot disagree about
    what critical means.
    """

    HIGH = "high"
    CRITICAL = "critical"

    @property
    def severity(self) -> int:
        return {SequenceSeverity.HIGH: 75, SequenceSeverity.CRITICAL: 90}[self]


#: Real action names an agent emits, mapped to the canonical step names the
#: rules are written in.
#:
#: This mapping is the difference between a rule that fires and a rule that
#: reads well in a specification and never matches anything. A rule written for
#: `read_sensitive_file` matches nothing if agents emit `read_file`, `getObject`
#: or `fs.read` -- and a gate that cannot fire is the defect class this
#: repository has found more often than any other.
ACTION_ALIASES: Final[Mapping[str, str]] = MappingProxyType({
    # ── reading something sensitive ──────────────────────────────────────────
    "read_sensitive_file": "read_sensitive_file",
    "read_file": "read_sensitive_file",
    "readfile": "read_sensitive_file",
    "fs.read": "read_sensitive_file",
    "getobject": "read_sensitive_file",
    "get_object": "read_sensitive_file",
    "cat": "read_sensitive_file",
    # ── packaging it up ──────────────────────────────────────────────────────
    "compress_file": "compress_file",
    "compress": "compress_file",
    "zip": "compress_file",
    "tar": "compress_file",
    "archive": "compress_file",
    "encode": "compress_file",
    "base64": "compress_file",
    # ── sending it out ───────────────────────────────────────────────────────
    "external_upload": "external_upload",
    "upload": "external_upload",
    "http_post": "external_upload",
    "post": "external_upload",
    "put_object": "external_upload",
    "send_email": "external_upload",
    "webhook": "external_upload",
    # ── credentials and privilege ────────────────────────────────────────────
    "credential_access": "credential_access",
    "read_secret": "credential_access",
    "get_secret": "credential_access",
    "read_env": "credential_access",
    "assume_role": "credential_access",
    "cloud_login": "cloud_login",
    "login": "cloud_login",
    "authenticate": "cloud_login",
    "sts_assume": "cloud_login",
    "privilege_change": "privilege_change",
    "grant_role": "privilege_change",
    "add_policy": "privilege_change",
    "attach_policy": "privilege_change",
    "create_user": "privilege_change",
    "privilege_grant": "privilege_grant",
    "grant_privilege": "privilege_grant",
    "create_access_key": "privilege_grant",
    "create_service_account": "new_identity_use",
    "use_new_identity": "new_identity_use",
    "assume_new_role": "new_identity_use",
    "new_identity_use": "new_identity_use",
    # ── discovery and follow-on sensitive reads ─────────────────────────────
    "list_files": "discovery",
    "find_files": "discovery",
    "search_files": "discovery",
    "grep_files": "discovery",
    "enumerate": "discovery",
    "discover": "discovery",
    "discovery": "discovery",
    # ── decode/download then execution ──────────────────────────────────────
    "decode": "decode",
    "base64_decode": "decode",
    "base64 -d": "decode",
    "download": "download",
    "clone": "download",
    "git_clone": "download",
    "clone_repository": "download",
    "fetch_artifact": "download",
    "execute_command": "execute",
    "run_command": "execute",
    "shell_exec": "execute",
    "exec": "execute",
    "execute": "execute",
    "run_script": "execute",
    # ── prompt-injection chain ───────────────────────────────────────────────
    "untrusted_document": "untrusted_document",
    "fetch_url": "untrusted_document",
    "http_get": "untrusted_document",
    "read_email": "untrusted_document",
    "browse": "untrusted_document",
    "system_prompt_change": "system_prompt_change",
    "set_system_prompt": "system_prompt_change",
    "update_instructions": "system_prompt_change",
    "tool_invocation": "tool_invocation",
    "invoke_tool": "tool_invocation",
    "call_tool": "tool_invocation",
})


def canonical_action(action: str) -> str:
    """Map an emitted action onto the vocabulary the rules use.

    Falls back to the lowercased action itself, so an unmapped action is still
    comparable rather than becoming an empty string that matches everything.
    """
    normalised = (action or "").strip().lower()
    return ACTION_ALIASES.get(normalised, normalised)


@dataclass(frozen=True, slots=True)
class SequenceRule:
    """An ordered set of steps that is dangerous as a whole."""

    name: str
    steps: tuple[str, ...]
    severity: SequenceSeverity
    #: Why this order is dangerous. Carried into the finding, because an alert
    #: that names a rule without explaining it makes the reader look up the
    #: source before they can act.
    rationale: str
    #: A plausible benign sequence with the same shape. Included in findings so
    #: operators know the deterministic rule's main false-positive mode.
    known_gap_note: str
    #: How many unrelated steps may sit between two matched ones.
    max_gap: int = 20

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "steps": list(self.steps),
            "severity": self.severity.value,
            "rationale": self.rationale,
            "known_gap": self.known_gap_note,
        }


SEQUENCE_RULES: Final[tuple[SequenceRule, ...]] = (
    SequenceRule(
        name="staged_exfiltration",
        steps=("read_sensitive_file", "compress_file", "external_upload"),
        severity=SequenceSeverity.HIGH,
        rationale=(
            "Read, package, send. Each step is a legitimate feature and the "
            "combination is data leaving the estate. Compression in the middle "
            "is what distinguishes it from ordinary work: it is how a volume of "
            "records becomes one small artifact that fits in a single upload."
        ),
        known_gap_note=(
            "Backup and archival jobs can read, compress and upload to an "
            "approved internal bucket; destination ownership is needed to clear it."
        ),
    ),
    SequenceRule(
        name="credential_to_privilege",
        steps=("credential_access", "cloud_login", "privilege_change"),
        severity=SequenceSeverity.CRITICAL,
        rationale=(
            "Take a credential, use it, then widen what it can do. This is "
            "privilege escalation with the steps in the only order that works, "
            "and the last one makes the first two durable -- after a policy "
            "change, revoking the original credential no longer helps."
        ),
        known_gap_note=(
            "A bootstrap job may read a managed credential, authenticate and "
            "apply an expected policy during provisioning."
        ),
    ),
    SequenceRule(
        name="credential_to_outbound",
        steps=("credential_access", "external_upload"),
        severity=SequenceSeverity.HIGH,
        rationale=(
            "A credential or secret is read and the session later sends data "
            "out. The risk is not either step alone; it is the short path from "
            "secret access to network egress."
        ),
        known_gap_note=(
            "Secret-backed health checks and token exchange flows may read a "
            "credential before calling a trusted identity endpoint."
        ),
    ),
    SequenceRule(
        name="privilege_grant_to_new_identity_use",
        steps=("privilege_grant", "new_identity_use"),
        severity=SequenceSeverity.CRITICAL,
        rationale=(
            "Privileges are granted and a newly empowered identity is used. "
            "That is persistence or escalation becoming operational, rather "
            "than a dormant configuration change."
        ),
        known_gap_note=(
            "Legitimate provisioning may grant a role and immediately verify "
            "the new service account can assume it."
        ),
    ),
    SequenceRule(
        name="discovery_burst_to_sensitive_read",
        steps=("discovery", "discovery", "discovery", "read_sensitive_file"),
        severity=SequenceSeverity.HIGH,
        rationale=(
            "Repeated discovery followed by a sensitive read is a common path "
            "from reconnaissance to collection. The burst matters: one search "
            "is ordinary work; several searches before a credential read are "
            "a different behaviour."
        ),
        known_gap_note=(
            "Indexing, backup discovery and migration tools may enumerate many "
            "paths before reading a configured secret."
        ),
    ),
    SequenceRule(
        name="decode_to_exec",
        steps=("decode", "execute"),
        severity=SequenceSeverity.CRITICAL,
        rationale=(
            "A payload is decoded and then executed. Encoding is a common way "
            "to hide shell content from argument-level controls before running it."
        ),
        known_gap_note=(
            "Build systems sometimes decode checked-in fixtures or scripts and "
            "execute them as part of a deterministic test."
        ),
    ),
    SequenceRule(
        name="download_to_exec",
        steps=("download", "execute"),
        severity=SequenceSeverity.CRITICAL,
        rationale=(
            "A fresh artifact is cloned or downloaded and then executed in the "
            "same session. That is the shape of remote code execution through "
            "tooling, even when the individual download and run calls are normal."
        ),
        known_gap_note=(
            "CI and developer automation routinely clone trusted repositories "
            "and run their build scripts."
        ),
    ),
    SequenceRule(
        name="injection_to_action",
        steps=("untrusted_document", "system_prompt_change", "tool_invocation"),
        severity=SequenceSeverity.HIGH,
        rationale=(
            "Content arrives from outside, the agent's instructions change, and "
            "the agent then acts. This is indirect prompt injection observed as "
            "behaviour rather than inferred from text -- the agent did not need "
            "to be tricked in a way any classifier could see, only to read "
            "something and change what it was doing."
        ),
        known_gap_note=(
            "Prompt editors and evaluation harnesses may intentionally load an "
            "external fixture, update instructions and call a tool under test."
        ),
    ),
)


#: The last step of every rule.
#:
#: A cheap pre-filter for the ingest path. Sequence detection is O(session) per
#: event, so running it on EVERY event makes a session O(n^2) in its own length
#: -- and for all but the final step of a rule the answer cannot change, because
#: a subsequence is only completed by its last element arriving.
#:
#: So the graph is queried only when the incoming action could actually complete
#: something. On a thousand-step session that is the difference between a
#: thousand scans and a handful.
TERMINAL_STEPS: Final[frozenset[str]] = frozenset(r.steps[-1] for r in SEQUENCE_RULES)


def could_complete_a_sequence(action: str) -> bool:
    """Whether this action is the final step of any rule.

    False means no rule can newly match on this event, so the graph need not be
    read at all. It never means "safe" -- only "nothing new can complete here".
    """
    return canonical_action(action) in TERMINAL_STEPS


@dataclass(frozen=True, slots=True)
class SequenceMatch:
    """A rule that matched, and the exact steps that matched it.

    `matched_nodes` is the point. A finding that says "staged_exfiltration"
    without naming the three events cannot be checked, and an analyst's first
    question is always "which ones" -- so the answer travels with the finding
    rather than requiring a second query.
    """

    rule: SequenceRule
    matched_nodes: tuple[ExecutionNode, ...]
    session_id: str = ""

    @property
    def severity(self) -> int:
        return self.rule.severity.severity

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule.name,
            "severity": self.severity,
            "severity_band": self.rule.severity.value,
            "rationale": self.rule.rationale,
            "known_gap": self.rule.known_gap_note,
            "session_id": self.session_id,
            "matched": [
                {
                    "event_id": n.event_id,
                    "action": n.action,
                    "resource": n.resource,
                    "destination": n.destination,
                    "occurred_at": n.occurred_at,
                }
                for n in self.matched_nodes
            ],
        }


def detect_sequences(
    graph: ExecutionGraph, rules: Sequence[SequenceRule] = SEQUENCE_RULES
) -> tuple[SequenceMatch, ...]:
    """Find every rule whose steps appear in order within the graph.

    Pure and deterministic: same graph, same rules, same answer, every time.
    Nothing here reads a clock, a model or a database.

    Greedy first-match. For "did this pattern occur", the earliest witness is as
    good as any other and costs one pass; enumerating every combination would
    turn one story into hundreds of near-identical findings, which is how an
    alert becomes noise.
    """
    nodes = tuple(graph.nodes)
    if not nodes:
        return ()

    canonical = [canonical_action(n.action) for n in nodes]
    matches: list[SequenceMatch] = []

    for rule in rules:
        found: list[ExecutionNode] = []
        cursor = 0
        for step in rule.steps:
            hit = -1
            for index in range(cursor, len(nodes)):
                if canonical[index] != step:
                    continue
                # The gap is measured from the PREVIOUS matched step, so a rule
                # tolerates unrelated work between its steps but not an
                # unbounded stretch of it.
                if found and (index - cursor) > rule.max_gap:
                    break
                hit = index
                break
            if hit < 0:
                found = []
                break
            found.append(nodes[hit])
            cursor = hit + 1

        if len(found) == len(rule.steps):
            matches.append(
                SequenceMatch(
                    rule=rule,
                    matched_nodes=tuple(found),
                    session_id=graph.session_id,
                )
            )

    return tuple(matches)
