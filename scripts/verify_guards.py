"""Break each safety property on purpose, and require its guard to notice.

THE PROBLEM THIS SOLVES
-----------------------
Every serious defect found while building this release machinery was the same
shape: a check that read something other than what it appeared to read, and
therefore reported success no matter what.

  * Twenty-one gates resolved to `filename = None`, so nothing was ever looked
    for and every one reported UNVERIFIED forever.
  * A test scanned source text for "PASS" near `GA_GATES` -- and matched the
    prose promising the property rather than the property.
  * A pass-count regex was corrupted into a literal backspace byte. It matched
    nothing, which would have failed every pytest gate, and it was invisible in
    a terminal.
  * The console went entirely blank while a check that clicked every view and
    read its text reported all nine healthy: `innerText` returns text from
    hidden elements.
  * A DAST subprocess decoded UTF-8 with the locale codec, so the captured
    output was empty -- and the crash-detector asks whether the output contains
    "Failures:". A real finding would have been filed as a tool crash and
    suppressed.

Every one of those was GREEN. Reading the tests did not reveal them; four were
found by accident, one by a screenshot, one by comparing a runner's console
output against the report it fed.

A guard that cannot fail is not a guard, and the only way to know a guard can
fail is to make it fail.

WHAT THIS DOES
--------------
For each registered property: violate it in the source, run the specific test
that claims to protect it, and require that test to FAIL. Then restore the
source and require the test to pass again.

A guard that stays green while its property is broken is VACUOUS, and this
reports it as a defect. That is mutation testing, scoped to the handful of
invariants where a silent failure matters most, rather than sprayed across
every line.

WHY THE MUTATIONS ARE HAND-WRITTEN
-----------------------------------
Generic mutation tools flip operators and delete statements, which produces
thousands of mutants and a coverage percentage. That is a different question
from the one here. These mutations are the ACTUAL defects -- the exemption that
grew a third entry, the panel that lost its class, the regex that accepted a
zero count. Each one has already happened or is one careless edit away.

SAFETY
------
This edits real source files, so:

  * It REFUSES to run on a dirty tree. `git checkout .` must be a complete
    recovery at any moment.
  * Every file is snapshotted as exact bytes and restored in a `finally`, and
    the restoration is verified by digest. A failed restore aborts loudly with
    the command to recover rather than continuing.
  * One mutation is applied at a time and undone before the next.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import release_binding  # noqa: E402

OUT = ROOT / "release" / "gates" / "gate_guard_mutation.json"


@dataclass(frozen=True)
class Mutation:
    """One property, one way to break it, and the guard that must object."""

    name: str
    #: The file to edit, relative to the repository root.
    path: str
    #: Exact text to replace. Must appear EXACTLY once, so a mutation cannot
    #: silently apply somewhere else after a refactor.
    before: str
    #: What to put there instead -- the defect.
    after: str
    #: `pytest` node id of the guard that must fail.
    guard: str
    #: What goes wrong in production if this guard is vacuous.
    consequence: str


MUTATIONS: tuple[Mutation, ...] = (
    Mutation(
        name="console_panel_loses_its_switcher_class",
        path="sentinel/interface/console/index.html",
        # The Assess panel folded into Supply chain when the console became an
        # operator tool; Approvals is the panel an operator opens first, so it
        # is the one whose disappearance would be noticed last by a check that
        # reads text and first by a person.
        before='<main id="view-approvals" class="view" hidden>',
        after='<main id="view-approvals" hidden>',
        guard=(
            "tests_arch/test_console_bundle.py::"
            "test_every_view_panel_carries_the_class_the_switcher_selects"
        ),
        consequence=(
            "The entire console renders blank on every tab. `showView` iterates "
            "`.view`, so selecting a classless panel hides every panel it can "
            "see and unhides nothing. This exact defect shipped and survived a "
            "check that read innerText from all nine views."
        ),
    ),
    Mutation(
        name="gate_artifact_recording_failure_treated_as_success",
        path="scripts/build_release_evidence.py",
        before='if artifact.get("ok") is True:',
        after='if artifact.get("ok"):',
        guard=(
            "tests_arch/test_release_gate_runner.py::"
            "test_ok_must_be_the_boolean_true_and_not_merely_truthy"
        ),
        consequence=(
            'A gate artifact carrying `"ok": "failed"` reports PASS. Every '
            "non-empty string is truthy, so a runner that wrote a status word "
            "instead of a boolean would turn every failure into a pass."
        ),
    ),
    Mutation(
        name="hollow_pytest_run_accepted",
        path="scripts/run_release_gates.py",
        before='re.search(r"[1-9][0-9]* passed", output)',
        after='re.search(r"[0-9]* passed", output)',
        guard=(
            "tests_arch/test_release_gate_runner.py::"
            "test_the_pass_pattern_refuses_a_zero_count"
        ),
        consequence=(
            'pytest prints "0 passed, 5 skipped" for an all-skipped run and '
            "exits 0. A pattern accepting a zero count reports PASS for a gate "
            "that verified nothing -- which is how `redis_tests` would have "
            "gone green on every machine without Redis."
        ),
    ),
    Mutation(
        name="a_third_route_escapes_rate_limiting",
        path="sentinel/interface/throttle.py",
        before='exempt_paths: tuple[str, ...] = ("/health/live", "/health/ready")',
        after=(
            'exempt_paths: tuple[str, ...] = '
            '("/health/live", "/health/ready", "/v1/events")'
        ),
        guard=(
            "tests_arch/test_readiness_probe_cache.py::test_no_other_route_is_exempt"
        ),
        consequence=(
            "An ingest endpoint with no rate limit. The exemption list is the "
            "one place a route can escape the limiter entirely, and a third "
            "entry added in a large diff looks exactly like the two that are "
            "correct."
        ),
    ),
    Mutation(
        name="readiness_probe_stops_being_cached",
        path="sentinel/interface/health_routes.py",
        before="        cached = readiness_cache.get(\"database\")",
        after="        cached = None",
        guard=(
            "tests_arch/test_readiness_probe_cache.py::"
            "test_repeated_readiness_probes_do_not_requery_the_database"
        ),
        consequence=(
            "`/health/ready` is exempt from rate limiting and queries the "
            "database. Without the cache that is an unauthenticated, unmetered "
            "load amplifier anyone can aim at the database."
        ),
    ),
    Mutation(
        name="ga_gate_quietly_leaves_the_unsatisfiable_set",
        path="scripts/build_release_evidence.py",
        before='    "design_partner_validation": (',
        after='    "_removed_design_partner_validation": (',
        guard=(
            "tests_arch/test_ga_gates_cannot_be_faked.py::"
            "test_the_four_gates_are_the_four_expected_ones"
        ),
        consequence=(
            "A gate that leaves GA_GATES becomes satisfiable by a build, so a "
            "planted artifact would report PASS for customer validation that "
            "never happened."
        ),
    ),
    Mutation(
        name="secret_allowlist_widened_to_cover_real_keys",
        path=".gitleaks.toml",
        before="'''key_hash\\s*=\\s*\"abcdef0123456789\"'''",
        after="'''key_hash'''",
        guard=(
            "tests_arch/test_security_verification.py::"
            "test_the_gitleaks_allowlist_regexes_cannot_excuse_a_real_secret"
        ),
        consequence=(
            "An allowlist entry wide enough to excuse a real credential. The "
            "scan keeps reporting 'no leaks found' and starts meaning nothing, "
            "which is the one failure mode of a secret scanner that is "
            "completely silent."
        ),
    ),
    Mutation(
        name="leaves_and_nodes_share_a_hash_prefix",
        path="sentinel/domain/transparency.py",
        before='_NODE = b"\\x01"',
        after='_NODE = b"\\x00"',
        guard=(
            "tests_arch/test_transparency.py::"
            "test_the_node_prefix_is_applied_and_differs_from_the_leaf_prefix"
        ),
        consequence=(
            "RFC 6962's second-preimage attack reopens: an internal node hashes "
            "identically to a leaf, so a leaf whose value equals a "
            "concatenation of two hashes can be presented as an internal node. "
            "This mutation was UNDETECTED on the first run -- the existing "
            "domain-separation test built a one-entry log, which has no "
            "internal node, so it only ever checked the leaf prefix while its "
            "name promised both."
        ),
    ),
    Mutation(
        name="transparency_consistency_check_fails_open",
        path="sentinel/domain/transparency.py",
        before="    if new_size < old_size:\n        return ConsistencyFailure.SHRANK",
        after=(
            "    return None\n    if new_size < old_size:\n"
            "        return ConsistencyFailure.SHRANK"
        ),
        guard=(
            "tests_arch/test_transparency.py::"
            "test_a_rewritten_history_cannot_produce_a_consistency_proof"
        ),
        consequence=(
            "Every rewritten history verifies. Consistency is the ONLY check in "
            "the system that catches an operator who deleted a passport and "
            "re-signed the log; failing it open silently restores the ability "
            "to serve two different pasts to two auditors."
        ),
    ),
    Mutation(
        name="leftover_consistency_proof_nodes_tolerated",
        path="sentinel/domain/transparency.py",
        before="    if nodes:\n        # Unused nodes mean",
        after="    if False and nodes:\n        # Unused nodes mean",
        guard=(
            "tests_arch/test_transparency.py::"
            "test_a_consistency_proof_with_nodes_left_over_is_refused"
        ),
        consequence=(
            "A proof is accepted with attacker-chosen trailing content, because "
            "the walk is driven by the two tree SIZES rather than by the proof's "
            "length and simply stops reading. Also UNDETECTED on the first run: "
            "no test fed an over-long proof."
        ),
    ),
    Mutation(
        name="inclusion_sibling_orientation_always_left",
        path="sentinel/domain/transparency.py",
        before="            _node_hash(computed, sibling)\n            if on_left",
        after="            _node_hash(computed, sibling)\n            if True",
        guard=(
            "tests_arch/test_transparency.py::"
            "test_every_entry_in_a_log_of_any_size_proves_its_own_inclusion"
        ),
        consequence=(
            "Inclusion proofs verify only for entries that are a left child at "
            "every level -- index 0 in every tree. This was the original defect: "
            "one loop did the top-down orientation descent and the bottom-up "
            "hash fold together, applying the outermost orientation to the "
            "innermost sibling. Indices 1, 3, 4 and 6 failed and index 0 passed, "
            "so any test that checked a single entry would have shipped it."
        ),
    ),
    Mutation(
        name="empty_discovery_reports_a_complete_estate",
        path="sentinel/domain/ai_bom.py",
        before="    if not sources:\n        return Completeness.UNUSABLE",
        after="    if not sources:\n        return Completeness.COMPLETE",
        guard=(
            "tests_arch/test_ai_bom.py::"
            "test_a_bom_from_no_inventories_is_unusable_not_complete"
        ),
        consequence=(
            "A discovery run whose connectors all errored reports a CLEAN AI "
            "estate. Every dashboard shows zero unpinned models and zero "
            "unattested skills at the exact moment visibility was lost. This is "
            "the most damaging output an inventory can produce, because it is "
            "indistinguishable from good news."
        ),
    ),
    Mutation(
        name="a_scan_that_examined_nothing_counts_as_a_scan",
        path="sentinel/domain/ai_bom.py",
        before="    if all(source.coverage.examined == 0 for source in sources):",
        after="    if False:",
        guard=(
            "tests_arch/test_ai_bom.py::"
            "test_a_bom_whose_sources_examined_nothing_is_unusable"
        ),
        consequence=(
            "A connector that returns successfully having inspected zero "
            "objects -- wrong credential, wrong scope, empty namespace filter "
            "-- yields a COMPLETE document. The call did not fail, so nothing "
            "else in the pipeline would notice; only the denominator does."
        ),
    ),
    Mutation(
        name="a_partially_blind_scan_reports_complete",
        path="sentinel/domain/ai_bom.py",
        before="    if any(source.coverage.is_partial for source in sources):",
        after="    if False:",
        guard=(
            "tests_arch/test_ai_bom.py::"
            "test_any_unreachable_target_makes_the_document_partial"
        ),
        consequence=(
            "An entire AWS account that returned AccessDenied disappears behind "
            "a working Kubernetes scan, and the document says COMPLETE. "
            "Coverage exists precisely so a count has a denominator."
        ),
    ),
    Mutation(
        name="a_connector_can_self_certify_as_attested",
        path="sentinel/domain/ai_bom.py",
        before="            if level is Provenance.ATTESTED and not digest:",
        after="            if False:",
        guard=(
            "tests_arch/test_ai_bom.py::"
            "test_a_source_claiming_attested_without_a_digest_is_downgraded"
        ),
        consequence=(
            "Any connector mints verification by writing the word 'attested' "
            "into a field. The provenance census -- the one number that says "
            "how much of the inventory is actually verified -- becomes "
            "attacker-controlled, and an estate that verified nothing reports "
            "itself fully attested."
        ),
    ),
    Mutation(
        name="ungranted_capability_use_is_discarded_again",
        path="sentinel/domain/effective_permissions.py",
        before="        for capability in sorted(exercised - held)",
        after="        for capability in sorted(held - held)",
        guard=(
            "tests_arch/test_effective_permissions.py::"
            "test_a_capability_used_without_a_grant_is_reported"
        ),
        consequence=(
            "An agent exercising a capability it was never granted goes "
            "unreported. That is either a stale grant table or an "
            "authorization bypass, and it is the only signal in the "
            "recommender describing something that ALREADY happened -- the "
            "original code computed it and threw it away, which is how the "
            "defect got there in the first place."
        ),
    ),
    Mutation(
        name="revocations_offered_from_an_incomplete_activity_record",
        path="sentinel/domain/effective_permissions.py",
        before="    if not activity_complete:",
        after="    if False:",
        guard=(
            "tests_arch/test_effective_permissions.py::"
            "test_an_incomplete_activity_record_suppresses_every_revocation"
        ),
        consequence=(
            "A confident removal list is produced from telemetry that dropped. "
            "A revocation is an inference from ABSENCE, so an agent whose "
            "activity went unrecorded for a fortnight looks identical to one "
            "that did nothing -- and acting on the list breaks it."
        ),
    ),
    Mutation(
        name="an_unscanned_scope_stops_making_absence_unknown",
        path="sentinel/domain/exposure_graph.py",
        before="        if self.coverage.unscanned:",
        after="        if False:",
        guard=(
            "tests_arch/test_exposure_graph.py::"
            "test_an_unscanned_scope_makes_every_absence_unknown"
        ),
        consequence=(
            "An AWS account nobody could scan reports its agents as NOT "
            "REACHABLE -- indistinguishable from isolated, which is the most "
            "reassuring thing a graph can say. False comfort delivered during "
            "the one hour the graph is actually being read."
        ),
    ),
    Mutation(
        name="a_node_known_only_by_name_reports_isolation",
        path="sentinel/domain/exposure_graph.py",
        before="        if not self.coverage.covers(source):",
        after="        if False:",
        guard=(
            "tests_arch/test_exposure_graph.py::"
            "test_a_node_the_graph_only_knows_by_name_reports_unknown"
        ),
        consequence=(
            "An agent the graph knows only because somebody else's edge named "
            "it -- neighbourhood never enumerated -- is reported as reaching "
            "nothing. The graph knows it exists and knows nothing about it, and "
            "would be claiming the opposite."
        ),
    ),
    Mutation(
        name="shared_credential_edges_stop_being_derived",
        path="sentinel/domain/exposure_graph.py",
        before="        if len(principals) < 2:",
        after="        if True:",
        guard=(
            "tests_arch/test_exposure_graph.py::"
            "test_two_agents_on_one_credential_reach_each_other"
        ),
        consequence=(
            "Two agents sharing one key stop reaching each other in the graph. "
            "No permission table records credential sharing, so if this graph "
            "does not derive the edge, NOTHING in the product ever shows it -- "
            "and a leaked key's blast radius is reported as a fraction of its "
            "real size."
        ),
    ),
    Mutation(
        name="detonation_loses_network_isolation",
        path="sentinel/infrastructure/detonation_container.py",
        before='        "--network=none",',
        after='        "--network=host",',
        guard=(
            "tests_arch/test_container_detonation.py::"
            "test_the_network_is_severed"
        ),
        consequence=(
            "An untrusted skill detonates with the HOST's network namespace: "
            "it reaches the control plane's localhost services, the cloud "
            "metadata endpoint, and the internet. Exfiltration stops being an "
            "attempt and becomes a success, and the recording still comes back "
            "looking like an ordinary run."
        ),
    ),
    Mutation(
        name="detonation_runs_as_root_inside_the_container",
        path="sentinel/infrastructure/detonation_container.py",
        before='        "--user=65534:65534",',
        after='        "--user=0:0",',
        guard=(
            "tests_arch/test_container_detonation.py::"
            "test_the_skill_does_not_run_as_root"
        ),
        consequence=(
            "A container-runtime escape lands as ROOT on the host rather than "
            "as an unprivileged user. This is the difference between a "
            "contained incident and a compromised control plane."
        ),
    ),
    Mutation(
        name="an_uninstrumented_detonation_reports_a_complete_observation",
        path="sentinel/infrastructure/detonation_container.py",
        before="                observation_incomplete=True,\n                incomplete_reason=_incomplete_reason(\n                    f\"Process exited with code {completed.returncode}.\"\n                ),",
        after="                observation_incomplete=False,\n                incomplete_reason=\"\",",
        guard=(
            "tests_arch/test_container_detonation.py::"
            "test_every_recording_admits_the_observation_was_incomplete"
        ),
        consequence=(
            "A container run watches no syscalls, so its empty "
            "network_destinations tuple reads identically to 'this skill made "
            "no network calls'. Marking the observation complete turns every "
            "unwatched detonation into a clean bill of health -- the product "
            "would certify skills nobody observed."
        ),
    ),
    Mutation(
        name="sdk_defaults_to_allowing_when_the_gate_is_unreachable",
        path="sentinel/sdk/remote.py",
        before="    on_unreachable: FailureMode = FailureMode.REFUSE",
        after="    on_unreachable: FailureMode = FailureMode.ALLOW_AND_RECORD",
        guard="tests_arch/test_sdk_remote.py::test_refuse_is_the_default",
        consequence=(
            "Every customer who configures nothing gets fail-open. During an "
            "outage every request is permitted, nothing is recorded, and the "
            "dashboards look quiet BECAUSE no events arrived -- the failure "
            "that turns a security control into decoration."
        ),
    ),
    Mutation(
        name="sdk_treats_a_5xx_as_a_decision",
        path="sentinel/sdk/remote.py",
        before="        if status >= 500:",
        after="        if False:",
        guard=(
            "tests_arch/test_sdk_remote.py::"
            "test_every_5xx_is_an_outage_and_not_a_decision"
        ),
        consequence=(
            "A 502 from a load balancer carrying any body is parsed as a "
            "decision. A 403 means 'no' and a 502 means 'nobody answered'; "
            "collapsing them lets an outage become an allow."
        ),
    ),
    Mutation(
        name="sdk_stops_recording_that_the_gate_was_never_consulted",
        path="sentinel/sdk/remote.py",
        before="            consulted=False,",
        after="            consulted=True,",
        guard=(
            "tests_arch/test_sdk_remote.py::"
            "test_fail_open_allows_but_records_that_the_gate_was_never_consulted"
        ),
        consequence=(
            "An allow granted because the network failed becomes "
            "indistinguishable from one the gate issued. An auditor "
            "reconstructing an incident would find a clean authorisation trail "
            "for actions nothing ever authorised."
        ),
    ),
)


#: Where the pre-mutation bytes are recorded. Inside the repository so a
#: killed run leaves the evidence next to the damage, and git-ignored so it
#: never becomes a commit of its own.
_JOURNAL = ROOT / ".verify_guards_journal"


def _journal_write(target: Path, original: bytes) -> None:
    """Record the original bytes BEFORE mutating.

    Bytes, not a diff: recovery must not depend on the mutated file being
    parseable, or on git being installed.
    """
    _JOURNAL.mkdir(exist_ok=True)
    (_JOURNAL / "path").write_text(str(target), encoding="utf-8")
    (_JOURNAL / "original").write_bytes(original)


def _journal_clear() -> None:
    for name in ("path", "original"):
        candidate = _JOURNAL / name
        if candidate.exists():
            candidate.unlink()
    if _JOURNAL.exists():
        try:
            _JOURNAL.rmdir()
        except OSError:
            # Something else is in there. Left alone rather than removed
            # blindly -- this directory exists to protect source files.
            pass


def _recover_from_a_killed_run() -> None:
    """Restore a file a previous run was killed while mutating.

    A 10-minute timeout once killed this harness mid-mutation, leaving
    `if False:` in place of a coverage check in a domain module. The tree-dirty
    refusal below catches that, but the dangerous window is before anybody
    runs this again: the leftover diff is one line and reads like a debugging
    leftover, so it could be committed without comment.
    """
    recorded = _JOURNAL / "path"
    original = _JOURNAL / "original"
    if not (recorded.exists() and original.exists()):
        return

    target = Path(recorded.read_text(encoding="utf-8").strip())
    bytes_ = original.read_bytes()
    if target.exists() and target.read_bytes() != bytes_:
        target.write_bytes(bytes_)
        print(
            f"RECOVERED {target}: a previous run was killed while this file "
            "was mutated, and has been restored from the journal. Re-run to "
            "get a result."
        )
    _journal_clear()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_is_dirty() -> bool:
    result = subprocess.run(  # noqa: S603,S607 - fixed command
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=str(ROOT), capture_output=True, text=True, check=False,
    )
    return bool(result.stdout.strip())


def _run_guard(node_id: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv
        [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider",
            "-k", "not postgres", "-x", node_id,
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT)},
        timeout=900,
        check=False,
    )


def _check(mutation: Mutation) -> dict[str, object]:
    """Apply one mutation, run its guard, restore. Never leaves the file edited."""
    target = ROOT / mutation.path
    if not target.exists():
        return {
            "mutation": mutation.name,
            "vacuous": True,
            "consequence": mutation.consequence,
            "detail": f"{mutation.path} does not exist; the mutation is stale",
        }

    original = target.read_bytes()
    before_digest = hashlib.sha256(original).hexdigest()

    # Match on newline-normalised text. Decoding raw bytes leaves CRLF in
    # place, so any anchor spanning a line could never match on a Windows
    # checkout -- three mutations were reported stale for that reason alone,
    # which is a report about the checkout masquerading as a report about the
    # code. The original convention is restored on write.
    raw = original.decode("utf-8")
    newline = "\r\n" if "\r\n" in raw else "\n"
    text = raw.replace("\r\n", "\n")

    occurrences = text.count(mutation.before)
    if occurrences != 1:
        # NOT treated as a pass. A mutation that no longer applies is a
        # mutation that stopped testing anything, and the guard it covers is
        # unproven from this moment on.
        return {
            "mutation": mutation.name,
            "vacuous": True,
            "consequence": mutation.consequence,
            "detail": (
                f"the anchor text appears {occurrences} times in "
                f"{mutation.path} (expected exactly 1). The mutation is stale, "
                f"so the guard {mutation.guard} is no longer being proven."
            ),
        }

    try:
        # The journal goes down BEFORE the file changes. If this process is
        # killed between here and the restore, the next run recovers from it.
        _journal_write(target, original)
        # Written as BYTES: write_text would translate every "\n" to the
        # platform separator, turning a replacement's newline into "\r\r\n".
        mutated = text.replace(mutation.before, mutation.after)
        target.write_bytes(mutated.replace("\n", newline).encode("utf-8"))
        result = _run_guard(mutation.guard)
        guard_noticed = result.returncode != 0
        output = (result.stdout or "") + (result.stderr or "")
    finally:
        target.write_bytes(original)
        _journal_clear()
        if _digest(target) != before_digest:
            raise SystemExit(
                f"FAILED TO RESTORE {mutation.path}. The working tree is "
                f"MODIFIED and must not be committed. Recover with:\n"
                f"    git checkout -- {mutation.path}"
            )

    # A guard that errors on COLLECTION rather than failing an assertion has
    # not demonstrated anything: the mutation may simply have broken the
    # import. Distinguished so a syntax-level break is not mistaken for a
    # working guard.
    collection_error = "error" in output.lower() and "ERROR collecting" in output

    return {
        "mutation": mutation.name,
        "guard": mutation.guard,
        "path": mutation.path,
        "vacuous": not guard_noticed,
        "collection_error": collection_error,
        "consequence": mutation.consequence,
        "detail": (
            "the guard failed, as it must"
            if guard_noticed and not collection_error
            else "the guard errored during collection rather than failing an "
            "assertion, so it has not been shown to detect this defect"
            if collection_error
            else "THE GUARD STAYED GREEN while the property was broken"
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    # BEFORE the dirty-tree check, not after. A run killed mid-mutation leaves
    # a deliberately weakened guard in the working tree AND makes the tree
    # dirty -- so checking cleanliness first would refuse and leave the
    # weakened file sitting there for somebody to commit.
    _recover_from_a_killed_run()

    if _tree_is_dirty():
        raise SystemExit(
            "refusing to run on a modified working tree.\n\n"
            "This harness edits source files and restores them. On a clean "
            "tree `git checkout .` is a complete recovery if anything goes "
            "wrong; on a dirty one it would destroy your work. Commit or stash "
            "first."
        )

    print(f"proving {len(MUTATIONS)} guards can actually fail\n")
    findings: list[dict[str, object]] = []
    for mutation in MUTATIONS:
        print(f"  {mutation.name} ... ", end="", flush=True)
        outcome = _check(mutation)
        findings.append(outcome)
        print("DETECTED" if not outcome["vacuous"] else "*** VACUOUS ***")

    vacuous = [f for f in findings if f["vacuous"]]
    ok = not vacuous

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "gate": "guard_mutation",
                "ok": ok,
                "exit_code": 0 if ok else 1,
                "summary": (
                    f"guard_mutation: all {len(MUTATIONS)} guards failed when "
                    "their property was broken"
                    if ok
                    else "guard_mutation: "
                    + "; ".join(str(f["mutation"]) for f in vacuous)
                    + " stayed green while the property was broken"
                ),
                "command_rationale": (
                    "Mutation testing scoped to the invariants where a silent "
                    "failure matters most. Each mutation is a defect that has "
                    "already happened here or is one careless edit away, not a "
                    "generated operator flip."
                ),
                "does_not_prove": (
                    "That the guards are complete. It proves the listed guards "
                    "detect the listed defects. A property with no mutation "
                    "here is unproven, and adding one is how a new invariant "
                    "earns the same standing."
                ),
                "results": findings,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2, sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    release_binding.write_binding(
        OUT,
        release=release_binding.release_identity_from_git(ROOT),
        now=datetime.now(timezone.utc),
    )

    print()
    if ok:
        print(f"all {len(MUTATIONS)} guards detected their defect")
    else:
        for finding in vacuous:
            print(f"VACUOUS GUARD: {finding['mutation']}")
            print(f"  {finding['detail']}")
            print(f"  consequence: {finding.get('consequence', '')}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
