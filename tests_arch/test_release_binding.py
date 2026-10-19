"""Release evidence must belong to the release. Nothing did, before this.

WHAT WAS WRONG
--------------
`build_release_evidence.py` marked a gate PASS when a named file existed and
parsed. Nothing checked WHICH BUILD produced it — so an artifact from another
commit, another image, or last month all passed, and a fully green bundle could
be assembled from a directory of stale files.

Twenty-one PASS rows, every one a real file, none of them about the release
being cut. That is the most convincing kind of wrong, and it is the technical
credibility blocker Phase 1 exists to close.

WHY THESE TESTS ARE MOSTLY ABOUT REFUSAL
------------------------------------------
Every test below asserts that something is NOT accepted. That is the shape of
the control: the failure mode is a bundle that looks better than the truth, so
the tests are the ones that stop it looking better than the truth.

`test_no_configuration_can_turn_a_mismatch_into_a_pass` is the one that matters
most. A gate that can be argued into passing is a gate that will be, at 2am, by
somebody who needs the release out.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.release_binding import (
    DEFAULT_MAX_AGE,
    PROVENANCE_SUFFIX,
    ArtifactBinding,
    Binding,
    ReleaseIdentity,
    gate_set_digest,
    read_binding,
    source_tree_digest,
    verify,
)

NOW = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
COMMIT = "b63e11d659c8375f51a685129a9001effe88875f"
TREE = "ca0063a803ad3acf" + "0" * 48
IMAGE = "sha256:" + "ab" * 32

RELEASE = ReleaseIdentity(
    commit=COMMIT, source_tree_sha256=TREE, image_digest=IMAGE
)


def _artifact(
    tmp_path: Path,
    *,
    commit: str = COMMIT,
    tree: str = TREE,
    image: str = IMAGE,
    stamped: datetime | None = None,
    sidecar: bool = True,
) -> Path:
    artifact = tmp_path / "metrics.json"
    artifact.write_text(json.dumps({"f1": 0.91}), encoding="utf-8")
    if sidecar:
        (tmp_path / ("metrics.json" + PROVENANCE_SUFFIX)).write_text(
            json.dumps(
                ArtifactBinding(
                    commit=commit,
                    source_tree_sha256=tree,
                    image_digest=image,
                    generated_at=stamped or NOW - timedelta(minutes=5),
                ).as_dict()
            ),
            encoding="utf-8",
        )
    return artifact


# ── the four rejections Phase 1 names ────────────────────────────────────────


def test_an_artifact_from_another_commit_is_rejected(tmp_path):
    assert verify(
        _artifact(tmp_path, commit="0" * 40), release=RELEASE, now=NOW
    ) is Binding.WRONG_COMMIT


def test_an_artifact_from_another_image_digest_is_rejected(tmp_path):
    assert verify(
        _artifact(tmp_path, image="sha256:" + "cd" * 32), release=RELEASE, now=NOW
    ) is Binding.WRONG_IMAGE


def test_stale_evidence_is_rejected(tmp_path):
    stale = NOW - DEFAULT_MAX_AGE - timedelta(minutes=1)
    assert verify(
        _artifact(tmp_path, stamped=stale), release=RELEASE, now=NOW
    ) is Binding.STALE


def test_an_unbound_artifact_is_not_a_pass(tmp_path):
    """THE change that most improves the bundle's truthfulness. An artifact with
    no provenance is not "probably fine" — its origin was never recorded, and
    that is the same epistemic state as an artifact that does not exist.
    """
    verdict = verify(_artifact(tmp_path, sidecar=False), release=RELEASE, now=NOW)
    assert verdict is Binding.UNBOUND
    assert not verdict.is_bound


# ── the tree digest, which is what catches a modified checkout ────────────────


def test_the_same_commit_with_a_modified_tree_is_rejected(tmp_path):
    """A commit SHA does not describe a working tree. Somebody who edits a file
    after checkout and runs the tests has produced evidence about code that is
    in no commit at all.
    """
    assert verify(
        _artifact(tmp_path, tree="f" * 64), release=RELEASE, now=NOW
    ) is Binding.WRONG_TREE


def test_the_tree_digest_covers_paths_not_only_contents(tmp_path):
    """Renaming a file — moving a permissive policy over a strict one — must
    change the digest. Hashing contents alone would not notice.
    """
    root = tmp_path
    (root / "a.py").write_text("STRICT", encoding="utf-8")
    (root / "b.py").write_text("LOOSE", encoding="utf-8")
    before = source_tree_digest([root / "a.py", root / "b.py"], root=root)

    (root / "a.py").write_text("LOOSE", encoding="utf-8")
    (root / "b.py").write_text("STRICT", encoding="utf-8")
    after = source_tree_digest([root / "a.py", root / "b.py"], root=root)

    assert before != after, "swapping two files' contents produced the same digest"


# ── nothing can upgrade a verdict ────────────────────────────────────────────


def test_no_configuration_can_turn_a_mismatch_into_a_pass(tmp_path):
    """THE test. `verify` takes an artifact, a release identity and a clock.
    There is no override parameter, no environment variable and no force flag —
    a gate that can be argued into passing is a gate that will be.
    """
    import ast
    import inspect

    from scripts import release_binding

    signature = inspect.signature(release_binding.verify)
    assert set(signature.parameters) == {"artifact", "release", "now", "max_age"}

    # Scanned as CODE, not as text, and scoped to the DECISION functions.
    #
    # Two corrections to a cruder first version. It searched raw source, so it
    # matched "no override argument" in the docstring that PROMISES the property
    # — the same trap the console-bundle tests hit. And it banned `os.environ`
    # module-wide, which failed on the CLI: only CI knows the image digest it
    # built, so `_release_identity` legitimately reads one.
    #
    # The rule that actually matters is narrower: nothing that COMPUTES A
    # VERDICT may consult ambient state. Constructing the release identity from
    # the environment is fine, because a wrong value there makes artifacts stop
    # binding — it fails loudly and cannot upgrade anything.
    tree = ast.parse(inspect.getsource(release_binding))
    deciders = {"verify", "read_binding", "gate_set_digest", "source_tree_digest"}

    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name in deciders):
            continue
        body = ast.Module(body=list(node.body), type_ignores=[])
        for inner in ast.walk(body):
            if isinstance(inner, ast.Expr) and isinstance(inner.value, ast.Constant):
                inner.value.value = ""  # a docstring is not an escape hatch
        names = {n.id for n in ast.walk(body) if isinstance(n, ast.Name)} | {
            n.attr for n in ast.walk(body) if isinstance(n, ast.Attribute)
        }
        for escape in ("environ", "getenv", "force", "override", "skip", "allow_any"):
            assert escape not in names, (
                f"{node.name} consults {escape!r}; a verdict must come from the "
                "artifact and the release identity, nothing else"
            )


def test_the_image_digest_environment_variable_cannot_upgrade_a_verdict(
    tmp_path, monkeypatch
):
    """`SENTINEL_RELEASE_IMAGE_DIGEST` is a FACT about the release, not a knob.

    Whatever it is set to, an artifact stamped with a different digest is
    WRONG_IMAGE. There is no value — empty, wildcard, or the artifact's own —
    that a caller can set to make a mismatched artifact bind, because `verify`
    never reads it: it reads the identity the caller already constructed.
    """
    artifact = _artifact(tmp_path, image="sha256:" + "99" * 32)
    for attempt in ("", "*", "any", "sha256:" + "ab" * 32):
        monkeypatch.setenv("SENTINEL_RELEASE_IMAGE_DIGEST", attempt)
        assert verify(artifact, release=RELEASE, now=NOW) is Binding.WRONG_IMAGE


def test_a_release_identity_cannot_be_built_without_something_to_bind_to():
    """An empty commit or tree digest would make every artifact match."""
    with pytest.raises(ValueError, match="binds nothing"):
        ReleaseIdentity(commit="", source_tree_sha256=TREE)
    with pytest.raises(ValueError, match="binds nothing"):
        ReleaseIdentity(commit=COMMIT, source_tree_sha256="")


# ── required gates cannot silently disappear ─────────────────────────────────


def test_removing_a_required_gate_changes_the_pinned_digest():
    """Deleting a row from REQUIRED_GATES to make a bundle look complete must
    be a visible, deliberate act with a diff — not a quiet edit.
    """
    full = ("lint", "sast", "sbom", "dast")
    assert gate_set_digest(full) != gate_set_digest(full[:-1])


def test_reordering_gates_is_not_tampering():
    """The SET is what matters. Reordering for readability must not read as a
    removal, or the pin becomes noise somebody re-pins on every edit.
    """
    assert gate_set_digest(("a", "b", "c")) == gate_set_digest(("c", "a", "b"))


# ── malformed vs absent, which need different responses ──────────────────────


def test_a_malformed_sidecar_is_distinguished_from_a_missing_one(tmp_path):
    """UNBOUND means a CI job is not writing provenance. MALFORMED means one is
    writing it wrongly. Those get fixed in different places.
    """
    artifact = tmp_path / "metrics.json"
    artifact.write_text("{}", encoding="utf-8")
    (tmp_path / ("metrics.json" + PROVENANCE_SUFFIX)).write_text(
        "not json at all", encoding="utf-8"
    )
    assert verify(artifact, release=RELEASE, now=NOW) is Binding.MALFORMED
    assert read_binding(artifact)[1] is Binding.MALFORMED


def test_a_sidecar_missing_a_required_field_is_malformed(tmp_path):
    artifact = tmp_path / "metrics.json"
    artifact.write_text("{}", encoding="utf-8")
    (tmp_path / ("metrics.json" + PROVENANCE_SUFFIX)).write_text(
        json.dumps({"commit": COMMIT}), encoding="utf-8"
    )
    assert verify(artifact, release=RELEASE, now=NOW) is Binding.MALFORMED


def test_a_naive_timestamp_is_malformed_rather_than_assumed(tmp_path):
    """Comparing a zone-less timestamp to a UTC one means assuming a zone, and
    assuming is how an artifact from a different day passes an age check.
    """
    artifact = tmp_path / "metrics.json"
    artifact.write_text("{}", encoding="utf-8")
    (tmp_path / ("metrics.json" + PROVENANCE_SUFFIX)).write_text(
        json.dumps(
            {
                "commit": COMMIT,
                "source_tree_sha256": TREE,
                "image_digest": IMAGE,
                "generated_at": "2026-08-31T12:00:00",
            }
        ),
        encoding="utf-8",
    )
    assert verify(artifact, release=RELEASE, now=NOW) is Binding.MALFORMED


def test_an_artifact_from_the_future_is_stale_not_fresh(tmp_path):
    """Clock skew beyond a few minutes means producer and checker disagree about
    time, and an age check between them proves nothing.
    """
    assert verify(
        _artifact(tmp_path, stamped=NOW + timedelta(hours=3)),
        release=RELEASE,
        now=NOW,
    ) is Binding.STALE


def test_small_forward_skew_is_tolerated(tmp_path):
    """Refusing a two-minute skew would fail honest builds on ordinary drift."""
    assert verify(
        _artifact(tmp_path, stamped=NOW + timedelta(minutes=2)),
        release=RELEASE,
        now=NOW,
    ) is Binding.BOUND


# ── the image check when there is no image ───────────────────────────────────


def test_an_artifact_naming_an_image_a_release_did_not_build_is_rejected(tmp_path):
    """`image_digest == ""` means the release built no container. An artifact
    claiming one came from a different build, so it is a mismatch — not a pass
    by absence.
    """
    imageless = ReleaseIdentity(commit=COMMIT, source_tree_sha256=TREE)
    assert verify(
        _artifact(tmp_path), release=imageless, now=NOW
    ) is Binding.WRONG_IMAGE


def test_a_matching_imageless_artifact_binds(tmp_path):
    imageless = ReleaseIdentity(commit=COMMIT, source_tree_sha256=TREE)
    assert verify(
        _artifact(tmp_path, image=""), release=imageless, now=NOW
    ) is Binding.BOUND


# ── the happy path, last, because it is the least interesting ────────────────


def test_a_correctly_bound_artifact_binds(tmp_path):
    assert verify(_artifact(tmp_path), release=RELEASE, now=NOW) is Binding.BOUND


def test_every_verdict_carries_a_reason_a_human_can_act_on():
    """A verdict of `wrong_tree` with no explanation sends somebody to read this
    module. The reason belongs in the output.
    """
    for verdict in Binding:
        assert verdict.reason, f"{verdict} has no reason"
        assert len(verdict.reason) > 20, f"{verdict}'s reason explains nothing"


# ── the gate set is pinned, so a gate cannot quietly vanish ──────────────────

#: Pinned digests over the gate NAME SETS. Changing either is a deliberate act
#: with a diff and a reviewer, which is the only way a release gate should ever
#: be added or removed.
#:
#: If you are here because this test failed: do not re-pin to make it pass. Work
#: out which gate changed and whether that was intended. Re-pinning a removed
#: gate is how twenty-one gates becomes twenty and nobody notices.
#: Re-pinned once, deliberately, when Phase 2 added `performance_targets`.
#: The previous value was 456c2e9a…, and it changed because a gate was ADDED --
#: which is the event this pin exists to surface, working as intended.
REQUIRED_GATES_DIGEST = (
    "996046dd10a165eafaa642873563080a613664edd46e9d9b1791b0e5f9396adc"
)
GA_GATES_DIGEST = "0077fb1d80d3a73f2b4567f24c705896451365f6215968ded2487ea346bd2856"


def test_the_required_gate_set_has_not_changed():
    from scripts.build_release_evidence import REQUIRED_GATES

    assert gate_set_digest(REQUIRED_GATES) == REQUIRED_GATES_DIGEST, (
        "the required gate set changed. Do NOT re-pin to make this pass: work "
        "out which gate was added or removed and whether that was intended."
    )
    assert len(REQUIRED_GATES) == 22


def test_the_ga_gate_set_has_not_changed():
    from scripts.build_release_evidence import GA_GATES

    assert gate_set_digest(tuple(GA_GATES)) == GA_GATES_DIGEST
    assert len(GA_GATES) == 4


def test_no_ga_gate_can_ever_be_written_pass_by_the_builder():
    """The four external gates accrue from operating the product — a calendar, a
    contract, a third party. A build that could mark one PASS would be
    fabricating exactly the evidence the non-negotiable rules forbid.
    """
    import inspect

    from scripts import build_release_evidence

    source = inspect.getsource(build_release_evidence.collect)
    ga_block = source.split("for name in REQUIRED_GATES")[0]
    assert "GA_GATES" in ga_block
    assert "status=UNVERIFIED" in ga_block.replace(" ", "")
    assert "PASS" not in ga_block.split("GA_GATES")[1]


def test_an_unbound_artifact_downgrades_a_gate_that_used_to_pass(tmp_path):
    """The Phase 1 change, asserted end to end: a readable artifact with no
    provenance is UNVERIFIED, where the previous builder reported PASS.
    """
    from scripts import build_release_evidence as evidence

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "metrics.json").write_text(json.dumps({"f1": 0.9}), encoding="utf-8")

    bundle = evidence.collect(artifacts)
    detection = next(g for g in bundle.gates if g.name == "detection_evaluation")
    assert detection.status == evidence.UNVERIFIED
    assert detection.binding == "unbound"


# ── the one gate that reads what its artifact SAYS ───────────────────────────


def _bench(tmp_path: Path, *, p50=1.0, p95=2.0, p99=3.0) -> Path:
    """A benchmark artifact, bound to whatever release the caller checks with."""
    path = tmp_path / "authorization_bench.json"
    path.write_text(
        json.dumps(
            {
                "measurement": {
                    "overall": {"p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "n": 2000}
                },
                "environment": {"platform": "test-machine"},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_a_benchmark_over_target_fails_rather_than_passing_on_existence(tmp_path):
    """THE reason this gate reads content. A benchmark that ran successfully and
    reported a p99 over the target is a job that SUCCEEDED and a release that
    should not ship. Treating its existence as PASS is the Phase 1 defect one
    level up.
    """
    from scripts.build_release_evidence import FAIL, _judge

    status, detail = _judge("performance_targets", _bench(tmp_path, p99=5000.0))
    assert status == FAIL
    assert "over target" in detail


def test_a_benchmark_within_target_passes_and_names_the_machine(tmp_path):
    """A latency without a machine invites somebody to quote it about a
    different one.
    """
    from scripts.build_release_evidence import PASS, _judge

    status, detail = _judge("performance_targets", _bench(tmp_path))
    assert status == PASS
    assert "test-machine" in detail
    assert "no HTTP" in detail


def test_a_malformed_benchmark_is_unverified_not_passed(tmp_path):
    from scripts.build_release_evidence import UNVERIFIED, _judge

    path = tmp_path / "authorization_bench.json"
    path.write_text(json.dumps({"nothing": "useful"}), encoding="utf-8")
    status, _ = _judge("performance_targets", path)
    assert status == UNVERIFIED


def test_targets_come_from_configuration_not_from_the_gate():
    """A number hardcoded in a gate is one nobody can argue with when it is
    wrong, and an acceptable latency is a deployment decision.
    """
    import inspect

    from scripts import build_release_evidence

    source = inspect.getsource(build_release_evidence._judge)
    assert "performance_targets.json" in source
    for literal in ("50.0", "100.0", "50 ", "100 "):
        assert literal not in source, f"a target leaked into the gate: {literal!r}"
