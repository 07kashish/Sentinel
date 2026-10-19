"""Phase 1: evidence must belong to THIS build, or it is not evidence.

THE DEFECT THIS CLOSES
----------------------
`build_release_evidence.py` marked a gate PASS when a named file existed and
parsed. Nothing checked which build produced it. So:

  * an artifact from a DIFFERENT COMMIT passed;
  * an artifact from a different container image passed;
  * an artifact from last month passed;
  * a green bundle could be assembled from a directory of stale files.

That is the most convincing kind of wrong: twenty-one PASS rows, every one of
them a real file, none of them about the release being cut. A release gate that
cannot tell whose evidence it is holding is decoration.

THE RULE
--------
An artifact must CARRY its provenance -- the commit, the source-tree digest, the
image digest and when it was produced -- and every one of those must match the
release being assembled. Anything else is UNVERIFIED.

UNBOUND IS UNVERIFIED, NOT PASS
-------------------------------
An artifact with no provenance sidecar is not "probably fine". It is an artifact
whose origin nobody recorded, and the honest status for it is the same as for
one that does not exist: UNVERIFIED. This is the single change that most
improves the bundle's truthfulness, and it will make existing bundles LOOK
WORSE, which is the point.

NOTHING HERE CAN UPGRADE A STATUS
---------------------------------
`verify` returns a verdict computed from the artifact and the release identity.
There is no configuration parameter, no environment variable and no override
argument that turns a mismatch into a match -- `test_no_configuration_can_turn_a
_mismatch_into_a_pass` holds that. A gate that can be argued into passing is a
gate that will be, at 2am, by someone who needs the release out.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "DEFAULT_MAX_AGE",
    "PROVENANCE_SUFFIX",
    "release_identity_from_git",
    "ArtifactBinding",
    "Binding",
    "ReleaseIdentity",
    "gate_set_digest",
    "read_binding",
    "source_tree_digest",
    "verify",
]

#: The sidecar an artifact-producing job must write next to its artifact.
#: `metrics.json` -> `metrics.json.provenance.json`.
#:
#: A SIDECAR rather than a field inside the artifact, because most artifacts are
#: third-party formats -- CycloneDX, junit, a cosign signature -- and this
#: project does not get to add fields to them. A sidecar works for every format
#: including the ones that are not JSON at all.
PROVENANCE_SUFFIX = ".provenance.json"

#: How old evidence may be and still describe this build. Deliberately short:
#: CI produces every artifact within one workflow run, so anything older than a
#: few hours came from a different run and the commit check may not catch it
#: (a re-run of the same commit produces a different BUILD with the same SHA).
DEFAULT_MAX_AGE = timedelta(hours=12)


class Binding(str, Enum):
    """Why an artifact does or does not belong to this release."""

    BOUND = "bound"
    UNBOUND = "unbound"
    WRONG_COMMIT = "wrong_commit"
    WRONG_TREE = "wrong_tree"
    WRONG_IMAGE = "wrong_image"
    STALE = "stale"
    MALFORMED = "malformed"

    @property
    def is_bound(self) -> bool:
        return self is Binding.BOUND

    @property
    def reason(self) -> str:
        return _REASONS[self]


_REASONS: Mapping["Binding", str] = {
    Binding.BOUND: "provenance matches this release",
    Binding.UNBOUND: (
        "no provenance sidecar: the job that produced this artifact did not "
        "record which build it came from, so nothing connects it to this release"
    ),
    Binding.WRONG_COMMIT: "produced from a different commit",
    Binding.WRONG_TREE: (
        "same commit, different source tree -- the working tree was modified "
        "after the commit this release claims"
    ),
    Binding.WRONG_IMAGE: "produced against a different container image digest",
    Binding.STALE: "older than this release permits; it describes an earlier run",
    Binding.MALFORMED: "provenance sidecar exists but could not be read",
}


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    """What this release IS. Every artifact is checked against it.

    `image_digest` is empty when the release has no container. An empty digest
    means the image check is NOT APPLICABLE, never that it passed -- an artifact
    claiming an image digest when the release has none is still a mismatch,
    because it was produced against something this release did not build.
    """

    commit: str
    source_tree_sha256: str
    image_digest: str = ""

    def __post_init__(self) -> None:
        if not self.commit.strip():
            raise ValueError("a release identity without a commit binds nothing")
        if not self.source_tree_sha256.strip():
            raise ValueError("a release identity without a tree digest binds nothing")


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    """What an artifact claims about the build that produced it."""

    commit: str
    source_tree_sha256: str
    generated_at: datetime
    image_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "source_tree_sha256": self.source_tree_sha256,
            "image_digest": self.image_digest,
            "generated_at": self.generated_at.isoformat(),
        }


def release_identity_from_git(root: Path) -> "ReleaseIdentity":
    """This build's identity, with the commit read from the workspace.

    Every producer needs the same three lines to stamp its output, and three
    lines copied into four scripts is four places to get the commit wrong.
    There is deliberately no `commit` argument: an operator who can type the
    commit can type the wrong one, which is the forgery this mechanism exists
    to make hard.
    """
    import subprocess

    head = subprocess.run(  # noqa: S603,S607 - fixed command
        ["git", "rev-parse", "HEAD"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    commit = head.stdout.strip()
    if not commit:
        raise RuntimeError(
            "cannot determine HEAD. An artifact that cannot name the commit it "
            "came from is unbound evidence, which the release report treats as "
            "UNVERIFIED -- so refusing here reaches the same verdict before "
            "writing a misleading file."
        )
    return release_identity(commit, root=root)


def release_identity(commit: str, *, root: Path) -> "ReleaseIdentity":
    """What a release IS, computed one way for every producer and every reader.

    THIS FUNCTION EXISTS BECAUSE TWO COPIES OF IT WOULD BE SILENT
    ---------------------------------------------------------------
    A gate runner that stamps artifacts and a report generator that verifies
    them must agree on the tree digest to the byte. When they disagreed, every
    artifact came back UNBOUND -- and UNBOUND is reported as UNVERIFIED, which
    is the same word used for a gate nobody ran. So a one-line divergence in how
    the file list is built would present as "we never checked" across the whole
    report, with nothing pointing at the cause.

    The digest covers the working tree rather than the commit, deliberately: a
    commit SHA does not describe a checkout, and evidence produced against a
    modified tree is evidence about code that is in no commit at all.

    `SENTINEL_RELEASE_IMAGE_DIGEST` is read from the environment because only CI
    knows what it built. It is a fact about the release, NOT a control knob --
    setting it wrongly makes artifacts stop binding, which fails loudly rather
    than passing quietly.
    """
    source = [
        p
        for p in sorted((root / "sentinel").rglob("*.py"))
        if "__pycache__" not in p.parts
    ]
    return ReleaseIdentity(
        commit=commit,
        source_tree_sha256=source_tree_digest(source, root=root),
        image_digest=os.environ.get("SENTINEL_RELEASE_IMAGE_DIGEST", ""),
    )


def source_tree_digest(paths: list[Path], *, root: Path) -> str:
    """One digest over a set of files, path-sorted and path-included.

    The path is hashed as well as the bytes. Without it, renaming a file --
    moving a permissive policy over a strict one, say -- produces an identical
    digest, and the whole point is to notice that the tree changed.
    """
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(root)).replace("\\", "/").encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def gate_set_digest(gates: tuple[str, ...]) -> str:
    """A digest over the REQUIRED GATE NAMES.

    Pinned so a gate cannot silently disappear. Deleting a row from
    `REQUIRED_GATES` to make a bundle look complete changes this digest, and the
    test that pins it fails -- so removing a gate becomes a visible, deliberate
    act with a diff, which is the only way that decision should ever be made.

    Order-independent: the set is what matters, not the listing order, so
    reordering for readability does not read as tampering.
    """
    return hashlib.sha256("\n".join(sorted(gates)).encode()).hexdigest()


def read_binding(artifact: Path) -> tuple[ArtifactBinding | None, Binding]:
    """Read an artifact's provenance sidecar.

    Returns `(None, UNBOUND)` when there is no sidecar and `(None, MALFORMED)`
    when there is one that cannot be read. The two are reported separately
    because they need different responses: UNBOUND means a CI job is not
    writing provenance, MALFORMED means one is writing it wrongly.
    """
    sidecar = artifact.with_name(artifact.name + PROVENANCE_SUFFIX)
    if not sidecar.is_file():
        return None, Binding.UNBOUND
    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8"))
        return (
            ArtifactBinding(
                commit=str(payload["commit"]),
                source_tree_sha256=str(payload["source_tree_sha256"]),
                image_digest=str(payload.get("image_digest", "")),
                generated_at=datetime.fromisoformat(str(payload["generated_at"])),
            ),
            Binding.BOUND,
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None, Binding.MALFORMED


def verify(
    artifact: Path,
    *,
    release: ReleaseIdentity,
    now: datetime,
    max_age: timedelta = DEFAULT_MAX_AGE,
) -> Binding:
    """Does this artifact belong to this release?

    Checks are ordered most-specific first so the verdict names the most useful
    thing that is wrong. A wrong commit AND a stale timestamp reports
    WRONG_COMMIT, because that is the finding somebody has to act on.
    """
    binding, status = read_binding(artifact)
    if binding is None:
        return status

    if binding.commit != release.commit:
        return Binding.WRONG_COMMIT
    if binding.source_tree_sha256 != release.source_tree_sha256:
        return Binding.WRONG_TREE
    # An artifact claiming an image this release did not build is a mismatch,
    # not a pass. `release.image_digest == ""` means the release built no
    # container, so an artifact naming one came from a different build.
    if binding.image_digest != release.image_digest:
        return Binding.WRONG_IMAGE

    stamped = binding.generated_at
    if stamped.tzinfo is None:
        # A naive timestamp cannot be compared to a UTC one without assuming a
        # zone, and assuming is how an artifact from a different day passes an
        # age check. Treated as malformed rather than guessed at.
        return Binding.MALFORMED
    if stamped > now + timedelta(minutes=5):
        # From the future. Clock skew beyond a few minutes means the producer
        # and this checker disagree about time, and an age check between them
        # proves nothing.
        return Binding.STALE
    if now - stamped > max_age:
        return Binding.STALE

    return Binding.BOUND


def write_binding(
    artifact: Path, *, release: ReleaseIdentity, now: datetime
) -> Path:
    """Stamp an artifact with the build that produced it.

    Called by the CI job that PRODUCES an artifact, immediately after producing
    it. Stamping anywhere else -- a later job, a cleanup step, a human -- would
    let a sidecar claim a build the artifact did not come from, which is the
    forgery this whole mechanism is supposed to make hard.

    There is deliberately no `--commit` argument on the CLI below: the commit is
    read from git in the workspace that built the thing. An operator who can
    type the commit can type the wrong one.
    """
    sidecar = artifact.with_name(artifact.name + PROVENANCE_SUFFIX)
    sidecar.write_text(
        json.dumps(
            ArtifactBinding(
                commit=release.commit,
                source_tree_sha256=release.source_tree_sha256,
                image_digest=release.image_digest,
                generated_at=now,
            ).as_dict(),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return sidecar


def _cli(argv: list[str] | None = None) -> int:
    """`stamp` an artifact, or `check` one. Nothing else.

    Kept to two verbs because this is a mechanism CI calls, not a tool an
    operator explores. Every additional verb is another way to produce a
    sidecar that says something the build did not.
    """
    import argparse
    import os
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Bind release artifacts to a build.")
    parser.add_argument("verb", choices=("stamp", "check"))
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args(argv)

    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not commit:
        print("no git commit is resolvable here; refusing to stamp", file=sys.stderr)
        return 1

    source = [
        p for p in sorted((root / "sentinel").rglob("*.py")) if "__pycache__" not in p.parts
    ]
    identity = ReleaseIdentity(
        commit=commit,
        source_tree_sha256=source_tree_digest(source, root=root),
        image_digest=os.environ.get("SENTINEL_RELEASE_IMAGE_DIGEST", ""),
    )
    now = datetime.now(timezone.utc)

    if not args.artifact.is_file():
        print(f"{args.artifact} is not a file", file=sys.stderr)
        return 1

    if args.verb == "stamp":
        written = write_binding(args.artifact, release=identity, now=now)
        print(f"stamped {args.artifact.name} -> {written.name}")
        print(f"  commit {commit[:12]}  tree {identity.source_tree_sha256[:12]}")
        return 0

    verdict = verify(args.artifact, release=identity, now=now)
    print(f"{args.artifact.name}: {verdict.value} — {verdict.reason}")
    return 0 if verdict.is_bound else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
