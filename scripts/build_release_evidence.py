#!/usr/bin/env python3
"""Assemble the release evidence bundle from artifacts that actually exist.

    §8  Stop maintaining contradictory readiness facts manually.
        Create an automated release evidence pipeline.

THE ONE RULE THIS SCRIPT ENFORCES
-----------------------------------
**It never invents a fact.** Every field is either read from a real artifact
produced by a real run, or reported as `UNVERIFIED` with the reason it is
missing. There is no default, no placeholder, and no "assume it passed".

That rule is the entire point. Readiness documents in this repository have
contradicted each other before -- proprietary against ISC, production-ready
against pre-production -- because they were maintained by hand and each was
written by someone who knew a different subset of the truth. A generated
document cannot drift from the artifacts, because it has nothing else to say.

WHY `UNVERIFIED` IS A FIRST-CLASS OUTCOME, NOT A FAILURE
----------------------------------------------------------
A release bundle that refuses to emit unless everything passed would simply not
be run, and the hand-written document would come back. So this emits a bundle
whenever it is asked to, and the bundle states plainly which gates were proven
and which were not.

`readiness.json` therefore has three states per gate, and the difference between
the last two is the one people get wrong:

    PASS        an artifact exists and records success
    FAIL        an artifact exists and records failure
    UNVERIFIED  no artifact -- WE DO NOT KNOW

"UNVERIFIED" is not "probably fine". A reader must be able to tell
"we tested this and it worked" from "nobody ran it", and a bundle that blurs
those is worse than no bundle, because it launders absence into assurance.

WHAT THIS DELIBERATELY DOES NOT DO
------------------------------------
It does not run the tests. Generating evidence and producing it must be separate
programs, or the thing being measured is also the thing reporting the
measurement. CI runs the gates and drops artifacts; this reads them.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from types import MappingProxyType
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Any

# Runnable as `python scripts/build_release_evidence.py` from the repository
# root, which is how CI invokes it. Without this the `scripts` package is not
# importable and the release-evidence job died on its first import -- the
# same bootstrap `build_sbom_and_licenses.py` already carries.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import release_binding  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

#: Gate outcomes. Ordered worst-first so a summary can report the floor.
FAIL = "FAIL"
UNVERIFIED = "UNVERIFIED"
PASS = "PASS"

#: Gates §8 and §10 require a release to account for.
#:
#: Present in this list and absent from the artifacts means UNVERIFIED, which is
#: the honest answer and the one that makes a missing gate visible. Removing a
#: row here to make a bundle look better is the failure mode this list exists to
#: make obvious in a diff.
REQUIRED_GATES: tuple[str, ...] = (
    "lint",
    "type_check",
    "unit_tests",
    "postgres_tests",
    "redis_tests",
    "architecture_tests",
    "security_tests",
    "chaos_tests",
    "detection_evaluation",
    "migration_tests",
    "container_build",
    "kubernetes_helm",
    "dast",
    "sast",
    "secret_scanning",
    "dependency_scanning",
    "container_scanning",
    "sbom",
    "license_scan",
    "production_preflight",
    "artifact_signing",
    # Phase 2. Added deliberately, which is why the pinned gate-set digest in
    # `test_release_binding.py` had to change with it: a gate appearing or
    # disappearing is exactly the event that pin exists to make visible.
    "performance_targets",
)


#: The GA gates from specification section 105, and the reason each one cannot
#: be satisfied by a build.
#:
#: WHY THEY ARE LISTED HERE RATHER THAN LEFT OUT
#: ----------------------------------------------
#: Every gate above is a thing CI can produce an artifact for, so the best tier
#: a build could reach was RELEASE CANDIDATE and nothing in the bundle said what
#: separated that from GA. A reader with 21 green gates could reasonably conclude
#: the product was ready to sell.
#:
#: These four are what separates them, and not one is code. They accrue from
#: OPERATING the product -- from a calendar, a contract and a third party -- so
#: no amount of engineering moves them and no build should ever report them as
#: PASS. They are emitted as UNVERIFIED with their reason so that "why is this
#: not GA" is answered by the generated artifact rather than by whoever is asked.
#:
#: A `status` other than UNVERIFIED here must come from a human recording real
#: external evidence. Nothing in this script can write one.
GA_GATES: Mapping[str, str] = MappingProxyType({
    "independent_pentest": (
        "Requires a contracted third party, an agreed scope, a report and a "
        "remediation cycle. A scan this project runs against itself is not an "
        "INDEPENDENT assessment, which is the distinction section 78 draws."
    ),
    "production_soak": (
        "Requires a continuous production-like run tracking event loss, memory "
        "growth, queue backlog and ledger integrity. The elapsed time IS the "
        "evidence; a harness that runs for an hour proves something else."
    ),
    "disaster_recovery_proof": (
        "Requires recovery across an INDEPENDENT failure domain -- a second "
        "region or account that must exist before crossing it proves anything. "
        "The PITR drills in docs/ exercise the mechanism, not the boundary."
    ),
    "design_partner_validation": (
        "Requires real organisations running this against real traffic under "
        "real agreements. A commercial fact, not a technical one."
    ),
})


@dataclass
class Gate:
    """One required gate and what we actually know about it."""

    name: str
    status: str = UNVERIFIED
    detail: str = "no artifact was produced for this gate"
    source: str = ""
    #: Why the artifact does or does not belong to this build. Empty when no
    #: artifact was found at all -- absence has no provenance to report.
    binding: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "gate": self.name,
            "status": self.status,
            "detail": self.detail,
            "source": self.source,
            "binding": self.binding,
        }


@dataclass
class Bundle:
    commit: str
    version: str
    build_id: str
    generated_at: str
    gates: list[Gate] = field(default_factory=list)
    known_limitations: list[str] = field(default_factory=list)

    @property
    def verified(self) -> int:
        return sum(1 for g in self.gates if g.status == PASS)

    @property
    def failed(self) -> int:
        return sum(1 for g in self.gates if g.status == FAIL)

    @property
    def unverified(self) -> int:
        return sum(1 for g in self.gates if g.status == UNVERIFIED)

    @property
    def release_tier(self) -> str:
        """§103: do not call every build production-ready.

        Derived from evidence, never asserted. A build with unverified gates
        cannot be a Release Candidate no matter how much someone would like it
        to be -- which is the whole reason this is computed rather than typed.
        """
        if self.failed:
            return "BROKEN — a required gate failed"

        # The GA gates are ALWAYS unverified, so a build can never report GA and
        # this function can never be edited into doing so by accident. They are
        # excluded from the developer-preview test for the same reason: leaving
        # them in would pin every build to DEVELOPER PREVIEW for ever and make
        # the tier stop distinguishing anything.
        ci_unverified = sum(
            1
            for g in self.gates
            if g.status == UNVERIFIED and g.name not in GA_GATES
        )
        if ci_unverified:
            return "DEVELOPER PREVIEW — required gates are unverified"
        return (
            "RELEASE CANDIDATE — every gate a build can produce is verified. "
            "NOT GA: the four gates in GA_GATES are not satisfiable by any "
            "build and remain unverified."
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "version": self.version,
            "build_id": self.build_id,
            "generated_at": self.generated_at,
            "release_tier": self.release_tier,
            "gates_total": len(self.gates),
            "gates_passed": self.verified,
            "gates_failed": self.failed,
            "gates_unverified": self.unverified,
            "gates": [g.as_dict() for g in self.gates],
            "known_limitations": self.known_limitations,
            "honesty_note": (
                "UNVERIFIED means no artifact was found for that gate. It does "
                "NOT mean the gate passed, and it must not be read as assurance."
            ),
        }


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:  # noqa: BLE001 - a tarball has no git; that is not an error
        return ""


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - absent or malformed both mean "unknown"
        return None


def _judge(gate_name: str, path: Path) -> tuple[str, str]:
    """A bound artifact is present. For most gates that is the whole question.

    `performance_targets` is the exception, and the only gate here that reads
    what its artifact SAYS. Every other gate asks "did the job run and did its
    output belong to this build"; a benchmark that ran successfully and reported
    a p99 over the target is a job that succeeded and a release that should not
    ship, and treating its mere existence as PASS would be the same defect Phase
    1 fixed one level up.

    Targets come from `config/performance_targets.json`, not from this file: a
    number hardcoded in a gate is one nobody can argue with when it is wrong,
    and a deployment's acceptable latency is a deployment decision.
    """
    if gate_name != "performance_targets":
        artifact = _read_json(path) if path.suffix == ".json" else None
        if isinstance(artifact, dict) and "ok" in artifact:
            # A GATE ARTIFACT THAT RECORDS ITS OWN FAILURE IS A FAIL.
            #
            # `run_release_gates.py` writes a file whether the command it ran
            # succeeded or not, on purpose: an artifact that only appears on
            # success makes a failure indistinguishable from a job that never
            # ran, and the second is the one that reports UNVERIFIED. So the
            # presence of the file cannot be the verdict -- what it says is.
            #
            # Compared against `is True` rather than truth-tested, because a
            # string, a non-empty dict, or the number 1 would all pass a truth
            # test, and a gate runner that wrote `"ok": "failed"` would then
            # report PASS. The one value that means success is the boolean.
            if artifact.get("ok") is True:
                return PASS, str(artifact.get("summary") or f"{path.name} records success")
            return FAIL, str(
                artifact.get("summary")
                or f"{path.name} records exit {artifact.get('exit_code')!r}"
            )
        return PASS, f"artifact present and bound to this build ({path.name})"

    targets = _read_json(ROOT / "config" / "performance_targets.json")
    artifact = _read_json(path)
    if targets is None or artifact is None:
        return UNVERIFIED, "targets or benchmark artifact could not be read"

    try:
        limits = targets["authorization_decision"]
        measured = artifact["measurement"]["overall"]
    except (KeyError, TypeError):
        return UNVERIFIED, f"{path.name} is not in the expected benchmark shape"

    breaches = [
        f"{k} {measured[f'{k}_ms']}ms over {limits[f'{k}_ms']}ms"
        for k in ("p50", "p95", "p99")
        if measured.get(f"{k}_ms") is not None
        and measured[f"{k}_ms"] > limits[f"{k}_ms"]
    ]
    where = artifact.get("environment", {}).get("platform", "an unrecorded machine")
    if breaches:
        return FAIL, f"authorization latency over target: {'; '.join(breaches)}"
    return (
        PASS,
        f"p95 {measured['p95_ms']}ms / p99 {measured['p99_ms']}ms within target, "
        f"measured on {where} (single process, no HTTP, no network)",
    )


def _release_identity(commit: str) -> release_binding.ReleaseIdentity:
    """What this release IS, for every artifact to be checked against.

    Delegates to `release_binding.release_identity` so this reader and the gate
    runner that stamps the artifacts compute the tree digest the same way. When
    they differed, every artifact verified as UNBOUND and the report said
    UNVERIFIED for gates that had actually run.
    """
    return release_binding.release_identity(commit, root=ROOT)


def collect(artifacts: Path) -> Bundle:
    """Read whatever real artifacts exist and report exactly that."""
    bundle = Bundle(
        commit=_git("rev-parse", "HEAD") or "UNKNOWN",
        version=_git("describe", "--tags", "--always") or "UNKNOWN",
        build_id=os.environ.get("GITHUB_RUN_ID", "local"),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    # Each gate is resolved from a named artifact FILENAME, searched for
    # recursively.
    #
    # Recursively, because `actions/download-artifact` nests each job's output
    # under its own directory -- `artifacts/sentinel-cyclonedx-sbom/...`, not
    # `artifacts/sbom.json`. A flat lookup finds nothing on a real CI tree and
    # reports every gate UNVERIFIED while the artifacts sit one level down. That
    # is a gate that cannot fire, reported as caution, which is the most
    # convincing kind of wrong.
    #
    # The filenames are the ones CI actually writes, verified against the
    # workflow rather than guessed.
    sources: dict[str, str] = {
        "detection_evaluation": "metrics.json",
        "sbom": "sentinel.cdx.json",
        "license_scan": "licenses.json",
        "artifact_signing": "manifest.sig",
        "performance_targets": "authorization_bench.json",
    }
    # EVERY OTHER REQUIRED GATE RESOLVES TO A CONVENTIONAL FILENAME.
    #
    # This line closes a defect that made twenty of the twenty-six gates
    # structurally unable to fire. A gate absent from `sources` got
    # `filename = None`, so `find()` was never called and the gate reported
    # UNVERIFIED with "no artifact was produced for this gate" -- FOREVER, no
    # matter what CI produced. The message invites someone to go and produce the
    # artifact, and producing it would have changed nothing.
    #
    # That is worse than a gate that fails: a gate stuck on caution reads as
    # "not measured yet" rather than as "cannot be measured", and the two are
    # indistinguishable in the report. `run_release_gates.py` writes these
    # files; `test_release_evidence_gates.py` pins that no gate can be added
    # without a way to satisfy it.
    for _name in REQUIRED_GATES:
        sources.setdefault(_name, f"gate_{_name}.json")
    identity = _release_identity(bundle.commit)
    # `docs/` is searched because that is where the benchmark artifacts
    # already live (performance_microbench.json, ingest_loadtest_*.json).
    # Adding the root beats moving the artifacts and breaking every link
    # in the performance documentation.
    search_roots = [artifacts, ROOT / "release", ROOT / "evaluation", ROOT / "docs"]

    def find(filename: str) -> Path | None:
        for root in search_roots:
            if not root.exists():
                continue
            if (root / filename).is_file():
                return root / filename
            for hit in root.rglob(filename):
                if hit.is_file():
                    return hit
        return None

    for name, reason in GA_GATES.items():
        # Appended FIRST so they are impossible to miss at the top of the table,
        # and never given a source: there is no artifact this script could read
        # that would justify anything but UNVERIFIED.
        bundle.gates.append(
            Gate(name=name, status=UNVERIFIED, detail=f"NOT SATISFIABLE BY A BUILD — {reason}")
        )

    for name in REQUIRED_GATES:
        gate = Gate(name=name)
        filename = sources.get(name)
        path = find(filename) if filename else None
        if path is not None and path.exists():
            # READABLE FIRST, then BOUND. An artifact that cannot be parsed is a
            # broken job (FAIL); one that parses but belongs to another build is
            # not this release's evidence (UNVERIFIED). Collapsing the two would
            # hide a CI failure behind a provenance message.
            readable = True
            if path.suffix == ".json":
                if _read_json(path) is None:
                    gate.status = FAIL
                    gate.detail = f"{path.name} exists but could not be parsed"
                    readable = False
            elif not path.stat().st_size:
                # A cosign signature is not JSON, so it is judged by being
                # non-empty rather than by parsing.
                gate.status = FAIL
                gate.detail = f"{path.name} is empty"
                readable = False

            if readable:
                # THE PHASE 1 CHANGE. Previously any readable artifact was PASS,
                # so evidence from another commit, another image or last month
                # all counted -- twenty-one green rows about a different build.
                #
                # An artifact is this release's evidence only if its provenance
                # sidecar says so. UNBOUND is UNVERIFIED, not PASS: an artifact
                # whose origin nobody recorded is epistemically the same as one
                # that does not exist.
                verdict = release_binding.verify(
                    path, release=identity, now=datetime.now(timezone.utc)
                )
                if verdict.is_bound:
                    gate.status, gate.detail = _judge(name, path)
                else:
                    gate.status = UNVERIFIED
                    gate.detail = f"{path.name}: {verdict.reason}"
                gate.binding = verdict.value
            gate.source = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
        bundle.gates.append(gate)

    # Known limitations are READ from the documents that state them, not
    # summarised here -- a second summary is a second thing to keep in sync.
    for doc in ("SCALE_AND_ASSURANCE.md", "RESPONSE_AND_CONTAINMENT.md"):
        candidate = ROOT / "docs" / doc
        if candidate.exists():
            bundle.known_limitations.append(f"see docs/{doc}")

    return bundle


def render_markdown(bundle: Bundle) -> str:
    lines = [
        "# Release readiness",
        "",
        "**Generated. Do not edit by hand — edits are overwritten and, worse, "
        "unverifiable.**",
        "",
        f"- commit: `{bundle.commit}`",
        f"- version: `{bundle.version}`",
        f"- build: `{bundle.build_id}`",
        f"- generated: {bundle.generated_at}",
        "",
        f"## Tier: {bundle.release_tier}",
        "",
        f"{bundle.verified} passed · {bundle.failed} failed · "
        f"{bundle.unverified} unverified, of {len(bundle.gates)} required gates.",
        "",
        "> `UNVERIFIED` means no artifact was found for that gate. It does NOT "
        "mean the gate passed.",
        "",
        "| Gate | Status | Evidence |",
        "|---|---|---|",
    ]
    for gate in bundle.gates:
        mark = {PASS: "✅", FAIL: "❌", UNVERIFIED: "❔"}[gate.status]
        lines.append(f"| `{gate.name}` | {mark} {gate.status} | {gate.detail} |")
    lines += ["", "## Known limitations", ""]
    lines += [f"- {item}" for item in bundle.known_limitations] or ["- none recorded"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifacts",
        default="artifacts",
        help="directory CI downloaded job artifacts into",
    )
    parser.add_argument("--out", default="release")
    parser.add_argument(
        "--require-all",
        action="store_true",
        help=(
            "exit non-zero unless every required gate is PASS. For a GA build; "
            "off by default so a bundle can always be produced and read."
        ),
    )
    args = parser.parse_args(argv)

    bundle = collect(Path(args.artifacts))
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "readiness.json").write_text(
        json.dumps(bundle.as_dict(), indent=2), encoding="utf-8"
    )
    (out / "readiness.md").write_text(render_markdown(bundle), encoding="utf-8")

    sys.stdout.write(
        f"{bundle.release_tier}\n"
        f"{bundle.verified} passed, {bundle.failed} failed, "
        f"{bundle.unverified} unverified\n"
        f"written to {out}/readiness.json and {out}/readiness.md\n"
    )
    if args.require_all and (bundle.failed or bundle.unverified):
        sys.stderr.write(
            "refusing to certify: required gates are not all verified\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
