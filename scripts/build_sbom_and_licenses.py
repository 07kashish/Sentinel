"""Produce the SBOM and the licence inventory, and bind both to this build.

WHY THIS IS A SCRIPT AND NOT A COMMAND SOMEBODY TYPES
-------------------------------------------------------
Both artifacts feed release gates, and both were generated once by hand while
this was being written. A hand-typed incantation is a producer nobody can
re-run identically, which makes the artifact unreproducible -- and an
unreproducible artifact is a weak thing to hang a release gate on.

SCOPED TO THE DECLARED RUNTIME DEPENDENCIES, NOT THE ENVIRONMENT
-------------------------------------------------------------------
`pip-licenses` with no arguments reports every package installed in the
interpreter. On the machine this was written on that was 495 packages -- test
tooling, linters, notebook kernels, whatever else lives there. Publishing that
as "the product's licences" would be false in the direction that matters: it
overstates the dependency surface enormously and buries the ten packages that
actually ship.

So the package list is read from `requirements.txt`, which is the file that
declares what the product depends on at runtime. If a dependency is added
there, it appears here; if it is only a developer tool, it does not.

WHAT THIS DOES NOT DO
---------------------
It does not judge the licences. `psycopg` is LGPL-3.0-only and everything else
is permissive; whether that is acceptable is a legal question about how this
software is distributed, not one a build script can answer. The inventory is
the input to that decision, and presenting it as the decision would be the kind
of claim the readiness report exists to avoid.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


SBOM = ROOT / "docs" / "sentinel.cdx.json"
LICENSES = ROOT / "docs" / "licenses.json"


def runtime_packages() -> list[str]:
    """Package names from `requirements.txt`, in declaration order.

    Parsed rather than imported: a requirements file can carry markers, extras
    and version pins, and only the distribution name identifies the package to
    the licence tool.
    """
    names: list[str] = []
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or entry.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9._-]+)", entry)
        if match:
            names.append(match.group(1))
    return names


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, cwd=str(ROOT), capture_output=True, text=True, check=False
    )


def build_sbom() -> None:
    result = _run(
        [
            sys.executable, "-m", "cyclonedx_py", "requirements",
            "requirements.txt", "-o", str(SBOM), "--output-format", "JSON",
        ]
    )
    if result.returncode != 0 or not SBOM.exists():
        raise SystemExit(
            "cyclonedx-py failed, so NO SBOM was written. The gate stays "
            f"UNVERIFIED, which is the accurate report:\n{result.stderr[-800:]}"
        )


def build_licenses() -> None:
    packages = runtime_packages()
    if not packages:
        raise SystemExit("requirements.txt declares no packages; refusing to guess")

    result = _run(
        [sys.executable, "-m", "piplicenses", "--format=json", "--with-urls",
         "--packages", *packages]
    )
    if result.returncode != 0:
        raise SystemExit(f"pip-licenses failed:\n{result.stderr[-800:]}")

    inventory = json.loads(result.stdout)
    found = {entry["Name"].lower().replace("_", "-") for entry in inventory}
    missing = [
        name for name in packages
        if name.lower().replace("_", "-") not in found
    ]
    if missing:
        # A package declared in requirements.txt and absent from the inventory
        # means the environment does not have it installed. Writing the partial
        # list would report a smaller dependency surface than the product has.
        raise SystemExit(
            f"these declared dependencies are not installed, so their licences "
            f"could not be read: {missing}. Refusing to write a partial "
            "inventory that would understate the dependency surface."
        )

    LICENSES.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    build_sbom()
    build_licenses()

    for artifact in (SBOM, LICENSES):
        print(f"wrote {artifact.relative_to(ROOT)}")

    inventory = json.loads(LICENSES.read_text(encoding="utf-8"))
    print(f"\n{len(inventory)} runtime dependencies:")
    for entry in sorted(inventory, key=lambda e: e["Name"].lower()):
        print(f"  {entry['Name']:<22} {entry['Version']:<10} {entry['License']}")
    print(
        "\nThe inventory is the INPUT to a licence decision, not the decision. "
        "Whether a copyleft dependency is acceptable depends on how this "
        "software is distributed, which is not a question a build script "
        "answers."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
