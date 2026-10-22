"""Artifact selection, refusal and scan contracts shared by release checks."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: What ships. Directories are copied recursively; files are copied as named.
#: Adding to this list is a deliberate act, which is the point.
INCLUDE: tuple[str, ...] = (
    "sentinel",
    "scripts",
    "tests_arch",
    "deploy",
    "docs",
    "standard",
    "security",
    "README.md",
    "CONTRIBUTING.md",
    "pytest.ini",
    "pyproject.toml",
    "requirements.txt",
    "requirements.lock",
    "requirements-dev.txt",
    ".gitleaks.toml",
    ".dockerignore",
    "Dockerfile",
)

#: Refused wherever they appear, even under an included directory. Matched on
#: the file NAME, and on suffixes, because the danger is what the file is and
#: not where somebody put it.
REFUSED_NAMES: frozenset[str] = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging",
    "terraform.tfstate", "terraform.tfstate.backup",
    "id_rsa", "id_ed25519", ".npmrc", ".netrc",
    "credentials", "config.json",
})

#: NOT here, deliberately, after the first run of this script refused all three:
#:
#:   * `.terraform.lock.hcl` -- a provider VERSION LOCK, the terraform
#:     equivalent of requirements.txt. It should ship. The provider cache it
#:     sits next to is `.terraform/`, which PRUNED_DIRS already removes; I had
#:     confused the two.
#:   * `.log` -- `tests_arch/fixtures/strace_*.log` are real captured strace
#:     output and the tests that parse them are the only evidence the tracer
#:     works against reality. Refusing the suffix would have shipped an
#:     artifact whose test suite could not run.
#:
#: Both were refusals an operator could not have acted on, which is the failure
#: mode a crude denylist produces: it gets switched off wholesale. Runtime logs
#: are excluded because `data/` is pruned, and the gitleaks scan over the built
#: artifact is what actually defends against a secret in a file, rather than a
#: guess about what filenames secrets live in.
REFUSED_SUFFIXES: frozenset[str] = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".db", ".sqlite", ".sqlite3",
    ".pyc", ".pyo", ".coverage",
})

#: Directory names pruned anywhere in the tree. These are caches and local
#: state; none of them is a secret by itself and all of them are places one
#: ends up.
PRUNED_DIRS: frozenset[str] = frozenset({
    "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    ".git", ".terraform", "node_modules", ".venv", "venv", "htmlcov",
    ".idea", ".vscode", "data",
})


class Refused(RuntimeError):
    """Packaging refused. Never downgraded to a warning."""


def _is_refused(path: Path) -> str:
    """Why this file must not ship, or empty string."""
    if path.name in REFUSED_NAMES:
        return f"{path.name} is a credential-shaped filename"
    if path.name.startswith(".env"):
        return f"{path.name} is a dotenv file"
    if path.suffix.lower() in REFUSED_SUFFIXES:
        return f"{path.suffix} files are local state or build output"
    return ""


def _collect(root: Path) -> tuple[list[Path], list[str]]:
    """Every file that ships, and every refusal, from the allowlist.

    Refusals are COLLECTED rather than raised on the first one, so an operator
    fixing a packaging problem sees all of it at once. They are still fatal.
    """
    selected: list[Path] = []
    refusals: list[str] = []

    for entry in INCLUDE:
        source = root / entry
        if not source.exists():
            # Absent allowlist entries are fine and not silent: `standard/` does not
            # exist yet, and naming it here means it ships the day it does
            # rather than the day somebody remembers this file.
            continue
        if source.is_file():
            reason = _is_refused(source)
            if reason:
                refusals.append(f"{entry}: {reason}")
            else:
                selected.append(source)
            continue
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            if PRUNED_DIRS & set(path.relative_to(root).parts[:-1]):
                continue
            reason = _is_refused(path)
            if reason:
                refusals.append(f"{path.relative_to(root)}: {reason}")
                continue
            selected.append(path)

    return selected, refusals


def _write_zip(paths: list[Path], *, root: Path, destination: Path) -> None:
    """Deterministic archive: sorted entries, fixed timestamps.

    A zip whose bytes change between two builds of the same commit cannot be
    checksummed usefully -- the checksum would differ for reasons that have
    nothing to do with content, and anyone comparing two artifacts would see a
    difference that is not one.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(paths):
            info = zipfile.ZipInfo(
                filename=str(path.relative_to(root)).replace("\\", "/"),
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())


def _scan_artifact(artifact: Path) -> tuple[str, str]:
    """Scan the BUILT archive. Returns (status, detail).

    Status is PASS, FAIL or UNVERIFIED. UNVERIFIED when gitleaks is not
    installed -- not PASS, because "could not check" and "checked and clean" are
    different facts and only one is a reason to ship.
    """
    if shutil.which("gitleaks") is None:
        return (
            "UNVERIFIED",
            "gitleaks is not installed, so the artifact was NOT scanned. This "
            "is not a pass: install gitleaks and re-run before distributing.",
        )

    with tempfile.TemporaryDirectory() as temporary:
        extracted = Path(temporary) / "artifact"
        with zipfile.ZipFile(artifact) as archive:
            archive.extractall(extracted)
        result = subprocess.run(
            [
                "gitleaks", "dir", str(extracted),
                "--redact", "--no-banner",
                "--config", str(ROOT / ".gitleaks.toml"),
            ],
            capture_output=True,
            text=True,
        )

    if result.returncode == 0:
        return "PASS", "gitleaks found no secrets in the built artifact"
    # --redact is passed, so findings name locations and not values. An operator
    # pasting this output into an issue must not be pasting a credential.
    detail = (result.stdout + result.stderr).strip()
    return "FAIL", f"gitleaks reported findings in the built artifact:\n{detail}"
