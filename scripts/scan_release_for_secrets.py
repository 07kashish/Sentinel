#!/usr/bin/env python3
"""Scan release artifacts and the tracked tree for secrets. Never echoes one.

WHAT IT CHECKS
--------------
1. CONTENTS ALLOWLIST. A wheel may contain only `sentinel/**.py` and its
   `dist-info`; an sdist only the named top-level entries; a Helm chart only
   chart files. Anything else is a finding, because the file most likely to
   be added to a package by accident is the one nobody meant to ship.
2. SECRET-SHAPED CONTENT. High-confidence patterns (cloud access keys, private
   key blocks, vendor tokens, signed JWTs) always fire. A generic
   `key = "..."` assignment fires only when the value is high-entropy, so a
   test fixture spelled `ingest-key-that-is-long-enough` is not a finding
   while a real random credential is.
3. KNOWN VALUES. With `--known-secrets-from FILE`, every value in that dotenv
   is loaded into memory and searched for, byte for byte, across the tracked
   tree and every artifact. The report names the VARIABLE and the file it was
   found in. The value itself is never written anywhere.

WHAT IT NEVER DOES
------------------
Print, log or write a matched value. Findings carry the path, the line, the
rule and the first 8 hex characters of the sha256 of the match, which is
enough to correlate two reports and not enough to reconstruct anything.
The dotenv values are held in a local variable and discarded.

EXIT CODES
----------
0  nothing found      1  findings      2  could not check (missing artifact,
unreadable input). 2 is not a pass: a scan that could not run has verified
nothing, and CI treats it as a failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import tarfile
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

ROOT = Path(__file__).resolve().parent.parent

# ── Allowlists ───────────────────────────────────────────────────────────────

WHEEL_PACKAGE_PREFIX = "sentinel/"
WHEEL_ALLOWED_SUFFIXES = frozenset({".py"})
#: Package data that is allowed in the wheel beyond source. Named one by one:
#: a suffix rule would let the next stray JSON ship.
WHEEL_ALLOWED_DATA = frozenset({
    "sentinel/infrastructure/default_policy.json",
    "sentinel/interface/console/index.html",
    "sentinel/interface/console/app.js",
    "sentinel/interface/console/app.css",
})
WHEEL_DISTINFO_ALLOWED = frozenset(
    {"METADATA", "WHEEL", "RECORD", "top_level.txt", "entry_points.txt", "LICENSE", "licenses/LICENSE"}
)
SDIST_ALLOWED_TOP_LEVEL = frozenset(
    {"sentinel", "sentinel_agent_trust.egg-info", "LICENSE", "PKG-INFO",
     "README.md", "pyproject.toml", "setup.cfg"}
)
CHART_ALLOWED = (
    re.compile(r"^(Chart\.yaml|values\.yaml|values\.schema\.json|README\.md|\.helmignore|Chart\.lock)$"),
    re.compile(r"^templates/([A-Za-z0-9_\-./]+)\.(yaml|yml|tpl|txt)$"),
    re.compile(r"^tests/([A-Za-z0-9_\-./]+)\.(yaml|yml)$"),
    re.compile(r"^charts/([A-Za-z0-9_\-./]+)$"),
)

#: Refused anywhere in any artifact, by name or suffix. Mirrors
#: `artifact_contract.py`; the two lists are compared by a test.
REFUSED_NAMES = frozenset({
    ".env", ".env.local", ".env.production", ".env.staging",
    "terraform.tfstate", "terraform.tfstate.backup",
    "id_rsa", "id_ed25519", ".npmrc", ".netrc", "credentials",
})
REFUSED_SUFFIXES = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore",
    ".db", ".sqlite", ".sqlite3", ".pyc", ".pyo", ".coverage",
})

# ── Secret patterns ──────────────────────────────────────────────────────────

HIGH_CONFIDENCE: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("aws-access-key-id", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("private-key-block", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("github-token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-live-key", re.compile(rb"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("signed-jwt", re.compile(rb"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\b")),
    ("openai-key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("anthropic-key", re.compile(rb"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
)

#: `name = "value"` / `NAME=value` / `"name": "value"` where the name is
#: credential-shaped. Fires only when the VALUE passes the entropy gate.
GENERIC_ASSIGNMENT = re.compile(
    rb"(?i)\b([A-Z0-9_.\-]*(?:secret|password|passwd|api[_\-]?key|access[_\-]?key|"
    rb"auth[_\-]?token|private[_\-]?key|client[_\-]?secret|session[_\-]?secret)[A-Z0-9_.\-]*)"
    rb"\s*[:=]\s*[\"']?([A-Za-z0-9/+_\-=]{20,})[\"']?"
)
MIN_ENTROPY_BITS_PER_CHAR = 3.8

#: Published example credentials that vendors document and scanners
#: allowlist. They are identifiers of nothing; matching them would be noise.
PUBLISHED_EXAMPLES = frozenset({b"AKIAIOSFODNN7EXAMPLE", b"AKIAI44QH8DHBEXAMPLE"})

#: Tracked files allowed to contain a pattern match, each with the reason.
#: Only for the TREE scan: artifacts get no exceptions. A test asserts every
#: entry still matches something, so a stale entry cannot linger.
TREE_ALLOWLIST: tuple[tuple[str, str, str], ...] = (
    (".gitleaks.toml", "private-key-block", "a comment quoting the header it allowlists"),
    ("tests_arch/test_endpoint_sensor.py", "anthropic-key", "fake token proving the sensor redacts"),
    ("tests_arch/test_endpoint_sensor.py", "openai-key", "same fixture, matched by the broader rule"),
    ("tests_arch/test_sdk_remote.py", "openai-key", "sk-test fixture proving the SDK never logs a key"),
    ("tests_arch/test_tenant_integrations.py", "slack-token", "xoxb-1234 fixture for the integration redactor"),
)

#: Placeholders a template legitimately carries. Compared case-insensitively
#: against the whole value; a real credential never equals one of these.
PLACEHOLDER_HINTS = ("replace", "example", "changeme", "your-", "xxxx", "<", "${", "dummy", "placeholder", "sample")


def _entropy(value: bytes) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_random(value: bytes) -> bool:
    lowered = value.lower()
    if any(hint.encode() in lowered for hint in PLACEHOLDER_HINTS):
        return False
    has_digit = any(48 <= b <= 57 for b in value)
    has_alpha = any(65 <= b <= 90 or 97 <= b <= 122 for b in value)
    return has_digit and has_alpha and _entropy(value) >= MIN_ENTROPY_BITS_PER_CHAR


_TREE_ALLOWED = frozenset((path, rule) for path, rule, _ in TREE_ALLOWLIST)


def _fingerprint(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()[:8]


# ── Findings ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Finding:
    source: str        # artifact or "tree"
    path: str          # member path inside the artifact, or repo-relative
    rule: str
    line: int          # 0 when not line-addressable
    fingerprint: str   # sha256[:8] of the matched bytes; never the bytes

    def render(self) -> str:
        where = f"{self.source}:{self.path}" if self.source != "tree" else self.path
        line = f":{self.line}" if self.line else ""
        return f"{where}{line}  [{self.rule}]  fp={self.fingerprint}"


def _line_of(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def scan_bytes(source: str, path: str, data: bytes, known: dict[str, bytes]) -> list[Finding]:
    """Every secret-shaped thing in one file's bytes. Values never leave here."""
    out: list[Finding] = []
    for rule, pattern in HIGH_CONFIDENCE:
        for match in pattern.finditer(data):
            if match.group(0) in PUBLISHED_EXAMPLES:
                continue
            if source == "tree" and (path, rule) in _TREE_ALLOWED:
                continue
            out.append(Finding(source, path, rule, _line_of(data, match.start()), _fingerprint(match.group(0))))
    for match in GENERIC_ASSIGNMENT.finditer(data):
        value = match.group(2)
        if _looks_random(value):
            out.append(Finding(source, path, "high-entropy-credential-assignment",
                               _line_of(data, match.start()), _fingerprint(value)))
    for name, value in known.items():
        offset = data.find(value)
        if offset >= 0:
            out.append(Finding(source, path, f"known-secret:{name}", _line_of(data, offset), _fingerprint(value)))
    return out


# ── Artifact readers ─────────────────────────────────────────────────────────


def _members_zip(path: Path) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.is_dir():
                yield info.filename, archive.read(info)


def _members_tar(path: Path) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(path) as archive:
        for member in archive.getmembers():
            if member.isfile():
                handle = archive.extractfile(member)
                yield member.name, handle.read() if handle else b""


def _members_dir(path: Path) -> Iterator[tuple[str, bytes]]:
    for file in sorted(p for p in path.rglob("*") if p.is_file()):
        yield str(file.relative_to(path)).replace("\\", "/"), file.read_bytes()


def _refused(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    if base in REFUSED_NAMES or base.startswith(".env"):
        return f"credential-shaped filename {base!r}"
    suffix = ("." + base.rsplit(".", 1)[-1]).lower() if "." in base else ""
    if suffix in REFUSED_SUFFIXES:
        return f"refused suffix {suffix!r}"
    return ""


def check_wheel_member(name: str) -> str:
    """Why this wheel member is outside the allowlist, or empty."""
    reason = _refused(name)
    if reason:
        return reason
    if name in WHEEL_ALLOWED_DATA:
        return ""
    if name.startswith(WHEEL_PACKAGE_PREFIX):
        suffix = "." + name.rsplit(".", 1)[-1] if "." in name.rsplit("/", 1)[-1] else ""
        return "" if suffix in WHEEL_ALLOWED_SUFFIXES else f"non-source file {suffix or name!r} in the package"
    top, _, rest = name.partition("/")
    if top.endswith(".dist-info") and rest in WHEEL_DISTINFO_ALLOWED:
        return ""
    return "outside the package and its dist-info"


def check_sdist_member(name: str) -> str:
    reason = _refused(name)
    if reason:
        return reason
    parts = name.split("/")
    # sdist members are prefixed with `<name>-<version>/`.
    inner = parts[1] if len(parts) > 1 else parts[0]
    if inner not in SDIST_ALLOWED_TOP_LEVEL:
        return f"top-level entry {inner!r} is not allowlisted for the sdist"
    if inner == "sentinel" and not name.endswith(".py") and "/".join(parts[1:]) not in WHEEL_ALLOWED_DATA:
        return "non-source file in the package"
    return ""


def check_chart_member(name: str) -> str:
    reason = _refused(name)
    if reason:
        return reason
    # A packaged chart is prefixed with `<chart>/`; a chart directory is not.
    candidates = (name, name.partition("/")[2])
    if any(p.match(c) for c in candidates for p in CHART_ALLOWED):
        return ""
    return "not a chart file"


def scan_artifact(path: Path, known: dict[str, bytes]) -> tuple[list[Finding], int]:
    """(findings, members scanned). Raises on an unreadable artifact."""
    name = path.name
    if path.is_dir():
        members, checker, kind = _members_dir(path), check_chart_member, "chart"
    elif name.endswith(".whl"):
        members, checker, kind = _members_zip(path), check_wheel_member, "wheel"
    elif name.endswith((".tar.gz", ".tgz")):
        members, checker, kind = _members_tar(path), (check_chart_member if name.endswith(".tgz") else check_sdist_member), "archive"
    elif name.endswith(".zip"):
        members, checker, kind = _members_zip(path), lambda n: _refused(n), "zip"
    else:
        raise ValueError(f"{name}: not a wheel, sdist, chart or zip")
    findings: list[Finding] = []
    scanned = 0
    for member, data in members:
        scanned += 1
        reason = checker(member)
        if reason:
            findings.append(Finding(name, member, f"{kind}-allowlist: {reason}", 0, ""))
        findings.extend(scan_bytes(name, member, data, known))
    return findings, scanned


def scan_tree(root: Path, known: dict[str, bytes]) -> tuple[list[Finding], int]:
    """Every git-tracked file. Untracked files are not a release input."""
    listed = subprocess.run(  # noqa: S603,S607 - fixed command
        ["git", "ls-files", "-z"], cwd=str(root), capture_output=True, text=True, check=True,
    ).stdout.split("\0")
    findings: list[Finding] = []
    scanned = 0
    for rel in listed:
        if not rel:
            continue
        file = root / rel
        if not file.is_file():
            continue
        scanned += 1
        findings.extend(scan_bytes("tree", rel, file.read_bytes(), known))
    return findings, scanned


# ── Known values ─────────────────────────────────────────────────────────────


def load_known(path: Path) -> dict[str, bytes]:
    """Variable name -> value bytes, for values that could be a credential.

    Short values and placeholders are skipped so that `SENTINEL_ENV=production`
    does not become a "secret" found in every deployment manifest.
    """
    known: dict[str, bytes] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        value = raw.strip().strip("'\"")
        if len(value) < 12 or not _looks_random(value.encode()):
            continue
        known[key.strip()] = value.encode()
    return known


# ── CLI ──────────────────────────────────────────────────────────────────────


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--artifact", action="append", default=[], type=Path,
                        help="wheel, sdist, chart .tgz, chart directory or release zip (repeatable)")
    parser.add_argument("--tree", action="store_true", help="also scan every git-tracked file")
    parser.add_argument("--known-secrets-from", type=Path, default=None,
                        help="a dotenv whose VALUES are searched for; never printed")
    parser.add_argument("--json", type=Path, default=None, help="write the report here")
    parser.add_argument("--root", type=Path, default=ROOT)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    known: dict[str, bytes] = {}
    if args.known_secrets_from is not None:
        if not args.known_secrets_from.is_file():
            print(f"cannot check: {args.known_secrets_from} does not exist", file=sys.stderr)
            return 2
        known = load_known(args.known_secrets_from)

    findings: list[Finding] = []
    scanned: dict[str, int] = {}
    for artifact in args.artifact:
        if not artifact.exists():
            print(f"cannot check: artifact {artifact} does not exist", file=sys.stderr)
            return 2
        try:
            found, count = scan_artifact(artifact, known)
        except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
            print(f"cannot check: {artifact.name}: {exc}", file=sys.stderr)
            return 2
        findings.extend(found)
        scanned[artifact.name] = count
    if args.tree:
        found, count = scan_tree(args.root, known)
        findings.extend(found)
        scanned["tree"] = count
    if not scanned:
        print("cannot check: nothing to scan (pass --artifact and/or --tree)", file=sys.stderr)
        return 2

    known = {}  # drop the values before anything is written
    report = {
        "scanned": scanned,
        "known_secret_names": sorted(k for k in (args.known_secrets_from and load_known(args.known_secrets_from) or {})),
        "findings": [asdict(f) for f in findings],
        "verdict": "FAIL" if findings else "PASS",
    }
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for key, count in scanned.items():
        print(f"scanned {count} members of {key}")
    for finding in findings:
        print(f"FINDING  {finding.render()}")
    print(f"verdict: {report['verdict']} ({len(findings)} finding(s))")
    return 1 if findings else 0


def iter_findings(paths: Iterable[Path]) -> list[Finding]:  # pragma: no cover - convenience
    out: list[Finding] = []
    for path in paths:
        out.extend(scan_artifact(path, {})[0])
    return out


if __name__ == "__main__":
    raise SystemExit(main())
