"""Build the container image and scan it, recording both as gate evidence.

WHY ONE SCRIPT FOR TWO GATES
-----------------------------
`container_scanning` scans an image, and the image only exists because
`container_build` produced it. Splitting them into two scripts means the second
either rebuilds (doubling the slowest step) or scans whatever image happens to
be lying around under that tag -- which could be from another commit, another
branch, or another project. Scanning a stale image and filing the result as
this build's evidence is precisely the class of mistake the provenance
mechanism exists to prevent.

So the image is built and scanned in one pass, and the scan artifact records
the image digest it actually examined.

DOCKER MAY LIVE IN WSL
----------------------
On a Windows host without Docker Desktop, the daemon runs inside a WSL distro.
`--via-wsl <distro>` runs the same commands there and translates the repository
path. Without it, both commands run directly. Either way the commands are the
same ones `ci.yml` runs; only the transport differs, and the artifact records
which was used so a reader is not left guessing why a digest differs.

WHAT A PASS MEANS
-----------------
`container_build`: the Dockerfile produced an image. Nothing more -- not that
the image runs correctly, and not that it is minimal.

`container_scanning`: trivy found no vulnerability at or above the configured
severity in the image's packages. It does not examine application logic, and it
knows only what its database knew when it ran.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import release_binding  # noqa: E402

GATES = ROOT / "release" / "gates"
IMAGE = "sentinel:gate"

#: Severities worth failing over. Mirrors `ci.yml`.
FAIL_ON = "CRITICAL,HIGH"

#: Scanners, also mirroring ci.yml: package vulnerabilities, embedded secrets
#: and misconfiguration. A container gate that only looked at package versions
#: would miss a key baked into a layer.
SCANNERS = "vuln,secret,misconfig"


def _wsl_path(path: Path) -> str:
    """`F:\\repo` -> `/mnt/f/repo`."""
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    rest = str(resolved)[len(resolved.drive):].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def _runner(distro: str | None):
    """Return a function that runs a shell command, locally or inside WSL."""
    if distro is None:
        def run_local(command: str, *, timeout: int) -> subprocess.CompletedProcess:
            return subprocess.run(  # noqa: S602 - fixed commands, no user input
                command, shell=True, cwd=str(ROOT), capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=timeout, check=False,
            )
        return run_local

    workdir = _wsl_path(ROOT)
    drive = ROOT.resolve().drive.rstrip(":")
    mount = f"/mnt/{drive.lower()}"

    # THE MOUNT IS RE-ESTABLISHED ON EVERY CALL.
    #
    # WSL shuts an idle distro down, and a `drvfs` mount made by hand does not
    # survive that. The first build here succeeded, the distro idled out, and
    # the next invocation reported `docker build exited 1` with "No such file
    # or directory" -- a missing mount presented as a failed build.
    #
    # `mountpoint -q || mount` is idempotent and costs nothing when the mount
    # is already there. Fixing it in /etc/fstab is the durable answer, but a
    # script that only works on a distro somebody configured by hand is a
    # script that will fail on the next machine.
    prelude = f"(mountpoint -q {mount} || mount -t drvfs {drive}: {mount}) 2>/dev/null; "

    def run_wsl(command: str, *, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(  # noqa: S603 - fixed argv
            ["wsl", "-d", distro, "-u", "root", "--cd", "/root", "--",
             "bash", "-lc", f"{prelude}cd {workdir} && {command}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )

    return run_wsl


def _write(name: str, record: dict[str, object]) -> Path:
    GATES.mkdir(parents=True, exist_ok=True)
    path = GATES / f"gate_{name}.json"
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    release_binding.write_binding(
        path,
        release=release_binding.release_identity_from_git(ROOT),
        now=datetime.now(timezone.utc),
    )
    return path


def evaluate_scan(raw: str, *, returncode: int, image_id: str) -> dict:
    """Fail closed; retain metadata only, never scanner matches or raw output."""
    vulnerabilities, secrets, misconfigurations = [], [], []
    valid = False
    try:
        report = json.loads(raw)
        results = report["Results"]
        valid = (returncode == 0 and report["SchemaVersion"] == 2
                 and image_id.startswith("sha256:") and len(image_id) == 71
                 and report["Metadata"]["ImageID"] == image_id
                 and isinstance(results, list) and bool(results))
        for result in results:
            for finding in result.get("Vulnerabilities", []) or []:
                if finding["Severity"] in {"HIGH", "CRITICAL"}:
                    vulnerabilities.append({
                        "id": finding["VulnerabilityID"], "package": finding["PkgName"],
                        "severity": finding["Severity"],
                        "fixed_version": finding.get("FixedVersion", "") or "",
                    })
            for finding in result.get("Secrets", []) or []:
                secrets.append({"rule": finding["RuleID"], "severity": finding["Severity"]})
            for finding in result.get("Misconfigurations", []) or []:
                if finding["Severity"] in {"HIGH", "CRITICAL"} and finding.get("Status", "FAIL") == "FAIL":
                    misconfigurations.append({"id": finding["ID"], "severity": finding["Severity"]})
    except (ValueError, KeyError, TypeError, AttributeError):
        valid = False
    return {
        "gate": "container_scanning", "ok": valid and not (vulnerabilities or secrets or misconfigurations),
        "report_valid": valid, "exit_code": returncode, "image_id": image_id,
        "fixable_findings": [v for v in vulnerabilities if v["fixed_version"]],
        "unfixed_findings": [v for v in vulnerabilities if not v["fixed_version"]],
        "embedded_secrets": secrets, "misconfigurations": misconfigurations,
        "summary": "HIGH/CRITICAL vulnerabilities and misconfigurations, and every secret finding, block release; no automatic unfixed exemption.",
        "does_not_prove": "Absence of unknown vulnerabilities, application safety, or an independent assessment.",
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--via-wsl",
        default=None,
        metavar="DISTRO",
        help="run docker and trivy inside this WSL distro (Windows without "
             "Docker Desktop)",
    )
    parser.add_argument("--scan-report", type=Path, help="judge an existing private Trivy JSON report without printing its contents")
    parser.add_argument("--image-id", default="", help="expected immutable image ID for --scan-report")
    args = parser.parse_args(argv)
    if args.scan_report is not None:
        try:
            raw = args.scan_report.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raw = ""
        record = evaluate_scan(raw, returncode=0, image_id=args.image_id)
        _write("container_scanning", record)
        print("PASS container_scanning" if record["ok"] else "FAIL container_scanning (sanitized gate evidence retained)")
        return 0 if record["ok"] else 1
    run = _runner(args.via_wsl)
    transport = f"wsl:{args.via_wsl}" if args.via_wsl else "host"

    # ── container_build ──────────────────────────────────────────────────────
    build = run(f"docker build -t {IMAGE} .", timeout=3600)
    build_ok = build.returncode == 0
    build_output = build.stdout + build.stderr

    # A BUILD THAT NEVER STARTED IS NOT A FAILED BUILD.
    #
    # If the context directory is unreachable -- an unmounted drive, a wrong
    # path -- docker is never invoked, and recording that as `container_build:
    # FAILED` reports a defect in the Dockerfile that does not exist. No
    # artifact is written instead, so the gate reads UNVERIFIED: nobody built
    # anything here.
    if not build_ok and "No such file or directory" in build_output:
        for name in ("container_build", "container_scanning"):
            stale = GATES / f"gate_{name}.json"
            stale.unlink(missing_ok=True)
            Path(str(stale) + ".provenance.json").unlink(missing_ok=True)
        raise SystemExit(
            "the build context was unreachable, so docker never ran. No "
            "artifact was written and both gates stay UNVERIFIED -- an "
            "environment fault is not a defect in the image.\n"
            + build_output[-600:]
        )

    digest = ""
    if build_ok:
        inspect = run(
            f"docker image inspect {IMAGE} --format '{{{{.Id}}}}'", timeout=120
        )
        digest = inspect.stdout.strip()
        if not digest:
            # The build claimed success and produced no inspectable image.
            # Treated as a failure rather than passed on: an artifact naming no
            # image cannot be scanned, and the scan gate would then be reporting
            # about nothing.
            build_ok = False
            build_output += "\nbuild reported success but the image cannot be inspected"

    _write("container_build", {
        "gate": "container_build",
        "ok": build_ok,
        "exit_code": build.returncode,
        "summary": (
            f"container_build: built {IMAGE} ({digest[:19]}) via {transport}"
            if build_ok
            else f"container_build: docker build exited {build.returncode}"
        ),
        "command": [f"docker build -t {IMAGE} ."],
        "command_rationale": (
            "the same build ci.yml runs; only the transport differs, recorded "
            "here so a reader is not left guessing why a digest differs"
        ),
        "transport": transport,
        "image_id": digest,
        "does_not_prove": (
            "That the image runs correctly, or that it is minimal. Only that "
            "the Dockerfile produced an image."
        ),
        "output_tail": "\n".join(build_output.splitlines()[-40:]),
        "environment": {"platform": platform.platform()},
        "finished_at": datetime.now(timezone.utc).isoformat(),
    })
    print(f"{'PASS' if build_ok else 'FAIL'}  container_build")

    if not build_ok:
        # NO scan artifact. There is no image to scan, and a scan gate that
        # reported anything here would be describing an image that does not
        # exist. Absent means UNVERIFIED, which is correct.
        stale = GATES / "gate_container_scanning.json"
        stale.unlink(missing_ok=True)
        Path(str(stale) + ".provenance.json").unlink(missing_ok=True)
        print("SKIP  container_scanning: no image was produced, so nothing was "
              "scanned; the gate stays UNVERIFIED")
        return 1

    # Scan the immutable ID. Raw results may contain secret matches; never log them.
    scan = run(
        f"trivy image --quiet --scanners {SCANNERS} "
        f"--exit-code 0 --format json {digest}", timeout=2400,
    )
    record = evaluate_scan(scan.stdout, returncode=scan.returncode, image_id=digest)
    record["transport"] = transport
    _write("container_scanning", record)
    print("PASS container_scanning" if record["ok"] else "FAIL container_scanning (sanitized gate evidence retained)")
    return 0 if record["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
