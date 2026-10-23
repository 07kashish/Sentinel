#!/usr/bin/env python3
"""Install the built wheel into fresh virtual environments and use it.

THE QUESTION THIS ANSWERS
-------------------------
Does the thing we ship work on a machine that has never seen this repository?
The test suite runs against the working tree with every dev dependency
present, which proves the code and proves nothing about the package. A wheel
can miss a module, a data file or a dependency and every test still passes.

WHAT IT DOES, IN ORDER
----------------------
1. Builds the wheel (or takes one with `--wheel`).
2. THIN: a fresh venv, `pip install <wheel>` with no extras. Imports
   `sentinel.sdk` and every adapter, and asserts that NOTHING outside the
   standard library was loaded. That is the SDK promise: a customer installing
   it into an agent runtime gets no web framework, driver or classifier.
3. SERVER: another fresh venv, `pip install "<wheel>[server]"`. Runs the
   migration CLI against a temporary SQLite file, verifies the schema, starts
   the real ASGI application under uvicorn, and drives it over HTTP: liveness,
   readiness, and one authenticated `/v1/protect/evaluate` that must return a
   decision. Then stops it.

Each step records what it OBSERVED. The verdict is computed from the
observations, never from having reached the end of the script. Output is a
JSON report (`--json`) suitable for the release-hygiene job to upload.

It prints no environment values. The API key it generates is random, is used
once, and is not written to the report.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import venv
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STARTUP_TIMEOUT_SECONDS = 60

#: Modules the SDK is allowed to import. Everything else is a leak.
SDK_IMPORTS = (
    "sentinel.sdk", "sentinel.sdk.remote", "sentinel.sdk.models",
    "sentinel.sdk.adapters", "sentinel.sdk.adapters.openai_agents",
    "sentinel.sdk.adapters.langchain", "sentinel.sdk.adapters.anthropic",
    "sentinel.sdk.mcp_stdio",
)

THIN_PROBE = r"""
import builtins
import importlib
import sys
names = %r
# Startup hooks belong to the interpreter, not the SDK. Also record import
# requests so a dependency already cached at startup cannot evade this check.
before = set(sys.modules)
requested = set()
original_import = builtins.__import__
original_import_module = importlib.import_module

def tracked_import(*args, **kwargs):
    module = original_import(*args, **kwargs)
    requested.add(module.__name__)
    return module

def tracked_import_module(*args, **kwargs):
    module = original_import_module(*args, **kwargs)
    requested.add(module.__name__)
    return module

builtins.__import__ = tracked_import
importlib.import_module = tracked_import_module
try:
    for name in names:
        __import__(name)
finally:
    builtins.__import__ = original_import
    importlib.import_module = original_import_module
third = sorted(
    m for m in (set(sys.modules) - before) | requested
    if not m.startswith("sentinel")
    and m.split(".")[0] not in sys.stdlib_module_names
    and not m.startswith("_")
)
print("NONSTDLIB=" + ",".join(third))
"""


@dataclass
class Step:
    name: str
    ok: bool
    observed: str


@dataclass
class Report:
    wheel: str
    wheel_sha256: str
    python: str
    steps: list[Step] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "PASS" if self.steps and all(s.ok for s in self.steps) else "FAIL"

    def as_dict(self) -> dict:
        return {"wheel": self.wheel, "wheel_sha256": self.wheel_sha256, "python": self.python,
                "verdict": self.verdict, "steps": [asdict(s) for s in self.steps]}


def _say(text: str) -> None:
    print(text, flush=True)


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _venv(where: Path) -> Path:
    venv.EnvBuilder(with_pip=True, clear=True).create(where)
    python = where / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run([str(python), "-m", "pip", "install", "-q", "--disable-pip-version-check", "--upgrade", "pip"],
                   check=False, capture_output=True)
    return python


def _pip_install(python: Path, spec: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(python), "-m", "pip", "install", "-q", "--disable-pip-version-check", spec],
        capture_output=True, text=True, check=False,
    )


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def build_wheel(out: Path) -> Path:
    """Build with an isolated `build` frontend in its own venv."""
    builder = _venv(out / "builder")
    installed = _pip_install(builder, "build==1.2.2")
    if installed.returncode != 0:
        raise RuntimeError(f"could not install the build frontend: {installed.stderr[-400:]}")
    result = subprocess.run(
        [str(builder), "-m", "build", "--wheel", "--outdir", str(out / "dist"), str(ROOT)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"wheel build failed: {result.stderr[-800:]}")
    wheels = sorted((out / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected one wheel, found {[w.name for w in wheels]}")
    return wheels[0]


# ── Thin SDK ─────────────────────────────────────────────────────────────────


def check_thin(wheel: Path, work: Path) -> Step:
    python = _venv(work / "thin")
    installed = _pip_install(python, str(wheel))
    if installed.returncode != 0:
        return Step("thin.install", False, f"pip refused the wheel: {installed.stderr[-400:]}")
    listing = subprocess.run([str(python), "-m", "pip", "list", "--format=json", "--disable-pip-version-check"],
                             capture_output=True, text=True, check=False)
    packages = sorted(p["name"].lower() for p in json.loads(listing.stdout or "[]"))
    extras = [p for p in packages if p not in {"pip", "setuptools", "wheel", "sentinel-agent-trust"}]
    if extras:
        return Step("thin.install", False, f"the base install pulled dependencies it must not: {extras}")
    probe = subprocess.run([str(python), "-I", "-c", THIN_PROBE % (SDK_IMPORTS,)],
                           capture_output=True, text=True, check=False)
    if probe.returncode != 0:
        return Step("thin.import", False, f"importing the SDK failed: {probe.stderr[-600:]}")
    line = next((ln for ln in probe.stdout.splitlines() if ln.startswith("NONSTDLIB=")), "NONSTDLIB=?")
    leaked = line[len("NONSTDLIB="):]
    if leaked:
        return Step("thin.import", False, f"importing the SDK loaded non-stdlib modules: {leaked}")
    return Step("thin.import", True,
                f"{len(SDK_IMPORTS)} SDK modules imported; installed packages: {packages}; non-stdlib modules loaded: none")


# ── Server ───────────────────────────────────────────────────────────────────


def _http(base: str, path: str, *, key: str = "", payload: dict | None = None) -> tuple[int, dict | str]:
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(f"{base}{path}", data=data, method="POST" if data else "GET", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - localhost
            body = response.read().decode()
            status = response.status
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace")
        status = error.code
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def check_server(wheel: Path, work: Path) -> list[Step]:
    steps: list[Step] = []
    python = _venv(work / "server")
    installed = _pip_install(python, f"{wheel}[server]")
    if installed.returncode != 0:
        return [Step("server.install", False, f"pip refused the server extra: {installed.stderr[-600:]}")]
    steps.append(Step("server.install", True, "wheel with the server extra installed into a fresh venv"))

    key = secrets.token_urlsafe(32)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SENTINEL_ENV": "development",
        "SENTINEL_DB_PATH": str(work / "smoke.db"),
        "SENTINEL_API_KEYS": f"acme:{key}:admin",
        "SENTINEL_CORS_ORIGINS": "https://console.example.com",
        "SENTINEL_PROTECT_ENFORCE": "true",
    }
    cwd = work / "cwd"
    cwd.mkdir(exist_ok=True)

    for command in ("migrate", "verify"):
        result = subprocess.run([str(python), "-m", "sentinel.interface.cli", command],
                                cwd=str(cwd), env=env, capture_output=True, text=True, check=False)
        ok = result.returncode == 0
        steps.append(Step(f"server.cli.{command}", ok,
                          "exit 0" if ok else f"exit {result.returncode}: {(result.stderr or result.stdout)[-600:]}"))
        if not ok:
            return steps

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [str(python), "-m", "uvicorn", "sentinel.interface.asgi:create_application", "--factory",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        last = "no response yet"
        ready = False
        while time.monotonic() < deadline:
            if process.poll() is not None:
                last = f"server exited with code {process.returncode}: {(process.stdout.read() if process.stdout else '')[-800:]}"
                break
            try:
                status, _ = _http(base, "/health/ready")
                if status == 200:
                    ready = True
                    break
                last = f"readiness returned {status}"
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                last = f"not accepting connections yet ({error})"
            time.sleep(0.4)
        steps.append(Step("server.ready", ready, "GET /health/ready returned 200" if ready else last))
        if not ready:
            return steps

        status, _ = _http(base, "/health/live")
        steps.append(Step("server.live", status == 200, f"GET /health/live returned {status}"))

        for asset, marker in (("/console", "Sentinel Operator Console"),
                              ("/console/app.js", "use strict"),
                              ("/console/app.css", ".topbar")):
            status, body = _http(base, asset)
            ok = status == 200 and isinstance(body, str) and marker in body
            steps.append(Step(f"server.asset.{asset.rsplit('/', 1)[-1]}", ok,
                              f"GET {asset}: status={status}, expected content={ok}"))

        status, body = _http(base, "/v1/protect/evaluate", key=key, payload={
            "agentId": "smoke-agent", "tool": "shell", "action": "exec",
            "resource": "/etc/shadow", "arguments": {"command": "cat /etc/shadow"},
        })
        decision = body.get("decision") if isinstance(body, dict) else None
        ok = status == 200 and decision in {"allow", "warn", "require_approval", "block", "contain", "step_up_auth"}
        steps.append(Step("server.evaluate", ok, f"POST /v1/protect/evaluate returned {status} with decision={decision!r}"))

        status, body = _http(base, "/v1/tools/execute", key=key, payload={
            "agentId": "smoke-agent", "tool": "shell", "action": "exec",
            "resource": "/etc/shadow", "arguments": {"command": "cat /etc/shadow"},
        })
        steps.append(Step("server.unbound_execute_refused", status == 403,
                          f"POST /v1/tools/execute without an authorization returned {status} (403 expected)"))
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
    return steps


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheel", type=Path, default=None, help="use this wheel instead of building one")
    parser.add_argument("--json", type=Path, default=None, help="write the report here")
    parser.add_argument("--skip-server", action="store_true", help="thin SDK check only")
    parser.add_argument("--keep", action="store_true", help="keep the temporary environments")
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="sentinel-smoke-"))
    try:
        wheel = args.wheel.resolve() if args.wheel else build_wheel(work)
        report = Report(wheel=wheel.name, wheel_sha256=_sha256(wheel), python=sys.version.split()[0])
        _say(f"wheel: {wheel.name} sha256={report.wheel_sha256}")
        report.steps.append(check_thin(wheel, work))
        if not args.skip_server:
            report.steps.extend(check_server(wheel, work))
        for step in report.steps:
            _say(f"  [{'ok' if step.ok else 'FAIL'}] {step.name}: {step.observed}")
        _say(f"verdict: {report.verdict}")
        if args.json is not None:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(report.as_dict(), indent=2) + "\n", encoding="utf-8")
        return 0 if report.verdict == "PASS" else 1
    except RuntimeError as exc:
        _say(f"FAILED: {exc}")
        return 2
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
