"""Antigravity council seat — stdin/stdout wrapper around Antigravity's `agentapi` CLI.

This drives the real vendor CLI **headlessly, with no Antigravity IDE**:

    language_server.exe agentapi new-conversation --model=pro "<prompt>"

Earlier this seat required the full Electron IDE to be running, because a naive
standalone `language_server.exe` crashed inside `StartCascade`. That turned out to be
fixable: the IDE's own backend is itself launched with `--standalone`, and the only
things the GUI adds are (a) a couple of launch flags and (b) one RPC that registers
the open folder. Replicate those and the CLI runs with no GUI at all. The four pieces:

1. **Own headless server.** We spawn our *own* `language_server.exe --standalone ...`
   on a fixed HTTP port with a known CSRF token (see `SERVER_FLAGS`). No Electron.
   It reuses the user's OAuth creds under ``~/.gemini`` — no API key.
2. **AddTrackedWorkspace.** A fresh server has no open folder, so cascade's
   `ResolveProjectEnvironment` fails with "file does not exist". Registering the repo
   root via the `AddTrackedWorkspace` RPC is what the IDE does on folder-open; we do it
   explicitly right after the server is up.
3. **ANTIGRAVITY_LS_ADDRESS / _CSRF_TOKEN / _PROJECT_ID** env vars point the `agentapi`
   subcommand at our server. PROJECT_ID must name an existing file at
   ``~/.gemini/config/projects/<id>.json`` — its *absence* is the other, unrelated
   "file does not exist"; contents are otherwise free-form, so we ensure `{}`.

`agentapi` can start a conversation and send messages but has no command to read the
reply, so the answer is collected over the same server's Connect RPC
(`GetCascadeTrajectorySteps`), authenticated with the `x-codeium-csrf-token` header.

Because the prompt is an argv parameter and Windows caps a command line at ~32 KB,
the real prompt is written to a file and the CLI is handed a short pointer to it. The
agent reads the file itself with its own file tools.

Usage:  echo "<prompt>" | py council/antigravity_seat.py [--model pro] [--timeout S]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

LS_EXE = Path(
    r"C:\Users\pc\AppData\Local\Programs\Antigravity\resources\bin\language_server.exe"
)
REPO_ROOT = Path(__file__).resolve().parent.parent
PROMPT_DIR = REPO_ROOT / "council" / "prompts"
PROJECTS_DIR = Path.home() / ".gemini" / "config" / "projects"
PROJECT_ID = "council"

# Our own headless server binds here. The port is fixed (not random) so the seat can
# find and reuse an already-running council server across invocations instead of
# spawning a new one every round.
HTTP_PORT = 52001
CSRF = "council-headless-tok"
# A private app_data_dir so this server's state never collides with the user's IDE.
APP_DATA_DIR = "antigravity-council"

SERVICE = "exa.language_server_pb.LanguageServerService"
RESPONSE_STEP = "CORTEX_STEP_TYPE_PLANNER_RESPONSE"
ERROR_STEP = "CORTEX_STEP_TYPE_ERROR_MESSAGE"
DONE = "CORTEX_STEP_STATUS_DONE"

# A step is still in flight only while it carries one of these. Anything else --
# including CORTEX_STEP_STATUS_ERROR from a tool that failed -- is terminal. A single
# failed grep is normal in a long investigation and must not stall the whole turn.
IN_FLIGHT = ("WAITING", "RUNNING", "PENDING", "GENERATING", "EXECUTING")

# Only these step types, while in-flight, mean the agent is genuinely still working.
# Read-only tool steps (view-file / grep / list) occasionally get stranded in RUNNING
# after the agent has moved on; treating those as "busy" would hang a finished turn
# until the hard timeout, so they are deliberately excluded here.
RUN_COMMAND_STEP = "CORTEX_STEP_TYPE_RUN_COMMAND"
BLOCKING_STEP_TYPES = (RESPONSE_STEP, RUN_COMMAND_STEP)

# Flags that turn a bare language_server into a working headless agent backend. These
# mirror what the Antigravity IDE launches its own backend with (verified from the
# live process command line): --standalone + hub subclient + Gemini/CCPA endpoints +
# sidecars. Without --standalone the projects store never initializes and cascade
# nil-derefs; that was the old "needs the IDE" blocker.
SERVER_FLAGS = [
    "--standalone",
    "--override_ide_name", "antigravity",
    "--subclient_type", "hub",
    "--override_ide_version", "2.3.1",
    "--override_user_agent_name", "antigravity",
    "--https_server_port", "0",
    "--http_server_port", str(HTTP_PORT),
    "--csrf_token", CSRF,
    "--app_data_dir", APP_DATA_DIR,
    "--api_server_url", "https://generativelanguage.googleapis.com",
    "--cloud_code_endpoint", "https://daily-cloudcode-pa.googleapis.com",
    "--enable_sidecars",
]

BASE_URL = f"http://localhost:{HTTP_PORT}"


class SeatError(RuntimeError):
    pass


def _server_alive() -> bool:
    """True if our headless server already answers on HTTP_PORT."""
    try:
        req = urllib.request.Request(
            f"{BASE_URL}/{SERVICE}/GetWorkspaceInfos",
            data=b"{}",
            headers={"Content-Type": "application/json", "x-codeium-csrf-token": CSRF},
        )
        urllib.request.urlopen(req, timeout=10)
        return True
    except urllib.error.HTTPError as exc:
        # 200 or an auth/other HTTP status both mean a server is listening.
        return True if exc.code else False
    except Exception:  # noqa: BLE001
        return False


def ensure_server() -> None:
    """Start our own headless language server if one isn't already up. No IDE needed."""
    if _server_alive():
        return

    creationflags = 0
    if os.name == "nt":
        # Detach so the server outlives this seat process and can be reused next round.
        creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    try:
        subprocess.Popen(  # noqa: S603
            [str(LS_EXE), *SERVER_FLAGS],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            cwd=str(REPO_ROOT),
            creationflags=creationflags,
        )
    except OSError as exc:
        raise SeatError(f"could not launch headless language server: {exc}") from exc

    for _ in range(40):  # up to ~40s for the server to bind and initialize
        if _server_alive():
            return
        time.sleep(1)
    raise SeatError("headless language server did not come up within 40s")


def rpc(method: str, body: dict, timeout: int = 120, retries: int = 4) -> dict:
    # A freshly launched server accepts the socket but sometimes resets the first
    # request or two while its workspace/cascade managers finish wiring up. Those
    # surface as RemoteDisconnected / ConnectionError, not HTTP status, so retry them
    # with a short backoff instead of letting a raw traceback escape.
    last: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(
            f"{BASE_URL}/{SERVICE}/{method}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "x-codeium-csrf-token": CSRF},
        )
        try:
            return json.loads(urllib.request.urlopen(req, timeout=timeout).read().decode())
        except urllib.error.HTTPError as exc:
            raise SeatError(
                f"{method} -> HTTP {exc.code}: {exc.read().decode()[:250]}"
            ) from exc
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise SeatError(f"{method} unreachable after {retries} tries: {last}")


def register_workspace() -> None:
    """Tell the headless server which folder is the workspace.

    A standalone server has no open folder, so cascade cannot resolve the project
    environment ("file does not exist") until the repo root is registered -- exactly
    what the IDE does on folder-open. Idempotent; the server accepts repeats.
    """
    rpc("AddTrackedWorkspace", {"workspacePath": str(REPO_ROOT)}, timeout=30)


# EAGER auto-execution is mandatory headless: a shell command otherwise posts a
# RUN_COMMAND step with status WAITING for an approval no UI can give, hanging the turn
# until timeout. File-read tools auto-run regardless; this covers the command case. The
# council prompt keeps the agent read-only, so eager execution is a UX choice, not a
# safety one.
PROJECT_SETTINGS = {
    "autoExecutionPolicy": "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER",
    "cascadeAutoExecutionPolicy": "CASCADE_COMMANDS_AUTO_EXECUTION_EAGER",
    "autoInteractionBehavior": "AUTO_INTERACTION_BEHAVIOR_ALLOW_ALL",
    "terminalAutoExecutionEnabled": True,
    "artifactReviewMode": "ARTIFACT_REVIEW_MODE_TURBO",
}


def ensure_project() -> None:
    """Ensure ~/.gemini/config/projects/<id>.json exists WITH eager auto-execution.

    agentapi treats the file's absence as fatal ("file does not exist"), and a file
    lacking the eager-execution settings makes every shell command stall on approval.
    Write the full doc if the file is missing or has no `settings` block, so the seat is
    self-sufficient even if the project file was deleted.
    """
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    path = PROJECTS_DIR / f"{PROJECT_ID}.json"
    doc = {"id": PROJECT_ID, "name": "Council", "settings": dict(PROJECT_SETTINGS)}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
        # Only rewrite if auto-execution isn't already eager; don't clobber a hand-edited
        # file that already has what we need.
        if (existing.get("settings") or {}).get(
            "autoExecutionPolicy"
        ) == PROJECT_SETTINGS["autoExecutionPolicy"]:
            return
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def start_conversation(prompt: str, model: str) -> str:
    """Invoke the real agentapi CLI against our headless server. Returns the conv id."""
    PROMPT_DIR.mkdir(parents=True, exist_ok=True)
    prompt_path = PROMPT_DIR / f"prompt_{uuid.uuid4().hex[:8]}.md"
    prompt_path.write_text(prompt, encoding="utf-8")

    pointer = (
        f"Read the file {prompt_path.as_posix()} and follow the instructions inside it "
        "exactly. That file is your full brief. Review the repository read-only: you may "
        "read and search files, but do not create, edit, or delete any file, and do not "
        "run commands that change state. Reply with the requested markdown only."
    )

    env = dict(os.environ)
    env.update(
        {
            "ANTIGRAVITY_LS_ADDRESS": BASE_URL,
            "ANTIGRAVITY_CSRF_TOKEN": CSRF,
            "ANTIGRAVITY_PROJECT_ID": PROJECT_ID,
        }
    )

    proc = subprocess.run(  # noqa: S603
        [str(LS_EXE), "agentapi", "new-conversation", f"--model={model}", pointer],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(REPO_ROOT),
        env=env,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SeatError(f"agentapi returned non-JSON: {proc.stdout[:200]}") from exc

    if payload.get("error"):
        raise SeatError(f"agentapi: {payload['error']}")
    cid = (payload.get("response") or {}).get("newConversation", {}).get("conversationId")
    if not cid:
        raise SeatError(f"agentapi gave no conversationId: {proc.stdout[:200]}")
    return cid


def collect(cid: str, timeout: int, poll_sec: int = 15) -> str:
    """Poll the trajectory until it settles, then return the final prose answer."""
    deadline = time.time() + timeout
    count_stable = 0
    last_count = -1

    while time.time() < deadline:
        steps = rpc("GetCascadeTrajectorySteps", {"cascadeId": cid}).get("steps", [])

        errors = [
            (s.get("errorMessage") or {}).get("content", "")
            for s in steps
            if s.get("type") == ERROR_STEP
        ]
        if any(errors):
            raise SeatError(f"cascade error: {' | '.join(e for e in errors if e)[:300]}")

        replies = [
            (s.get("plannerResponse") or {}).get("modifiedResponse")
            or (s.get("plannerResponse") or {}).get("response")
            or ""
            for s in steps
            if s.get("type") == RESPONSE_STEP and s.get("status") == DONE
        ]
        text = "\n\n".join(r.strip() for r in replies if r.strip())

        # A conversation is "actively generating" only while a PLANNER_RESPONSE or a
        # RUN_COMMAND is in flight. File-view / grep / list tool steps are sometimes
        # left stranded in RUNNING forever after the agent moves on -- those zombie
        # steps must NOT be read as "still working", or a finished turn hangs until
        # the hard timeout even though the full answer is already present.
        active = any(
            s.get("type") in BLOCKING_STEP_TYPES
            and any(flag in (s.get("status") or "") for flag in IN_FLIGHT)
            for s in steps
        )

        # Track how long the trajectory has stopped growing, independent of `active`.
        count_stable = count_stable + 1 if len(steps) == last_count else 0
        last_count = len(steps)

        # Normal completion: answer present, nothing generating, count held steady.
        if text and not active and count_stable >= 2:
            return text
        # Zombie guard: the trajectory has been frozen for ~90s (agent stopped adding
        # steps) but a non-blocking tool step is stuck RUNNING. Return what we have
        # rather than poll uselessly to the hard timeout.
        if text and count_stable >= 6:
            return text

        time.sleep(poll_sec)

    raise SeatError(f"no settled response within {timeout}s (conversation {cid})")


def main() -> int:
    ap = argparse.ArgumentParser(description="Antigravity council seat (stdin -> stdout).")
    ap.add_argument("--model", default="pro", choices=("flash_lite", "flash", "pro"))
    ap.add_argument("--timeout", type=int, default=1500)
    args = ap.parse_args()

    prompt = sys.stdin.read().strip()
    if not prompt:
        print("no prompt on stdin", file=sys.stderr)
        return 2
    # Peer transcripts arrive via stdin and can carry lone surrogates (Windows
    # console decoding), which are unencodable in UTF-8 and would blow up the
    # prompt-file write. Scrub them rather than lose the round.
    prompt = prompt.encode("utf-8", "replace").decode("utf-8", "replace")

    try:
        ensure_server()
        register_workspace()
        ensure_project()
        cid = start_conversation(prompt, args.model)
        sys.stdout.write(collect(cid, args.timeout) + "\n")
        return 0
    except SeatError as exc:
        print(f"antigravity seat failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
