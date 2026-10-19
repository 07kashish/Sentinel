"""Seat definitions for the Sentinel SOC AI Strategy Council.

Independent models from rival vendors review this repository through their own
CLIs, using each CLI's ambient login. No API keys are read from the environment
unless a seat explicitly declares it needs one: a seat either works because the
user is logged into that CLI, or it is reported as unavailable. Every seat runs
read-only.

Seat availability verified 2026-07-25:
  claude       OK   ambient login, no setup
  codex        OK   ambient login, no setup. The model slug must come from the
                    account's own catalog (`codex debug models`); see the seat below.
  antigravity  OK   Google (Gemini 3.1 Pro) on Antigravity's own OAuth, no API key.
                    Driven by the real vendor CLI, `language_server.exe agentapi`,
                    wrapped by council/antigravity_seat.py. Runs FULLY HEADLESS -- the
                    seat launches its own `--standalone` language server and registers
                    the workspace via AddTrackedWorkspace, so the Antigravity IDE does
                    NOT need to be open. Unlike the other two seats this one is not
                    sandboxed -- it executes tools and shell commands autonomously --
                    so it is instructed to stay read-only in-prompt rather than by
                    policy.
  (The Gemini 2.5 Flash CLI seat that needed GEMINI_API_KEY was removed: Google
   returns IneligibleTierError for Code Assist on personal accounts, so it only ran
   with a paid key. The council now needs no API key -- Gemini is served keyless
   through the headless Antigravity seat above.)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CLAUDE_CMD = r"C:\Users\pc\.local\bin\claude.cmd"
CODEX_CMD = r"C:\Users\pc\.local\bin\codex.cmd"


@dataclass(frozen=True, slots=True)
class Seat:
    """One council member: a vendor CLI invoked headlessly, read-only."""

    key: str
    display: str
    vendor: str
    model: str
    argv: list[str]
    attempts: int = 2
    env: dict[str, str] = field(default_factory=dict)
    # Seats that cannot run on ambient login name the variable they need.
    requires_env: str = ""


_ALL_SEATS: tuple[Seat, ...] = (
    Seat(
        key="claude",
        display="Claude Opus 4.8",
        vendor="Anthropic",
        model="claude-opus-4-8",
        # --allowedTools keeps the seat to read-only inspection; no Edit/Write.
        argv=[
            CLAUDE_CMD,
            "-p",
            "--model",
            "claude-opus-4-8",
            "--allowedTools",
            "Read,Glob,Grep",
        ],
    ),
    Seat(
        key="codex",
        display="Codex GPT-5.6-terra",
        vendor="OpenAI",
        model="gpt-5.6-terra",
        # `-` reads the prompt from stdin; exec defaults to a read-only sandbox.
        # The model is pinned HERE rather than inherited from ~/.codex/config.toml,
        # which still names `gpt-5.6-sol`. That slug is not in this account's
        # server-advertised catalog (`codex debug models` lists gpt-5.6-terra,
        # gpt-5.6-luna, gpt-5.5, gpt-5.4, gpt-5.4-mini), so inheriting the config
        # made every seat call fail with HTTP 400 "model is not supported when
        # using Codex with a ChatGPT account" -- an entitlement error that reads
        # like an auth error and cost a run to diagnose. Pinning an advertised
        # slug keeps the council reproducible regardless of the user's global config.
        argv=[
            CODEX_CMD,
            "exec",
            "--skip-git-repo-check",
            "-m",
            "gpt-5.6-terra",
            "-C",
            str(REPO_ROOT),
            "-",
        ],
    ),
    Seat(
        key="antigravity",
        display="Antigravity (Gemini 3.1 Pro)",
        vendor="Google",
        # Antigravity is OAuth-only -- NO API key. The tier is `pro` (the user's
        # "Gemini 3.1 Pro"). Antigravity reports models under obfuscated placeholder
        # ids (`--model=pro` -> MODEL_PLACEHOLDER_M36), so the exact public version
        # string is not exposed by the CLI; step metadata confirms
        # API_PROVIDER_GOOGLE_GEMINI with thinking tokens.
        model="agentapi --model=pro (MODEL_PLACEHOLDER_M36, Google Gemini, OAuth, no API key)",
        argv=[
            sys.executable,
            str(REPO_ROOT / "council" / "antigravity_seat.py"),
            "--model",
            "pro",
            "--timeout",
            "2400",
        ],
        # A single turn runs ~100 tool steps over tens of minutes; a blind retry
        # would double that for no benefit.
        attempts=1,
    ),
    # The Gemini 2.5 Flash CLI seat (which needed GEMINI_API_KEY) is REMOVED.
    # Google cut off ambient OAuth for personal accounts, so it only ran with a
    # paid API key -- the "api key thing" the user asked to drop. The flash model
    # is now served keyless through the Antigravity seat above, so nothing in the
    # council requires an API key.
)

SEATS: tuple[Seat, ...] = tuple(
    s for s in _ALL_SEATS if not s.requires_env or os.environ.get(s.requires_env)
)
UNAVAILABLE: tuple[Seat, ...] = tuple(s for s in _ALL_SEATS if s not in SEATS)

SEATS_BY_KEY = {seat.key: seat for seat in SEATS}


@dataclass(slots=True)
class SeatResult:
    seat_key: str
    ok: bool
    text: str
    elapsed_sec: float
    attempts_used: int
    error: str = ""


def run_seat(seat: Seat, prompt: str, timeout_sec: int, env_base: dict[str, str]) -> SeatResult:
    """Invoke one seat with `prompt` on stdin. Never raises."""
    started = time.monotonic()
    env = dict(env_base)
    env.update(seat.env)

    last_error = "not attempted"
    for attempt in range(1, seat.attempts + 1):
        try:
            proc = subprocess.run(  # noqa: S603
                seat.argv,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                cwd=str(REPO_ROOT),
                env=env,
            )
        except subprocess.TimeoutExpired:
            last_error = f"timeout after {timeout_sec}s"
            continue
        except OSError as exc:
            # Missing binary is terminal; retrying will not help.
            return SeatResult(
                seat_key=seat.key,
                ok=False,
                text="",
                elapsed_sec=time.monotonic() - started,
                attempts_used=attempt,
                error=f"launch failed: {exc}",
            )

        text = (proc.stdout or "").strip()
        if proc.returncode == 0 and text:
            return SeatResult(
                seat_key=seat.key,
                ok=True,
                text=text,
                elapsed_sec=time.monotonic() - started,
                attempts_used=attempt,
            )
        stderr_tail = _tail(proc.stderr or "", 600)
        last_error = f"exit={proc.returncode}; stderr_tail={stderr_tail}"

    return SeatResult(
        seat_key=seat.key,
        ok=False,
        text="",
        elapsed_sec=time.monotonic() - started,
        attempts_used=seat.attempts,
        error=last_error,
    )


def _tail(text: str, limit: int) -> str:
    """Drop JS stack-trace noise, then keep the tail."""
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith("at ")]
    joined = "\n".join(lines).strip()
    return joined[-limit:]


__all__ = [
    "REPO_ROOT",
    "SEATS",
    "SEATS_BY_KEY",
    "UNAVAILABLE",
    "Seat",
    "SeatResult",
    "run_seat",
]
