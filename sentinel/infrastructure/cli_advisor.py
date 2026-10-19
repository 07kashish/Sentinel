"""An advisory model reached through a locally signed-in agent CLI (Antigravity's `agy`).

Same contract and the same lack of authority as `HttpModelAdvisor`: the text
lands in `advisory_*` facts and the report, never in priority. What differs is
the transport, and the transport is the risk. `agy` is an AGENT, with tools,
being handed attacker-influenced incident text. So:

* never `--dangerously-skip-permissions`: in print mode an unapproved tool
  request is simply not run, which is the property this relies on;
* `--sandbox` and `--disable-slash-commands`, so the text cannot expand into a
  command or reach the terminal unrestricted;
* an EMPTY working directory created per call, so there is no repository for
  the agent to read, and a child environment of HOME and PATH only -- the
  service's keys, DSN and data key are not inherited;
* the prompt goes on stdin as one NDJSON frame, never on the command line,
  where it would be visible in the process table;
* a hard timeout (two minutes: measured answers took 10-60 seconds, and the
  call runs on a pipeline worker thread, not on a request), and output through the same shape validation and provenance
  stamp as the HTTP adapter.

These reduce the blast radius; they do not make an agent CLI a safe parser of
hostile text. The control remains that nothing here can move triage.
"""
from __future__ import annotations

import json
import os
import subprocess  # noqa: S404 - fixed argv, no shell, see the module docstring
import tempfile
from typing import Any, Callable, Mapping

from sentinel.application.records import ModelAdvice
from sentinel.domain.primitives import InvalidValue
from sentinel.infrastructure.model_advisor import (
    _PROVENANCE_TAG,
    _SYSTEM_INSTRUCTION,
    _build_prompt,
    _sanitise_output,
)

__all__ = ["AntigravityCliAdvisor"]

#: A CLI answer is small; anything larger is not the prose that was asked for.
_MAX_STDOUT_BYTES = 1_048_576


class AntigravityCliAdvisor:
    """Runs `agy` once per incident in print mode and records its answer as advice."""

    __slots__ = ("_command", "_model", "_timeout", "_run", "_home")

    def __init__(self, *, command: str, model: str, home: str = "", timeout_seconds: float = 120.0,
                 run: Callable[..., Any] = subprocess.run) -> None:
        if not os.path.isabs(command) or any(ch.isspace() for ch in command):
            raise InvalidValue("the advisor CLI command must be one absolute path with no arguments")
        if not model or any(ch.isspace() for ch in model) or model.startswith("-"):
            raise InvalidValue("the advisor CLI model must be a single model name")
        self._command, self._model, self._timeout, self._run = command, model, timeout_seconds, run
        self._home = home

    def model_receipt(self) -> str:
        return f"antigravity-cli:{self._model}"

    def advise(self, *, incident: Mapping[str, Any]) -> ModelAdvice:
        prompt = f"{_SYSTEM_INSTRUCTION}\n\n{_build_prompt(incident)}"
        frame = json.dumps({"event": "user", "message": {"role": "user", "content": prompt}}) + "\n"
        argv = [self._command, "--input-format", "stream-json", "--output-format", "stream-json",
                "--model", self._model, "--sandbox", "--disable-slash-commands",
                "--print-timeout", f"{int(self._timeout)}s", "-p="]
        child_env = {"HOME": self._home, "PATH": "/usr/local/bin:/usr/bin:/bin"}
        try:
            with tempfile.TemporaryDirectory(prefix="sentinel-advisor-") as empty:
                done = self._run(argv, input=frame, capture_output=True, check=False, text=True,  # noqa: S603
                                 timeout=self._timeout + 5, cwd=empty, env=child_env)
        except subprocess.TimeoutExpired:
            return ModelAdvice.unavailable("the advisor CLI did not answer within its timeout")
        except OSError as exc:
            return ModelAdvice.unavailable(f"the advisor CLI could not be started: {type(exc).__name__}")
        if done.returncode != 0:
            return ModelAdvice.unavailable(f"the advisor CLI exited with status {done.returncode}")
        text = _result_text(str(done.stdout)[:_MAX_STDOUT_BYTES])
        if text is None:
            return ModelAdvice.unavailable("the advisor CLI reported no successful result")
        cleaned = _sanitise_output(text)
        if cleaned is None:
            return ModelAdvice.unavailable(
                "the advisor CLI returned output that failed shape validation and was discarded rather than stored"
            )
        return ModelAdvice(available=True, detail="advisory second opinion recorded; it is not authoritative",
                           model_receipt=self.model_receipt(), reasoning=f"{_PROVENANCE_TAG} {cleaned}"[:4000])


def _result_text(stdout: str) -> str | None:
    """The `response` of the final SUCCESS `result` frame; None for anything else."""
    answer: str | None = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue  # progress chatter, not a protocol frame
        if not isinstance(event, dict) or event.get("event") != "result":
            continue
        result = event.get("result")
        if not isinstance(result, dict) or str(result.get("status", "")).upper() != "SUCCESS":
            return None
        answer = str(result.get("response") or "")
    return answer or None
