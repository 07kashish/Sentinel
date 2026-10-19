"""The agent-CLI advisor: fixed argv, stripped environment, empty cwd, defensive parsing. No real CLI, no database."""
from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.domain.primitives import InvalidValue
from sentinel.infrastructure.cli_advisor import AntigravityCliAdvisor
from sentinel.interface.advisor_check import main

KEYS = {"SENTINEL_API_KEYS": "acme:" + "k" * 40 + ":admin"}
INCIDENT = {"severity": "high", "incident_type": "credential_file_read", "raw_payload": {"secret": "never-forwarded"}}


def _frames(response: str, status: str = "SUCCESS") -> str:
    return "\n".join([
        "chatter that is not a frame",
        json.dumps({"event": "init", "init": {"tools": ["run_command"]}}),
        json.dumps({"event": "result", "result": {"status": status, "response": response}}),
    ])


class _Run:
    def __init__(self, stdout: str = "", returncode: int = 0, raises: Exception | None = None) -> None:
        self.calls: list[dict] = []
        self._stdout, self._returncode, self._raises = stdout, returncode, raises

    def __call__(self, argv, **kwargs):
        self.calls.append({"argv": argv, **kwargs, "cwd_listing": os.listdir(kwargs["cwd"])})
        if self._raises:
            raise self._raises
        return SimpleNamespace(returncode=self._returncode, stdout=self._stdout, stderr="")


def test_the_call_is_sandboxed_isolated_and_never_auto_approves(monkeypatch):
    monkeypatch.setenv("SENTINEL_API_KEYS", "acme:super-secret-key:admin")
    monkeypatch.setenv("SENTINEL_DATABASE_URL", "postgresql://u:p@db/x")
    run = _Run(_frames("Check who read the file.\nRotate the key."))
    advice = AntigravityCliAdvisor(command="/opt/agy", model="gemini-x-pro", run=run).advise(incident=INCIDENT)
    assert advice.available and advice.reasoning.startswith("[unverified-model-output] Check who read")
    assert advice.model_receipt == "antigravity-cli:gemini-x-pro"
    call = run.calls[0]
    assert call["argv"][0] == "/opt/agy" and "--sandbox" in call["argv"] and "--disable-slash-commands" in call["argv"]
    assert "--dangerously-skip-permissions" not in call["argv"]
    assert set(call["env"]) == {"HOME", "PATH"}, "the service's secrets must not reach the agent"
    assert call["cwd_listing"] == [] and not os.path.exists(call["cwd"]), "an empty directory, removed afterwards"
    # The prompt travels on stdin, fenced, and carries only the redacted facts.
    assert all("credential_file_read" not in part for part in call["argv"])
    sent = json.loads(call["input"])["message"]["content"]
    assert "UNTRUSTED_INCIDENT_FACTS" in sent and "credential_file_read" in sent and "never-forwarded" not in sent


@pytest.mark.parametrize("run, reason", [
    (_Run(_frames("x", status="ERROR")), "no successful result"),
    (_Run("not json at all"), "no successful result"),
    (_Run(_frames("<a><b><c><d><e><f><g><h><i>")), "failed shape validation"),
    (_Run(_frames("fine"), returncode=3), "exited with status 3"),
    (_Run(raises=subprocess.TimeoutExpired("agy", 1)), "did not answer within its timeout"),
    (_Run(raises=FileNotFoundError("agy")), "could not be started"),
])
def test_every_failure_is_stated_unavailability_never_an_exception(run, reason):
    advice = AntigravityCliAdvisor(command="/opt/agy", model="m", run=run).advise(incident=INCIDENT)
    assert not advice.available and reason in advice.detail and advice.reasoning == ""


@pytest.mark.parametrize("command, model", [("agy", "m"), ("/opt/agy --dangerously-skip-permissions", "m"),
                                             ("/opt/agy", ""), ("/opt/agy", "--model x"), ("/opt/agy", "a b")])
def test_only_one_absolute_path_and_one_model_name_are_accepted(command, model):
    with pytest.raises(InvalidValue):
        AntigravityCliAdvisor(command=command, model=model)
    with pytest.raises(ConfigurationError):
        Settings.from_environment({**KEYS, "SENTINEL_ADVISOR_CLI_COMMAND": command, "SENTINEL_ADVISOR_MODEL": model})


def test_cli_and_endpoint_are_mutually_exclusive_and_the_container_wires_the_cli():
    cli = {**KEYS, "SENTINEL_ADVISOR_CLI_COMMAND": "/opt/agy", "SENTINEL_ADVISOR_MODEL": "gemini-x-pro"}
    for extra in ({"SENTINEL_ADVISOR_ENDPOINT": "https://model.example/v1"}, {"SENTINEL_ADVISOR_TOKEN": "t"}):
        with pytest.raises(ConfigurationError):
            Settings.from_environment({**cli, **extra})
    container = build_container(Settings.from_environment(cli), verify_schema=False)
    try:
        assert isinstance(container.advisor, AntigravityCliAdvisor)
        assert container.advisor.model_receipt() == "antigravity-cli:gemini-x-pro"
    finally:
        container.close()


def test_the_check_command_reports_a_cli_answer(monkeypatch, capsys):
    for name in ("SENTINEL_ADVISOR_ENDPOINT", "SENTINEL_ADVISOR_TOKEN", "SENTINEL_DB_PATH"):
        monkeypatch.delenv(name, raising=False)
    for name, value in {**KEYS, "SENTINEL_ADVISOR_CLI_COMMAND": "/opt/agy", "SENTINEL_ADVISOR_MODEL": "gemini-x-pro"}.items():
        monkeypatch.setenv(name, value)
    assert main([], cli_run=_Run(_frames("Look at the session that read it."))) == 0
    text = capsys.readouterr().out
    assert "provider antigravity cli, model gemini-x-pro: answered" in text and "authority: none" in text
    assert main(["--list-models"], cli_run=_Run()) == 64


def test_pipeline_worker_count_is_explicit_bounded_and_may_be_zero(monkeypatch):
    from sentinel.interface import asgi

    monkeypatch.delenv("SENTINEL_PIPELINE_WORKERS", raising=False)
    assert asgi._pipeline_workers() == 4
    for raw, expected in (("0", 0), ("8", 8), ("32", 32)):
        monkeypatch.setenv("SENTINEL_PIPELINE_WORKERS", raw)
        assert asgi._pipeline_workers() == expected
    for raw in ("-1", "33", "four", "1.5"):
        monkeypatch.setenv("SENTINEL_PIPELINE_WORKERS", raw)
        with pytest.raises(ValueError):
            asgi._pipeline_workers()


def test_an_api_only_replica_starts_no_pipeline_threads():
    from sentinel.interface.worker import WorkerPool

    container = build_container(Settings.from_environment(KEYS), verify_schema=False)
    try:
        pool = WorkerPool(container, size=0)
        pool.start()
        assert pool._threads == []
        pool.stop()
    finally:
        container.close()


def test_the_cli_home_can_be_set_apart_from_the_process_home():
    env = {**KEYS, "HOME": "/app", "SENTINEL_ADVISOR_CLI_COMMAND": "/opt/agy/agy", "SENTINEL_ADVISOR_MODEL": "m"}
    assert Settings.from_environment(env).advisor.cli_home == "/app"
    assert Settings.from_environment({**env, "SENTINEL_ADVISOR_CLI_HOME": "/var/lib/sentinel-agy"}).advisor.cli_home == "/var/lib/sentinel-agy"
