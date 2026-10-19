"""Containment and observation are different things, and this conflates neither.

A container is good at stopping a skill doing harm and bad at recording what it
tried to do. The dangerous outcome is therefore not an escape -- it is a CLEAN
VERDICT about a skill nobody watched, because an uninstrumented run produces an
empty `network_destinations` tuple that reads exactly like "made no network
calls".

Most of these tests run with no daemon installed, by asserting on the pure
argument vector rather than on a live container. That is deliberate: the
isolation has to be checkable in CI, and a check that only runs where Docker
exists is a check that does not run.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from sentinel.domain.detonation import (
    DetonationUnavailable,
    RefusingDetonator,
    assess,
)
from sentinel.infrastructure.detonation_container import (
    DEFAULT_TIMEOUT_SECONDS,
    ISOLATION_KIND,
    REQUIRED_ISOLATION_FLAGS,
    UNOBSERVED_BEHAVIOURS,
    ContainerDetonator,
    build_run_argv,
    required_flags_missing_from,
    runtime_available,
)

CANARIES = {"api_key": "canary-4f2a-value", "token": "canary-9b1c-value"}


def _argv(**kwargs) -> tuple[str, ...]:
    defaults = dict(
        image="sentinel/detonate:pinned",
        package_path="/tmp/pkg.bin",
        skill_id="skill-1",
        canaries=CANARIES,
    )
    defaults.update(kwargs)
    return build_run_argv(**defaults)  # type: ignore[arg-type]


# ── the isolation, asserted against the real argv ────────────────────────────


def test_every_required_isolation_flag_is_in_the_command():
    """Read from the vector that is actually executed, not from a comment.

    Every previous version of this kind of check in this codebase passed while
    reading something other than what it appeared to read.
    """
    assert required_flags_missing_from(_argv()) == ()


def test_the_network_is_severed():
    """The single most valuable flag: it turns exfiltration and callback into
    failures rather than successes.
    """
    assert "--network=none" in _argv()


def test_every_linux_capability_is_dropped():
    assert "--cap-drop=ALL" in _argv()


def test_the_root_filesystem_is_read_only_and_the_workspace_is_noexec():
    argv = _argv()

    assert "--read-only" in argv
    workspace = next(a for a in argv if a.startswith("--tmpfs=/workspace"))
    assert "noexec" in workspace
    assert "nosuid" in workspace


def test_the_skill_does_not_run_as_root():
    """A runtime escape should land as an unprivileged user, not as root."""
    assert "--user=65534:65534" in _argv()


def test_setuid_binaries_cannot_elevate():
    assert "--security-opt=no-new-privileges" in _argv()


def test_a_fork_bomb_and_an_allocation_loop_are_capped():
    argv = _argv()

    assert "--pids-limit=64" in argv
    assert "--memory=256m" in argv


def test_the_package_is_mounted_read_only():
    """A skill that could rewrite its own package would defeat the digest that
    was reviewed.
    """
    argv = _argv(package_path="/staging/package.bin")
    mount = next(a for a in argv if a.startswith("--volume="))

    assert mount.endswith(":ro")
    assert "/staging/package.bin" in mount


def test_the_container_is_removed_on_exit():
    assert "--rm" in _argv()


def test_dropping_a_flag_is_detected_rather_than_assumed_absent():
    """The guard must be able to FAIL, or it proves nothing.

    Asserting only the positive case would pass just as happily against a
    function that returned an empty tuple unconditionally.
    """
    weakened = tuple(a for a in _argv() if a != "--network=none")

    assert required_flags_missing_from(weakened) == ("--network=none",)


def test_the_missing_flags_are_named_rather_than_reduced_to_a_boolean():
    """"Isolation is wrong" and "the network flag is missing" call for
    different responses.
    """
    stripped = tuple(
        a for a in _argv() if a not in {"--network=none", "--cap-drop=ALL"}
    )

    assert required_flags_missing_from(stripped) == (
        "--cap-drop=ALL",
        "--network=none",
    )


def test_the_argv_is_deterministic():
    assert _argv() == _argv()


# ── refusals ─────────────────────────────────────────────────────────────────


def test_a_missing_runtime_refuses_rather_than_falling_back():
    """No subprocess fallback, on purpose.

    A subprocess on this host shares the filesystem, network position,
    environment and credentials of the control plane -- the exact attack the
    feature prevents, reached by precisely the deployments that never
    configured isolation.
    """
    detonator = ContainerDetonator(
        image="sentinel/detonate:pinned", binary="definitely-not-installed-xyz"
    )

    with pytest.raises(DetonationUnavailable) as raised:
        detonator.detonate(skill_id="s", package=b"x", canaries={})

    message = str(raised.value)
    assert "not on PATH" in message
    assert "no subprocess fallback" in message


def test_an_unconfigured_image_is_refused():
    """Falling back to a default image nobody reviewed is worse than failing."""
    with pytest.raises(ValueError) as raised:
        _argv(image="   ")
    assert "nobody reviewed" in str(raised.value)


def test_a_non_positive_timeout_is_refused():
    with pytest.raises(ValueError) as raised:
        _argv(timeout_seconds=0)
    assert "wall-clock ceiling" in str(raised.value)


def test_the_detonator_refuses_if_its_own_argv_loses_a_flag(monkeypatch):
    """Belt and braces against a future edit to `build_run_argv`.

    Executing an untrusted skill with isolation somebody weakened by accident
    is worse than not executing it, because the result would be trusted.
    """
    import sentinel.infrastructure.detonation_container as module

    monkeypatch.setattr(module, "runtime_available", lambda binary="docker": True)
    monkeypatch.setattr(
        module,
        "build_run_argv",
        lambda **kwargs: ("docker", "run", "sentinel/detonate:pinned"),
    )

    detonator = ContainerDetonator(image="sentinel/detonate:pinned")
    with pytest.raises(DetonationUnavailable) as raised:
        detonator.detonate(skill_id="s", package=b"x", canaries={})

    assert "missing required isolation flags" in str(raised.value)


def test_a_runtime_that_cannot_start_raises_rather_than_reporting_a_result(
    monkeypatch,
):
    """An infrastructure fault is not a verdict about the skill.

    A tooling failure that reads as a clean run is worse than no run at all.
    """
    import sentinel.infrastructure.detonation_container as module

    monkeypatch.setattr(module, "runtime_available", lambda binary="docker": True)

    def explode(*args, **kwargs):
        raise OSError("cannot connect to the daemon socket")

    monkeypatch.setattr(module.subprocess, "run", explode)

    with pytest.raises(DetonationUnavailable) as raised:
        ContainerDetonator(image="i").detonate(
            skill_id="s", package=b"x", canaries={}
        )

    assert "clean run is worse than no run" in str(raised.value)


# ── the honesty about what was NOT observed ──────────────────────────────────


class _FakeCompleted:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", code: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = code


def _run_with(monkeypatch, *, stdout=b"", stderr=b"", code=0, canaries=CANARIES):
    import sentinel.infrastructure.detonation_container as module

    monkeypatch.setattr(module, "runtime_available", lambda binary="docker": True)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: _FakeCompleted(stdout, stderr, code),
    )
    return ContainerDetonator(image="i").detonate(
        skill_id="s", package=b"x", canaries=canaries
    )


def test_every_recording_admits_the_observation_was_incomplete(monkeypatch):
    """THE property this module turns on.

    An OCI run reports an exit code and output streams. It does not report
    files read, hosts contacted or processes spawned -- so an empty
    `network_destinations` means nothing, and must not be allowed to read as
    "made no network calls".
    """
    observation = _run_with(monkeypatch)

    assert observation.observation_incomplete is True
    assert observation.network_destinations == ()


def test_the_reason_names_each_behaviour_that_was_not_watched(monkeypatch):
    """"Coverage was partial" is a shrug wearing a data structure. An analyst
    needs to know exactly which absences in the recording mean nothing.
    """
    reason = _run_with(monkeypatch).incomplete_reason

    for behaviour in UNOBSERVED_BEHAVIOURS:
        assert behaviour in reason, f"{behaviour} not named as unwatched"


def test_the_reason_distinguishes_containment_from_observation(monkeypatch):
    """Containment held even though observation did not, and an operator
    deciding whether to be alarmed needs both halves.
    """
    reason = _run_with(monkeypatch).incomplete_reason

    assert "network=none" in reason
    assert "not seen" in reason or "not watched" in reason


def test_a_clean_verdict_cannot_be_reached_from_an_uninstrumented_run(monkeypatch):
    """The consequence, checked end to end through the real judge.

    A skill that did nothing observable must not come back as verified safe,
    because nothing observed it.
    """
    observation = _run_with(monkeypatch)
    verdict = assess(observation, canaries=CANARIES)

    # Read the VALUE, not the serialised text. A substring search for
    # "incomplete" passes for every verdict ever produced, because the key
    # `observation_incomplete` is always present whatever it is set to -- so
    # the first version of this assertion passed identically against a fully
    # observed run and checked nothing at all.
    assert observation.observation_incomplete is True
    assert verdict.as_dict()["observation_incomplete"] is True, (
        "the verdict does not carry the incompleteness forward, so a consumer "
        "reading only the verdict would treat an unwatched run as clean"
    )
    # The negative case, so this test can fail. Without it the assertion above
    # would still pass against a judge that hardcoded True.
    fully_observed = assess(
        type(observation)(skill_id="s", observation_incomplete=False),
        canaries=CANARIES,
    )
    assert fully_observed.as_dict()["observation_incomplete"] is False


def test_a_timeout_produces_a_recording_rather_than_an_absence(monkeypatch):
    """An absent finding reads as clean, so a hang must be recorded."""
    import sentinel.infrastructure.detonation_container as module

    monkeypatch.setattr(module, "runtime_available", lambda binary="docker": True)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=30)

    monkeypatch.setattr(module.subprocess, "run", timeout)

    observation = ContainerDetonator(image="i").detonate(
        skill_id="s", package=b"x", canaries={}
    )

    assert observation.observation_incomplete is True
    assert "did not finish" in observation.incomplete_reason


# ── the one behaviour that IS observable ─────────────────────────────────────


def test_a_canary_printed_by_the_skill_is_recorded_as_an_exfiltration_attempt(
    monkeypatch,
):
    """With the network cut, stdout is the remaining channel.

    A skill that prints a seeded credential was trying to get it out, and that
    is a genuine observation rather than an inference.
    """
    observation = _run_with(
        monkeypatch, stdout=b"leaking canary-4f2a-value now"
    )

    assert observation.outbound_payloads == ("api_key",)


def test_a_canary_on_stderr_counts_too(monkeypatch):
    observation = _run_with(monkeypatch, stderr=b"oops canary-9b1c-value")

    assert observation.outbound_payloads == ("token",)


def test_printing_the_variable_name_without_its_value_is_not_a_finding(
    monkeypatch,
):
    """A skill that printed only the name has demonstrated nothing. Matching on
    the name would fire on any skill that logged its own configuration.
    """
    observation = _run_with(
        monkeypatch, stdout=b"reading SENTINEL_CANARY_api_key from env"
    )

    assert observation.outbound_payloads == ()


def test_an_empty_canary_value_never_matches(monkeypatch):
    """An empty string is a substring of every output, so an unset canary would
    otherwise report every skill as exfiltrating.
    """
    observation = _run_with(
        monkeypatch, stdout=b"anything at all", canaries={"unset": ""}
    )

    assert observation.outbound_payloads == ()


def test_output_that_is_not_utf8_does_not_crash_the_run(monkeypatch):
    """A decode error here would surface as a crash in the analysis layer and
    be filed as a scanner fault instead of as the skill's output -- which has
    already happened once in this codebase.
    """
    observation = _run_with(monkeypatch, stdout=b"\xff\xfe invalid bytes")

    assert observation.observation_incomplete is True


# ── the boundary is named honestly ───────────────────────────────────────────


def test_the_isolation_is_called_a_container_and_not_a_sandbox():
    """An operator who reads "sandboxed" allows a different set of skills than
    one who reads "shares the host kernel".
    """
    assert ISOLATION_KIND == "container"


def test_the_module_states_that_a_container_is_not_a_virtual_machine():
    """Left implied, somebody ships this and calls the problem solved."""
    import inspect

    from sentinel.infrastructure import detonation_container

    doc = " ".join((inspect.getdoc(detonation_container) or "").split())

    assert "not a virtual machine" in doc.lower()
    assert "shares the host kernel" in doc
    assert "kernel exploit escapes" in doc


def test_the_module_distinguishes_containment_from_observation():
    import inspect

    from sentinel.infrastructure import detonation_container

    doc = " ".join((inspect.getdoc(detonation_container) or "").split())

    assert "Containment" in doc
    assert "Observation" in doc


def test_the_refusing_detonator_is_still_the_default_for_the_unconfigured():
    """Adding a real implementation must not turn the no-isolation case into a
    silent pass.
    """
    with pytest.raises(DetonationUnavailable):
        RefusingDetonator().detonate(skill_id="s", package=b"x", canaries={})


def test_runtime_availability_is_resolved_the_way_subprocess_resolves_it():
    """A check in this codebase previously looked for a tool that was installed
    but not on PATH and concluded it was absent.
    """
    assert runtime_available("definitely-not-installed-xyz") is False
    assert runtime_available("python") is (shutil.which("python") is not None)


def test_the_default_timeout_is_bounded():
    assert 0 < DEFAULT_TIMEOUT_SECONDS <= 300


def test_the_required_flag_set_is_immutable():
    assert isinstance(REQUIRED_ISOLATION_FLAGS, frozenset)


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.infrastructure import detonation_container

    mutable = [
        name
        for name, value in vars(detonation_container).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
