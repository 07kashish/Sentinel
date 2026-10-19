"""Dynamic skill analysis: the contract, the verdict, and the refusal.

WHAT IS BUILT HERE AND WHAT IS NOT
------------------------------------
Built: the observation record a sandbox produces, the verdict logic over it, the
canary mechanism, typosquat detection, and a port a real isolation boundary
implements.

NOT built: the isolation boundary. A gVisor sandbox or a Firecracker microVM is
infrastructure this repository cannot stand up, and pretending otherwise would
be the fake-integration failure the non-negotiables forbid. `RefusingDetonator`
is what a deployment without one gets.

THE TEST THAT MATTERS MOST IS A GREP
--------------------------------------
`test_nothing_here_can_execute_anything`. The tempting shape for a missing
sandbox is "fall back to a subprocess with a timeout and reduced privileges",
and that is worse than having nothing: a subprocess on the control-plane host
shares its filesystem, its network position, its environment and its
credentials. The degraded mode would be precisely the attack the feature exists
to prevent, reached by exactly the deployments that never configured isolation.

WHY THE CANARY IS THE ONLY PROOF
----------------------------------
"Did this skill steal credentials" is not answerable by watching syscalls — a
skill legitimately reads configuration and legitimately makes requests. What IS
answerable is whether a value existing nowhere but the sandbox appeared in an
outbound payload. Everything else in this module is signal; that one is proof,
and `proven_malicious` is reserved for it.
"""

from __future__ import annotations

import pytest

from sentinel.domain.detonation import (
    Behaviour,
    DetonationObservation,
    DetonationUnavailable,
    Detonator,
    RefusingDetonator,
    assess,
    typosquat_candidates,
)

CANARIES = {"aws_secret_key": "AKIA-CANARY-9f3c1d2e4b5a6789"}


def _observed(**overrides) -> DetonationObservation:
    base = {"skill_id": "invoice-reader"}
    base.update(overrides)
    return DetonationObservation(**base)


def _behaviours(verdict) -> set[Behaviour]:
    return {f.behaviour for f in verdict.findings}


# ── the refusal, which is the honest default ─────────────────────────────────


def test_a_deployment_with_no_sandbox_refuses_rather_than_running_anything():
    with pytest.raises(DetonationUnavailable, match="no subprocess fallback"):
        RefusingDetonator().detonate(
            skill_id="unknown-skill", package=b"whatever", canaries={}
        )


def test_the_refusal_is_not_retryable():
    """A deployment will not acquire a sandbox between two attempts, and
    retrying turns a configuration gap into a loop.
    """
    assert DetonationUnavailable.is_retryable is False


def test_nothing_here_can_execute_anything():
    """THE test. A domain module that could execute a skill would be one that
    runs untrusted code on the control plane — the single thing the
    specification forbids outright.

    Checked by INSPECTING IMPORTS AND CALLS, not by scanning text. Two earlier
    versions of this failed on their own subject matter: the module docstring
    explains at length why there is no `subprocess` fallback, and
    `RefusingDetonator`'s error message says the same thing to whoever hits it.
    Both are prose that a substring search cannot tell from an import.

    Imports and call targets are what the interpreter would actually act on, so
    reading them is both precise and immune to the module describing itself.
    """
    import ast
    import inspect

    from sentinel.domain import detonation

    FORBIDDEN_MODULES = {
        "subprocess",
        "socket",
        "ctypes",
        "pty",
        "multiprocessing",
        "importlib",
        "runpy",
        "shutil",
        "tempfile",
    }
    FORBIDDEN_CALLS = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "system",
        "popen",
        "spawn",
        "fork",
        "execv",
    }

    tree = ast.parse(inspect.getsource(detonation))
    imported: set[str] = set()
    called: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                called.add(target.id)
            elif isinstance(target, ast.Attribute):
                called.add(target.attr)

    assert not (imported & FORBIDDEN_MODULES), (
        f"detonation.py imports {sorted(imported & FORBIDDEN_MODULES)}; this "
        "module records and judges, it must never be able to run anything"
    )
    assert not (called & FORBIDDEN_CALLS), (
        f"detonation.py calls {sorted(called & FORBIDDEN_CALLS)}; same reason"
    )


def test_the_refusing_detonator_satisfies_the_port():
    """So a container can hold it wherever a real sandbox would go, and the
    absence of isolation is a wiring fact rather than a special case.
    """
    assert isinstance(RefusingDetonator(), Detonator)


# ── the canary: proof, not signal ────────────────────────────────────────────


def test_a_seeded_credential_in_an_outbound_payload_is_proof():
    """That value exists nowhere but the sandbox. There is exactly one way it
    reaches a network.
    """
    verdict = assess(
        _observed(
            outbound_payloads=(
                f'{{"data": "{CANARIES["aws_secret_key"]}"}}',
            )
        ),
        canaries=CANARIES,
    )
    assert Behaviour.CANARY_EXFILTRATION in _behaviours(verdict)
    assert verdict.proven_malicious is True
    assert verdict.score == 100


def test_everything_other_than_the_canary_is_signal_not_proof():
    """A skill that reads a credential file may be doing its job. Reserving
    `proven_malicious` keeps the word meaning something.
    """
    verdict = assess(
        _observed(files_read=("/home/app/.aws/credentials",)), canaries=CANARIES
    )
    assert Behaviour.CREDENTIAL_FILE_READ in _behaviours(verdict)
    assert verdict.proven_malicious is False


def test_a_clean_run_finds_nothing_and_says_it_proves_nothing():
    """A skill that checks the date, waits for a real credential, or recognises
    a sandbox does nothing here and everything in production.
    """
    verdict = assess(_observed(), canaries=CANARIES)
    assert verdict.findings == ()
    assert verdict.score == 0
    assert "NOT a safety certificate" in verdict.as_dict()["limits"]


# ── the behaviours ───────────────────────────────────────────────────────────


def test_reading_a_credential_path_is_reported_whatever_the_skill_claims():
    for path in (
        "/root/.aws/credentials",
        "/home/u/.ssh/id_rsa",
        "/var/run/secrets/token",
        "/home/u/.kube/config",
    ):
        verdict = assess(_observed(files_read=(path,)), canaries={})
        assert Behaviour.CREDENTIAL_FILE_READ in _behaviours(verdict), path


def test_writing_a_persistence_path_is_reported():
    """A skill writing here is asking to run again when nobody invoked it."""
    verdict = assess(_observed(files_written=("/home/u/.bashrc",)), canaries={})
    assert Behaviour.PERSISTENCE_ATTEMPT in _behaviours(verdict)


def test_remote_code_execution_outranks_most_things():
    """Whatever was reviewed, this is not what ran."""
    verdict = assess(
        _observed(remote_code_loaded=("https://cdn.evil/payload.py",)), canaries={}
    )
    assert Behaviour.REMOTE_CODE_LOADED in _behaviours(verdict)
    assert verdict.score == 80


def test_traffic_beyond_the_manifest_is_undeclared_even_when_it_looks_benign():
    verdict = assess(
        _observed(network_destinations=("api.github.com", "telemetry.unknown.io")),
        canaries={},
        declared_destinations=("api.github.com",),
    )
    undeclared = [
        f for f in verdict.findings if f.behaviour is Behaviour.UNDECLARED_NETWORK
    ]
    assert len(undeclared) == 1
    assert undeclared[0].evidence == "telemetry.unknown.io"


def test_installing_a_package_at_runtime_is_reported():
    """What executes is no longer what was scanned."""
    verdict = assess(_observed(packages_installed=("requests",)), canaries={})
    assert Behaviour.PACKAGE_INSTALLED_AT_RUNTIME in _behaviours(verdict)


def test_reading_secret_shaped_environment_is_harvesting():
    verdict = assess(
        _observed(environment_read=("PATH", "AWS_SECRET_ACCESS_KEY", "HOME")),
        canaries={},
    )
    assert Behaviour.ENVIRONMENT_HARVESTED in _behaviours(verdict)


def test_reading_ordinary_environment_is_not_harvesting():
    """Reporting PATH and HOME would bury the finding that matters."""
    verdict = assess(_observed(environment_read=("PATH", "HOME", "LANG")), canaries={})
    assert Behaviour.ENVIRONMENT_HARVESTED not in _behaviours(verdict)


# ── scoring and honesty ──────────────────────────────────────────────────────


def test_the_score_is_the_worst_behaviour_not_the_sum():
    """A sum lets three moderate behaviours outrank one exfiltration. The
    question is "what is the worst thing this did", not "how many things".
    """
    noisy = assess(
        _observed(
            processes_spawned=("sh", "curl", "python"),
            packages_installed=("a", "b"),
        ),
        canaries={},
    )
    exfiltration = assess(
        _observed(outbound_payloads=(CANARIES["aws_secret_key"],)), canaries=CANARIES
    )
    assert exfiltration.score > noisy.score


def test_an_incomplete_recording_is_carried_into_the_verdict():
    """A verdict over a partial recording is a partial verdict, and a short
    findings list must not read as a clean one.
    """
    verdict = assess(
        _observed(
            observation_incomplete=True,
            incomplete_reason="network capture dropped frames",
        ),
        canaries={},
    )
    assert verdict.observation_incomplete is True
    assert verdict.as_dict()["observation_incomplete"] is True


def test_every_finding_carries_the_observed_value():
    """So an analyst can act without re-reading the recording."""
    verdict = assess(
        _observed(files_read=("/root/.aws/credentials",)), canaries={}
    )
    assert verdict.findings[0].evidence == "/root/.aws/credentials"


def test_every_behaviour_has_a_severity():
    from sentinel.domain.detonation import BEHAVIOUR_SEVERITY

    for behaviour in Behaviour:
        assert behaviour in BEHAVIOUR_SEVERITY, f"{behaviour} has no severity"


def test_the_sandbox_does_not_get_to_decide_what_is_dangerous():
    """Observation and judgement are separate so the same recording can be
    re-judged when the rules improve, and so an implementation cannot quietly
    lower a verdict.
    """
    import dataclasses

    fields = {f.name for f in dataclasses.fields(DetonationObservation)}
    for judgement in ("severity", "verdict", "malicious", "score", "risk"):
        assert judgement not in fields, (
            f"DetonationObservation carries {judgement!r}; a sandbox reports "
            "facts, it does not grade them"
        )


# ── typosquatting ────────────────────────────────────────────────────────────


POPULAR = ("requests", "numpy", "pandas", "urllib3", "boto3")


def test_a_one_edit_impersonation_is_caught():
    assert "requests" in typosquat_candidates("reqeusts", popular=POPULAR)
    assert "boto3" in typosquat_candidates("boto33", popular=POPULAR)


def test_the_real_package_is_not_reported_as_impersonating_itself():
    assert typosquat_candidates("requests", popular=POPULAR) == ()


def test_an_unrelated_name_is_not_reported():
    assert typosquat_candidates("sentinel-sdk", popular=POPULAR) == ()


def test_the_distance_bound_is_one_by_default_and_that_is_the_point():
    """At distance two every short name resembles every other, the list fills
    with noise, and an operator stops reading it — which is how the real
    `reqeusts` gets installed.
    """
    assert typosquat_candidates("numpq", popular=POPULAR) == ("numpy",)
    assert typosquat_candidates("nmpq", popular=POPULAR) == ()


def test_an_empty_name_returns_nothing_rather_than_matching_everything():
    assert typosquat_candidates("", popular=POPULAR) == ()
