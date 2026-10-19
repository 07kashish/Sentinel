"""The declared topology is not the topology.

The defect this covers was live: `settings.py` refuses production when
`SENTINEL_WORKER_SHARD_COUNT` exceeds one without a shared limiter, and

    uvicorn sentinel.interface.asgi:app --workers 4

with that variable unset sails through it. Four processes, four independent
limiters, four times the configured rate, and every check green.

So the load-bearing test here is not that a refusal happens -- it is that the
refusal happens WITHOUT the operator declaring anything, because a test that
sets the shard count before asserting the refusal would pass against the old
broken check too. `test_four_workers_are_refused_with_nothing_declared` is the
one that fails against the predecessor.
"""

from __future__ import annotations

import base64

import pytest

from sentinel.composition.topology import (
    ATTESTED_SINGLE_PROCESS,
    Observation,
    ObservedTopology,
    TopologyRefused,
    judge_topology,
    observe_topology,
    require_shared_limiter_or_refuse,
    worker_count_in_argv,
)

UVICORN = "/usr/local/bin/python"


def _proc(pid: int, root, *, argv: list[str], ppid: int) -> None:
    """Fabricate one /proc/<pid> entry."""
    directory = root / str(pid)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cmdline").write_bytes(
        "\0".join(argv).encode("utf-8") + b"\0"
    )
    # Name deliberately contains a space and parentheses: `stat` parsing breaks
    # on exactly this, which is why the implementation reads `status`.
    (directory / "status").write_text(
        f"Name:\t(py thon) worker\nPPid:\t{ppid}\n", encoding="utf-8"
    )


# ── reading a worker count off a command line ───────────────────────────────


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([UVICORN, "-m", "uvicorn", "app", "--workers", "4"], 4),
        ([UVICORN, "-m", "uvicorn", "app", "--workers=8"], 8),
        ([UVICORN, "-m", "gunicorn", "-w", "3", "app"], 3),
        ([UVICORN, "-m", "uvicorn", "app"], 0),
        ([UVICORN, "-m", "uvicorn", "app", "--workers", "1"], 1),
    ],
)
def test_the_worker_flag_is_read_in_every_spelling(argv, expected):
    """uvicorn, gunicorn and hypercorn spell it three ways. Missing one means
    the check silently does not apply to that server.
    """
    assert worker_count_in_argv(argv) == expected


@pytest.mark.parametrize(
    "argv",
    [
        [UVICORN, "app", "--workers", "not-a-number"],
        [UVICORN, "app", "--workers"],
        [UVICORN, "app", "--workers", "0"],
        [UVICORN, "app", "--workers=-2"],
    ],
)
def test_an_unparseable_worker_flag_yields_no_count(argv):
    """Better to observe nothing than to observe a wrong number: a wrong number
    reaches an operator as a refusal they cannot reproduce, and they will
    switch the check off.
    """
    assert worker_count_in_argv(argv) == 0


# ── the judgement ───────────────────────────────────────────────────────────


def test_a_parent_launched_with_four_workers_is_multiple():
    topology = judge_topology(
        proc_readable=True,
        self_argv=[UVICORN, "-m", "uvicorn", "app"],
        parent_argv=[UVICORN, "-m", "uvicorn", "app", "--workers", "4"],
        sibling_count=1,
    )

    assert topology.observation is Observation.MULTIPLE
    assert topology.process_count == 4
    assert "--workers 4" in topology.how


def test_siblings_alone_are_enough_when_no_flag_is_recorded():
    """A supervisor that spawns workers without a flag anywhere still produces
    the dangerous topology, so the flag cannot be the only signal.
    """
    topology = judge_topology(
        proc_readable=True, self_argv=[UVICORN, "app"], sibling_count=3
    )

    assert topology.observation is Observation.MULTIPLE
    assert topology.process_count == 3


def test_one_process_with_no_flag_is_single():
    topology = judge_topology(
        proc_readable=True, self_argv=[UVICORN, "app"], sibling_count=1
    )

    assert topology.observation is Observation.SINGLE
    assert topology.process_count == 1


def test_workers_one_is_not_multiple():
    """`--workers 1` is a single process. Treating any flag as multiple would
    refuse a correct deployment.
    """
    topology = judge_topology(
        proc_readable=True,
        self_argv=[UVICORN, "app", "--workers", "1"],
        sibling_count=1,
    )

    assert topology.observation is Observation.SINGLE


def test_unreadable_proc_is_unobservable_and_not_single():
    """The whole reason `Observation` has three members. Rendering "could not
    look" as "one process" is the original defect with extra steps.
    """
    topology = judge_topology(proc_readable=False)

    assert topology.observation is Observation.UNOBSERVABLE
    assert topology.observation is not Observation.SINGLE
    assert topology.process_count == 0
    assert topology.needs_shared_state is False


def test_an_unobservable_topology_cannot_carry_a_count():
    """A count on an UNOBSERVABLE result is a number a caller might believe."""
    with pytest.raises(ValueError) as raised:
        ObservedTopology(
            observation=Observation.UNOBSERVABLE, process_count=1, how="guessed"
        )

    assert "Nothing was counted" in str(raised.value)


def test_multiple_with_one_process_is_refused_as_a_contradiction():
    with pytest.raises(ValueError):
        ObservedTopology(
            observation=Observation.MULTIPLE, process_count=1, how="inconsistent"
        )


# ── reading a real process tree ─────────────────────────────────────────────


def test_a_fabricated_tree_with_a_workers_parent_is_observed(tmp_path):
    root = tmp_path / "proc"
    _proc(100, root, argv=[UVICORN, "-m", "uvicorn", "app", "--workers", "4"], ppid=1)
    _proc(101, root, argv=[UVICORN, "-m", "uvicorn", "app"], ppid=100)
    (root / "self").symlink_to(root / "101", target_is_directory=True)

    topology = observe_topology(proc_root=root)

    assert topology.observation is Observation.MULTIPLE
    assert topology.process_count == 4


def test_siblings_are_counted_from_a_real_tree(tmp_path):
    """Three workers under one parent, with no flag recorded anywhere."""
    root = tmp_path / "proc"
    _proc(200, root, argv=["/bin/sh", "-c", "start"], ppid=1)
    for pid in (201, 202, 203):
        _proc(pid, root, argv=[UVICORN, "-m", "uvicorn", "app"], ppid=200)
    (root / "self").symlink_to(root / "201", target_is_directory=True)

    topology = observe_topology(proc_root=root)

    assert topology.observation is Observation.MULTIPLE
    assert topology.process_count == 3


def test_a_sibling_running_something_else_is_not_counted(tmp_path):
    """A supervisor may have spawned a log shipper. Counting it would produce a
    refusal naming a number the operator cannot find.
    """
    root = tmp_path / "proc"
    _proc(300, root, argv=["/bin/sh", "-c", "start"], ppid=1)
    _proc(301, root, argv=[UVICORN, "-m", "uvicorn", "app"], ppid=300)
    _proc(302, root, argv=["/usr/bin/vector", "--config", "x"], ppid=300)
    (root / "self").symlink_to(root / "301", target_is_directory=True)

    topology = observe_topology(proc_root=root)

    assert topology.observation is Observation.SINGLE


def test_a_missing_proc_reads_as_unobservable(tmp_path):
    topology = observe_topology(proc_root=tmp_path / "absent")

    assert topology.observation is Observation.UNOBSERVABLE


# ── the refusal ─────────────────────────────────────────────────────────────


def test_four_workers_are_refused_with_nothing_declared():
    """THE test. No shard count is declared anywhere -- the refusal comes from
    observation alone. This is the case the predecessor check let through.
    """
    topology = judge_topology(
        proc_readable=True,
        self_argv=[UVICORN, "app"],
        parent_argv=[UVICORN, "app", "--workers", "4"],
    )

    with pytest.raises(TopologyRefused) as raised:
        require_shared_limiter_or_refuse(
            topology=topology, redis_url="", production=True
        )

    message = str(raised.value)
    assert "4x the configured rate" in message
    # And it says so: fixing the variable will not clear this.
    assert "SENTINEL_WORKER_SHARD_COUNT" in message


def test_a_shared_limiter_permits_any_topology():
    """With Redis the limit is enforced in one place, so the process count
    stops mattering for this control.
    """
    topology = judge_topology(
        proc_readable=True, self_argv=[UVICORN, "app"], sibling_count=9
    )

    require_shared_limiter_or_refuse(
        topology=topology, redis_url="redis://cache:6379", production=True
    )


def test_a_single_process_needs_no_shared_limiter():
    topology = judge_topology(proc_readable=True, self_argv=[UVICORN, "app"])

    require_shared_limiter_or_refuse(
        topology=topology, redis_url="", production=True
    )


def test_production_refuses_an_unobservable_topology_without_a_limiter():
    """The assumption that makes a per-process limiter correct is unverified.
    Passing here would put an unverified assumption under a security control.
    """
    with pytest.raises(TopologyRefused) as raised:
        require_shared_limiter_or_refuse(
            topology=judge_topology(proc_readable=False),
            redis_url="",
            production=True,
        )

    assert ATTESTED_SINGLE_PROCESS in str(raised.value)


def test_an_attestation_clears_only_the_unobservable_case():
    require_shared_limiter_or_refuse(
        topology=judge_topology(proc_readable=False),
        redis_url="",
        production=True,
        attested_single_process=True,
    )


def test_an_attestation_cannot_override_an_observation():
    """Otherwise the attestation is just a way to switch the check off, and it
    would be set by the first operator who hit the refusal.
    """
    topology = judge_topology(
        proc_readable=True,
        self_argv=[UVICORN, "app"],
        parent_argv=[UVICORN, "app", "--workers", "4"],
    )

    with pytest.raises(TopologyRefused):
        require_shared_limiter_or_refuse(
            topology=topology,
            redis_url="",
            production=True,
            attested_single_process=True,
        )


def test_development_tolerates_an_unobservable_topology():
    """A Windows developer machine cannot read /proc and is not serving
    traffic. Refusing there teaches operators the check is noise.
    """
    require_shared_limiter_or_refuse(
        topology=judge_topology(proc_readable=False),
        redis_url="",
        production=False,
    )


def test_development_still_refuses_an_observed_multiple():
    """Several processes with a per-process limiter is wrong in development
    too, and it is the configuration a developer is most likely to reproduce.
    """
    topology = judge_topology(
        proc_readable=True, self_argv=[UVICORN, "app"], sibling_count=2
    )

    with pytest.raises(TopologyRefused):
        require_shared_limiter_or_refuse(
            topology=topology, redis_url="", production=False
        )


def test_whitespace_is_not_a_redis_url():
    """A variable set to spaces reads as configured to a truthiness check, and
    would silently disable the refusal.
    """
    topology = judge_topology(
        proc_readable=True, self_argv=[UVICORN, "app"], sibling_count=4
    )

    with pytest.raises(TopologyRefused):
        require_shared_limiter_or_refuse(
            topology=topology, redis_url="   ", production=True
        )


def _settings_on(engine_config, sqlite_path):
    """Settings pointed at the parametrised engine.

    The topology check has nothing to do with SQL, but the fitness rule that
    every database-touching test module runs on BOTH engines is not one to opt
    out of on the grounds that this particular test is unlikely to care -- the
    retention sweep passed on SQLite while deleting nothing on PostgreSQL, and
    the reason that rule exists is that nobody predicted it there either.
    """
    from dataclasses import replace

    from sentinel.composition.settings import Settings

    base = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_DB_PATH": str(sqlite_path),
            "SENTINEL_API_KEYS": f"acme:{'k' * 40}:analyst",
            "SENTINEL_CORS_ORIGINS": "https://console.example.com",
        }
    )
    return replace(base, engine=engine_config)


def _migrated(settings) -> None:
    """Bring the schema up before the app refuses to serve against it.

    `create_app` refuses an unmigrated database, which is correct and unrelated
    to topology -- without this the wiring tests below would fail for a reason
    that has nothing to do with what they are testing, and the first reading of
    that failure cost time here.
    """
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate

    pool = build_engine(settings.engine)
    try:
        migrate(pool)
    finally:
        pool.close()


# ── the check has to actually run ───────────────────────────────────────────
#
# Everything above tests a function. A function that is never called is the
# defect class this repository has hit five times: a module that passes its
# whole suite while being unreachable. These two tests read the startup path.


def test_the_served_application_refuses_a_multi_process_deployment(
    tmp_path, monkeypatch, engine_config
):
    """Enters the real lifespan with a real app.

    The topology observation is replaced -- not the refusal -- so what is under
    test is whether `create_application` consults it and lets the refusal
    escape. A test that stubbed the refusal would prove only that stubs work.
    """
    from fastapi.testclient import TestClient

    from sentinel.interface import asgi

    settings = _settings_on(engine_config, tmp_path / "topology.db")

    _migrated(settings)

    monkeypatch.setattr(
        asgi,
        "observe_topology",
        lambda: ObservedTopology(
            observation=Observation.MULTIPLE,
            process_count=4,
            how="the launch command names 4 workers (--workers 4)",
        ),
    )

    app = asgi.create_application(settings=settings, worker_threads=1)

    with pytest.raises(TopologyRefused) as raised:
        with TestClient(app):
            pass  # never reached: the lifespan refuses before serving

    assert "4x the configured rate" in str(raised.value)


def test_a_single_process_deployment_starts_normally(
    tmp_path, monkeypatch, engine_config
):
    """The negative case. Without it the test above would also pass against an
    application that refused to start under every topology.
    """
    from fastapi.testclient import TestClient

    from sentinel.interface import asgi

    settings = _settings_on(engine_config, tmp_path / "topology-ok.db")

    _migrated(settings)

    monkeypatch.setattr(
        asgi,
        "observe_topology",
        lambda: ObservedTopology(
            observation=Observation.SINGLE, process_count=1, how="one process"
        ),
    )

    app = asgi.create_application(settings=settings, worker_threads=1)

    with TestClient(app) as client:
        assert client.get("/health/live").status_code == 200


def test_the_preflight_report_says_it_does_not_check_topology():
    """An operator who reads "no problems found" and then watches startup
    refuse has been misled by the preflight. It cannot check this -- observing
    from a CLI reports on the CLI -- so it has to say so.
    """
    from sentinel.composition.preflight import validate_production_configuration

    report = validate_production_configuration(
        {
            "SENTINEL_ENV": "production",
            "SENTINEL_API_KEYS": f"acme:{'k' * 40}:analyst",
            "SENTINEL_DATABASE_URL": "postgresql://sentinel@db/sentinel",
            "SENTINEL_CORS_ORIGINS": "https://console.example.com",
            "SENTINEL_RATE_LIMIT_FAIL_OPEN": "false",
            "SENTINEL_REQUIRE_EXECUTION_BINDING": "false",
            "SENTINEL_DATA_KEY_K1": base64.b64encode(b"0123456789abcdef" * 2).decode(),
            "SENTINEL_ACTIVE_KEY_ID": "k1",
        }
    )
    rendered = report.render()

    assert report.ok, rendered
    assert "NOT checked here" in rendered
    assert "processes actually serving this deployment" in rendered
