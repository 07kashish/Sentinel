"""Alerting rules must select metrics this code actually exposes.

WHY THIS FILE EXISTS
--------------------
An alerting rule fails in a direction that looks exactly like health. If
`deploy/alerts/sentinel.rules.yml` selects `sentinel_detection_degraded` and the
process publishes `sentinel_detection_status`, Prometheus loads the rule without
complaint, evaluates it against an empty vector forever, and the dashboard stays
green while detection runs at ~0.067 recall. Nobody finds out from the alert;
they find out from the incident it did not catch.

So the check here is not "is the YAML valid". It is: for every metric name any
rule selects, does a real container -- built, swept, and rendered through the
same `render_prometheus()` the scrape endpoint serves -- actually emit that
name? The exposition is generated, never hard-coded, so renaming a metric in
`sentinel/` breaks this test rather than silently disarming the alert.

`absent(...)` rules are the deliberate exception and are still checked: their
argument must be a real metric name too, or the guard guards nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from sentinel.composition.container import build_container
from sentinel.composition.settings import Settings
from sentinel.domain.primitives import TenantId
from sentinel.infrastructure.sql.engine import build_engine
from sentinel.infrastructure.sql.migrate import migrate
from sentinel.interface.worker import MaintenanceLoop

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "deploy" / "alerts"
PROMETHEUS_YML = ROOT / "deploy" / "prometheus.yml"
COMPOSE = ROOT / "docker-compose.yml"

TENANT = TenantId("acme")
KEY = "m" * 40

#: PromQL builtins and scrape-generated series that are not Sentinel metrics.
_NOT_OURS = frozenset({"time", "up", "absent", "rate", "increase", "sum", "max", "min", "avg"})

#: Identifiers in an expression that are Prometheus functions rather than series.
_TOKEN = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")


def _rule_files() -> list[Path]:
    return sorted(RULES_DIR.glob("*.yml"))


def _all_rules() -> list[tuple[Path, dict]]:
    out: list[tuple[Path, dict]] = []
    for path in _rule_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for group in doc.get("groups") or []:
            for rule in group.get("rules") or []:
                out.append((path, rule))
    return out


def _selected_metric_names(expr: str) -> set[str]:
    """Every identifier in the expression that is a series selector.

    Crude on purpose: it over-collects rather than under-collects, because a
    name this misses is a name the test would not have verified.
    """
    names = set()
    for token in _TOKEN.findall(re.sub(r"\[[0-9smhdwy:.]+\]", "", expr)):
        if token in _NOT_OURS:
            continue
        if token.isdigit():
            continue
        names.add(token)
    return names


@pytest.fixture(scope="module")
def exposition(tmp_path_factory) -> str:
    """The real `/metrics/prometheus` body, after one maintenance sweep.

    The sweep matters: `sentinel_possible_bypass_agents` and its freshness
    timestamp are published by `MaintenanceLoop`, not at composition time, so a
    fixture that only builds a container would not prove those names exist.
    """
    tmp = tmp_path_factory.mktemp("alert-rules")
    settings = Settings.from_environment(
        {
            "SENTINEL_ENV": "development",
            "SENTINEL_API_KEYS": f"{TENANT}:{KEY}:admin",
            "SENTINEL_DB_PATH": str(tmp / "alerts.db"),
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        MaintenanceLoop(
            container, tenants=lambda: [TENANT], interval_seconds=60
        ).run_once()
        return container.metrics.render_prometheus()
    finally:
        container.close()


def _exposed_names(exposition: str) -> set[str]:
    names = set()
    for line in exposition.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        series = line.split(" ", 1)[0]
        names.add(series.split("{", 1)[0])
    return names


# ── The check that matters ───────────────────────────────────────────────────


def test_every_metric_an_alert_selects_is_actually_exposed(exposition):
    """The silent-rule guard. Rename a metric and this fails, not production."""
    exposed = _exposed_names(exposition)
    assert exposed, "rendered exposition was empty; the fixture proved nothing"

    missing: list[str] = []
    for path, rule in _all_rules():
        for name in _selected_metric_names(rule["expr"]):
            if name not in exposed:
                missing.append(
                    f"{path.name}:{rule['alert']} selects {name!r}, "
                    "which nothing exposes"
                )
    assert not missing, (
        "alert rules select metrics that do not exist — these rules can never "
        "fire:\n" + "\n".join(missing) + f"\n\nexposed: {sorted(exposed)}"
    )


def test_the_two_signals_this_work_wired_are_present_and_numeric(exposition):
    """Named explicitly, so deleting a rule cannot quietly drop the coverage."""
    exposed = _exposed_names(exposition)
    for required in (
        "sentinel_detection_degraded",
        "sentinel_possible_bypass_agents",
        "sentinel_bypass_sweep_timestamp_seconds",
    ):
        assert required in exposed, f"{required} is not exposed"

    values = {}
    for line in exposition.splitlines():
        if " " in line and not line.startswith("#"):
            series, _, raw = line.partition(" ")
            values[series] = float(raw)

    # Healthy tree: the artifact loads, so detection is not degraded.
    assert values["sentinel_detection_degraded"] == 0.0
    assert values["sentinel_possible_bypass_agents"] == 0.0
    # A real epoch, not a placeholder — the staleness rule subtracts from time().
    assert values["sentinel_bypass_sweep_timestamp_seconds"] > 1_700_000_000


def test_detection_mode_label_key_matches_what_the_rules_reference(exposition):
    """The annotation points operators at `sentinel_detection_mode`; keep it real."""
    assert 'sentinel_detection_mode{mode="' in exposition


# ── Rule hygiene ─────────────────────────────────────────────────────────────


def test_rules_exist_and_parse():
    assert _rule_files(), f"no alerting rules found in {RULES_DIR}"
    rules = _all_rules()
    assert rules, "rule files contain no alerts"
    for path, rule in rules:
        assert rule.get("alert"), f"{path.name}: rule without a name"
        assert rule.get("expr"), f"{path.name}:{rule.get('alert')}: no expr"
        assert rule.get("labels", {}).get("severity"), (
            f"{path.name}:{rule['alert']}: no severity, so it cannot be routed"
        )
        annotations = rule.get("annotations") or {}
        assert annotations.get("summary"), (
            f"{path.name}:{rule['alert']}: no summary — a page with no text "
            "makes the responder start from nothing"
        )


def test_bypass_silence_is_alerted_on_value_and_on_freshness():
    """`possible_bypass` is silence; a stopped sweep is also silence.

    Both produce 0. Alerting only on the value cannot distinguish them, which is
    why the staleness rule is required to exist alongside it.
    """
    by_name = {rule["alert"]: rule for _path, rule in _all_rules()}
    assert "SentinelPossibleAgentBypass" in by_name
    stale = by_name.get("SentinelBypassSweepStale")
    assert stale, (
        "no staleness alert: a MaintenanceLoop that stops publishing leaves "
        "sentinel_possible_bypass_agents pinned at its last value, and 0 reads "
        "as healthy"
    )
    assert "sentinel_bypass_sweep_timestamp_seconds" in stale["expr"]
    assert stale["labels"]["severity"] == "critical"


# ── The rules have to actually be loaded ─────────────────────────────────────


def test_prometheus_config_loads_the_rule_directory():
    """A rule file nobody loads is a file, not an alert."""
    config = yaml.safe_load(PROMETHEUS_YML.read_text(encoding="utf-8"))
    globs = config.get("rule_files") or []
    assert globs, "prometheus.yml declares no rule_files"
    assert any("alerts" in str(g) for g in globs), (
        f"rule_files {globs} does not cover the alerts directory"
    )


def test_compose_mounts_the_rules_where_prometheus_looks_for_them():
    """The other half of the same failure: declared, globbed, never mounted."""
    config = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    volumes = config["services"]["prometheus"]["volumes"]
    mounts = [v if isinstance(v, str) else str(v) for v in volumes]
    assert any("deploy/alerts" in m for m in mounts), (
        "docker-compose does not mount deploy/alerts into the prometheus "
        f"container; rule_files would glob an empty directory. mounts={mounts}"
    )
