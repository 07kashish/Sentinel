"""Configuration guards must reject plausible, nonfunctional controls."""
from pathlib import Path
import base64
import json
import pytest
import yaml
from jsonschema import Draft7Validator
from scripts import check_config_alignment as check
from sentinel.composition.settings import Settings

ROOT = Path(__file__).resolve().parents[1]


def test_prose_cannot_register_a_configuration_reader(tmp_path):
    path = tmp_path / "reader.py"
    path.write_text('"""Historical SENTINEL_NOT_READ=1 was ignored."""\n# SENTINEL_COMMENT\nvalue = source.get("SENTINEL_REAL", "")\n')
    assert check._literal_names(path) == {"SENTINEL_REAL"}


def test_checked_in_configuration_names_align():
    assert check.main([]) == 0


def test_dynamic_secret_file_names_have_readers():
    service, _ = check.read_by_code()
    assert "SENTINEL_KUBERNETES_TOKEN_FILE" in service
    assert "SENTINEL_SIEM_OTLP_TOKEN_FILE" in service
    assert "SENTINEL_RLS_ENABLED" not in service


@pytest.mark.parametrize("key,value", [("requireExecutionBinding", False), ("rateLimitFailOpen", True)])
def test_chart_refuses_unbound_or_fail_open_values(key, value):
    chart = ROOT / "deploy/helm/sentinel"
    values = yaml.safe_load((chart / "values.yaml").read_text())
    values["externalPostgres"]["archiveTimeoutConfirmed"] = True
    validator = Draft7Validator(json.loads((chart / "values.schema.json").read_text()))
    assert not list(validator.iter_errors(values))
    values[key] = value
    assert list(validator.iter_errors(values))


def test_raw_deployment_values_activate_the_real_enforcement_parser():
    docs = list(yaml.safe_load_all((ROOT / "deploy/k8s/sentinel.yaml").read_text()))
    deployment = next(doc for doc in docs if doc and doc.get("kind") == "Deployment")
    entries = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    env = {entry["name"]: str(entry["value"]) for entry in entries if "value" in entry}
    # Synthetic fixture values replace mounted secrets; never read local credentials.
    # Secret-backed in the manifest (secretKeyRef), so supplied here like the DSN.
    env["SENTINEL_DATA_KEY_K1"] = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    env.update(SENTINEL_DATABASE_URL="postgresql://sentinel@localhost/sentinel",
               SENTINEL_API_KEYS="tenant:" + "x" * 40 + ":admin",
               SENTINEL_REDIS_URL="redis://localhost:6379/0")
    env.pop("SENTINEL_METRICS_TOKEN_FILE", None)
    settings = Settings.from_environment(env)
    assert settings.is_production
    assert settings.require_execution_binding
    assert settings.protect_enforcement
    assert not settings.rate_limit_fail_open
    assert settings.redis_url
    assert env["GUNICORN_WORKERS"] == "1"


def test_rendered_helm_controls_activate_real_settings(monkeypatch):
    import os
    import shutil
    import subprocess
    binary = os.environ.get("SENTINEL_TEST_HELM_BINARY") or shutil.which("helm")
    if not binary:
        pytest.skip("Helm binary unavailable; chart rendering is unverified")
    command = [binary, "template", "sentinel", str(ROOT / "deploy/helm/sentinel"),
               "--set", "externalPostgres.archiveTimeoutConfirmed=true",
               "--set", "corsOrigins=https://console.example.invalid"]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    docs = list(yaml.safe_load_all(result.stdout))
    deployment = next(d for d in docs if d and d.get("kind") == "Deployment")
    entries = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    env = {e["name"]: str(e["value"]) for e in entries if "value" in e}
    refs = {e["name"]: e["valueFrom"]["secretKeyRef"] for e in entries if "valueFrom" in e}
    assert refs["SENTINEL_REDIS_URL"] == {"name": "sentinel-redis", "key": "redisUrl"}
    env.update(SENTINEL_DATABASE_URL="postgresql://sentinel@localhost/sentinel",
               SENTINEL_API_KEYS="tenant:" + "x" * 40 + ":admin",
               SENTINEL_REDIS_URL="redis://localhost:6379/0")
    env.pop("SENTINEL_METRICS_TOKEN_FILE", None)
    # The evidence data key is a secretKeyRef too, and production refuses to
    # start without one. This test predated evidence encryption and never
    # supplied it, which went unseen while helm was absent from the machine.
    data_keys = [name for name in refs if name.startswith("SENTINEL_DATA_KEY_")]
    assert data_keys and env.get("SENTINEL_ACTIVE_KEY_ID"), "the chart no longer wires the evidence data key"
    for name in data_keys:
        env[name] = base64.b64encode(bytes(range(32))).decode()
    settings = Settings.from_environment(env)
    assert settings.require_execution_binding and settings.protect_enforcement
    assert not settings.rate_limit_fail_open and settings.redis_url
    assert env["GUNICORN_WORKERS"] == "1"
    egress = next(d for d in docs if d and d.get("kind") == "NetworkPolicy"
                  and d["metadata"]["name"] == "sentinel-egress")["spec"]["egress"]
    assert any(rule.get("ports") == [{"protocol": "TCP", "port": 6379}]
               and rule["to"] == [{"podSelector": {"matchLabels": {"app": "redis"}}}]
               for rule in egress)
    denied = subprocess.run(command + ["--set", "requireExecutionBinding=false"],
                            capture_output=True, text=True)
    assert denied.returncode != 0 and "requireExecutionBinding" in denied.stderr
