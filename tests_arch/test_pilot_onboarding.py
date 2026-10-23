"""Real HTTP/storage checks plus a synthetic endpoint. Never scan the developer."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from sentinel.composition.container import build_container
from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.model_advisor import HttpModelAdvisor
from sentinel.infrastructure.sql.engine import Dialect, build_engine
from sentinel.infrastructure.sql.migrate import CURRENT_VERSION, migrate
from sentinel.interface.http import create_app
from sentinel.sdk.discovery import discover, main, validate_report

ADMIN = "pilot-admin-synthetic-key-00000000000000"
OTHER = "pilot-other-synthetic-key-00000000000000"
VIEWER = "pilot-viewer-synthetic-key-0000000000000"
INGEST = "pilot-ingest-synthetic-key-0000000000000"


def headers(key=ADMIN):
    return {"Authorization": f"Bearer {key}"}


def report(tmp_path):
    return discover(home=tmp_path, system="Linux", config_presence=True,
                    app_presence=False, device_id=str(uuid4()))


def test_scanner_never_opens_content_or_follows_symlinks(tmp_path, monkeypatch):
    root = tmp_path / "home"
    (root / ".gemini").mkdir(parents=True)
    (root / ".gemini/settings.json").write_text('{"api_key":"synthetic-never-export-this-value"}')
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "mcp.json").write_text("sensitive")
    (root / ".cursor").symlink_to(outside, target_is_directory=True)

    def forbidden(*args, **kwargs):
        raise AssertionError("Scanner opened file contents")

    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    scan = discover(home=root, system="Linux", config_presence=True,
                    app_presence=True, device_id=str(uuid4()))
    states = {o["probe"]: o["state"] for o in scan["observations"]}
    assert states["gemini-settings"] == "present"
    assert states["cursor-mcp"] == "inaccessible"
    assert states["claude-app"] == "unsupported"
    encoded = json.dumps(scan)
    assert "synthetic-never-export" not in encoded and str(tmp_path) not in encoded
    validate_report(scan)


def test_scanner_does_not_stat_unapproved_categories(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No filesystem permission granted")
    monkeypatch.setattr(Path, "lstat", forbidden)
    scan = discover(home=tmp_path, system="Darwin", config_presence=False,
                    app_presence=False, device_id=str(uuid4()))
    assert all(o["state"] == "not_consented" for o in scan["observations"])


def test_cli_requires_consent_and_does_not_overwrite(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main([])
    assert main(["--explain"]) == 0
    assert "never opened" in capsys.readouterr().out
    # Unsupported application scan exercises CLI without reading this host.
    output = tmp_path / "report.json"
    output.write_text("preserve-existing-work")
    assert main(["--consent", "--app-presence", "--device-id", "invalid", "--output", str(output)]) == 2
    assert output.read_text() == "preserve-existing-work"


@pytest.fixture
def pilot(engine_config):
    env = {"SENTINEL_API_KEYS": f"acme:{ADMIN}:admin,other:{OTHER}:admin,acme:{VIEWER}:viewer,acme:{INGEST}:ingest",
           "SENTINEL_CREDENTIAL_LIMIT": "1000"}
    if engine_config.dialect is Dialect.POSTGRES:
        env["SENTINEL_DATABASE_URL"] = engine_config.dsn
    else:
        env["SENTINEL_DB_PATH"] = engine_config.dsn
    settings = Settings.from_environment(env)
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        with TestClient(create_app(container), raise_server_exceptions=False) as client:
            yield client, container
    finally:
        container.close()


def test_import_replace_read_delete_and_tenant_isolation(pilot, tmp_path):
    client, container = pilot
    body = report(tmp_path)
    assert client.post("/v1/pilot/devices", json=body, headers=headers()).status_code == 201
    # Same device identifier in another tenant is independent.
    other_body = json.loads(json.dumps(body))
    other_body["observations"][0]["state"] = "present"
    assert client.post("/v1/pilot/devices", json=other_body, headers=headers(OTHER)).status_code == 201
    own = client.get("/v1/pilot/devices", headers=headers(VIEWER))
    assert own.headers["cache-control"] == "no-store"
    assert own.json()["devices"][0]["report"] == body
    assert own.json()["devices"][0]["enforced"] is False
    assert client.post("/v1/pilot/devices", json=body, headers=headers()).status_code == 201
    assert len(client.get("/v1/pilot/devices", headers=headers()).json()["devices"]) == 1
    assert client.delete("/v1/pilot/devices/" + body["device_id"], headers=headers()).status_code == 200
    assert client.get("/v1/pilot/devices", headers=headers()).json()["devices"] == []
    assert len(client.get("/v1/pilot/devices", headers=headers(OTHER)).json()["devices"]) == 1
    # Inventory never enrolls an agent or creates a trust decision.
    assert client.get("/v1/inventory/agents", headers=headers()).json()["agents"] == []
    if container.settings.engine.dialect is Dialect.POSTGRES:
        with container.pool.acquire() as conn:
            conn.begin()
            assert conn.execute("SELECT device_id FROM device_discovery") == []
            conn.rollback()


def test_roles_and_unauthenticated_access(pilot, tmp_path):
    client, _ = pilot
    body = report(tmp_path)
    assert client.get("/v1/pilot/setup").status_code == 401
    assert client.get("/v1/pilot/devices", headers=headers(INGEST)).status_code == 403
    for key in [VIEWER, INGEST]:
        assert client.post("/v1/pilot/devices", headers=headers(key), json=body).status_code == 403
        assert client.delete("/v1/pilot/devices/" + body["device_id"], headers=headers(key)).status_code == 403
    setup = client.get("/v1/pilot/setup", headers=headers(VIEWER)).json()
    assert setup["tenant"] == "acme" and setup["can_import"] is False
    assert setup["brain"]["advisor_configured"] is False
    assert setup["mcp_proxy_enabled"] is False


@pytest.mark.parametrize("mutation", ["extra", "credential", "consent", "duplicate", "bad_type", "bad_time"])
def test_invalid_report_is_rejected_without_echoing_values(pilot, tmp_path, mutation):
    client, _ = pilot
    body = report(tmp_path)
    secret = "synthetic-confidential-value-never-echo"
    if mutation == "extra":
        body["api_key"] = secret
    elif mutation == "credential":
        body["observations"][0]["state"] = secret
    elif mutation == "consent":
        body["consent"]["config_presence"] = False
    elif mutation == "duplicate":
        body["observations"][1] = body["observations"][0]
    elif mutation == "bad_type":
        body["platform"] = [secret]
    else:
        body["scanned_at"] = secret
    response = client.post("/v1/pilot/devices", headers=headers(), json=body)
    assert response.status_code == 400 and secret not in response.text
    assert client.get("/v1/pilot/devices", headers=headers()).json()["devices"] == []


def test_oversize_report_refused(pilot):
    client, _ = pilot
    response = client.post("/v1/pilot/devices", headers=headers(), content=b" " * 32769)
    assert response.status_code == 413


def test_downloaded_companion_runs_without_server_dependencies(pilot, tmp_path):
    client, _ = pilot
    response = client.get("/v1/pilot/discovery-script", headers=headers(VIEWER))
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    script = tmp_path / "discovery.py"
    script.write_bytes(response.content)
    result = subprocess.run([sys.executable, "-I", "-S", str(script), "--explain"],
                            capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0 and "No network transmission" in result.stdout


def test_upgrade_from_previous_schema(engine_config):
    pool = build_engine(engine_config)
    try:
        migrate(pool)
        with pool.acquire() as conn:
            conn.begin()
            conn.execute_rowcount("DROP TABLE device_discovery")
            conn.execute_rowcount("DELETE FROM schema_migrations WHERE version=38")
            conn.commit()
        assert migrate(pool) == CURRENT_VERSION
        assert migrate(pool) == CURRENT_VERSION
    finally:
        pool.close()


def test_advisor_configuration_is_complete_secret_safe_and_https():
    env = {"SENTINEL_API_KEYS": f"acme:{ADMIN}:admin", "SENTINEL_ADVISOR_ENDPOINT": "https://model.example/v1"}
    with pytest.raises(ConfigurationError):
        Settings.from_environment(env)
    env.update(SENTINEL_ADVISOR_MODEL="pilot-model", SENTINEL_ADVISOR_TOKEN="synthetic-provider-key")
    settings = Settings.from_environment(env)
    assert "synthetic-provider-key" not in repr(settings)
    for endpoint in ["http://model.example/v1", "https://user:secret@model.example", "https://model.example?key=secret"]:
        with pytest.raises(ConfigurationError):
            Settings.from_environment({**env, "SENTINEL_ADVISOR_ENDPOINT": endpoint})
    container = build_container(settings, verify_schema=False)
    try:
        assert isinstance(container.advisor, HttpModelAdvisor)
        assert container.advisor.model_receipt() == "pilot-model"
    finally:
        container.close()


def test_commands_are_found_by_name_without_following_or_running_them(tmp_path, monkeypatch):
    from sentinel.sdk.discovery import render_html, summarise

    home = tmp_path / "home"
    (home / ".local/bin").mkdir(parents=True)
    target = tmp_path / "elsewhere" / "real-agy"
    target.parent.mkdir()
    target.write_text("#!/bin/sh\nexit 1\n")
    (home / ".local/bin/agy").symlink_to(target)          # how package managers install commands
    (home / "bin").mkdir()
    (home / "bin/aider").mkdir()                            # a directory is not a command
    monkeypatch.setattr("subprocess.run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("scanner ran a command")))
    scan = discover(home=home, system="Linux", config_presence=False, app_presence=False, cli_presence=True,
                    device_id=str(uuid4()), system_bin_dirs=())
    states = {o["probe"]: o["state"] for o in scan["observations"]}
    assert states["antigravity-cli"] == "present" and states["aider-cli"] == "inaccessible"
    assert states["gemini-cli"] == "not_found" and states["gemini-settings"] == "not_consented"
    validate_report(scan)
    assert summarise(scan) == [("Antigravity", ["antigravity-cli"])]
    page = render_html(scan)
    assert "Antigravity" in page and str(tmp_path) not in page and "real-agy" not in page and "<script" not in page


def test_a_report_in_the_previous_schema_is_refused(pilot, tmp_path):
    client, _ = pilot
    body = report(tmp_path)
    body["schema"] = "sentinel.device-discovery/v1"
    assert client.post("/v1/pilot/devices", json=body, headers=headers()).status_code == 400
    del body["consent"]["cli_presence"]
    assert client.post("/v1/pilot/devices", json=body, headers=headers()).status_code == 400


def test_html_and_json_outputs_never_overwrite(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    page, data = tmp_path / "r.html", tmp_path / "r.json"
    monkeypatch.setattr("sentinel.sdk.discovery.SYSTEM_BIN_DIRS", ())
    monkeypatch.setattr("platform.system", lambda: "Linux")
    assert main(["--consent", "--config-presence", "--output", str(data), "--html", str(page)]) == 0
    assert "none of the known AI tools" in capsys.readouterr().err
    assert json.loads(data.read_text())["schema"].endswith("/v2") and page.read_text().startswith("<!doctype html>")
    assert main(["--consent", "--config-presence", "--html", str(page)]) == 2


def test_windows_install_folders_and_commands_are_found_under_the_home(tmp_path):
    home = tmp_path / "home"
    (home / "AppData/Local/Programs/cursor").mkdir(parents=True)
    (home / "AppData/Roaming/npm").mkdir(parents=True)
    (home / "AppData/Roaming/npm/claude.cmd").write_text("@echo off\n")
    (home / ".gemini").mkdir()
    (home / ".gemini/settings.json").write_text("{}")
    scan = discover(home=home, system="Windows", config_presence=True, app_presence=True, cli_presence=True,
                    device_id=str(uuid4()), system_bin_dirs=())
    states = {o["probe"]: o["state"] for o in scan["observations"]}
    assert states["cursor-app"] == "present" and states["claude-cli"] == "present" and states["gemini-settings"] == "present"
    assert states["ollama-app"] == "not_found" and states["gemini-cli"] == "not_found"
    assert "unsupported" not in states.values()
    validate_report(scan)


def test_the_desktop_app_scans_only_what_was_ticked_and_saves_without_overwriting(tmp_path):
    from sentinel.sdk import discovery_app as app

    with pytest.raises(ValueError):
        app.run_scan({"config_presence": False, "app_presence": False, "cli_presence": False}, home=tmp_path)
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex/config.toml").write_text("model = 'x'")
    scan = app.run_scan({"config_presence": True, "app_presence": False, "cli_presence": False}, home=home, system="Linux")
    assert scan["consent"] == {"config_presence": True, "app_presence": False, "cli_presence": False}
    assert app.result_lines(scan) == ["Codex  —  1 sign found"]
    data, page = app.save_report(scan, tmp_path / "out")
    assert json.loads(data.read_text())["schema"].endswith("/v2") and "Codex" in page.read_text()
    with pytest.raises(FileExistsError):
        app.save_report(scan, tmp_path / "out")
    source = Path(app.__file__).read_text()
    assert not any(word in source for word in ("urllib", "socket", "http.client", "requests")), "the app must not be able to send anything"
    assert "BooleanVar(value=False)" in source, "consent boxes start unticked"
    assert app.self_test() == 0
