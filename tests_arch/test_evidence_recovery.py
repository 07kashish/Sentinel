"""Evidence outlives the database that produced it, and a rewrite is caught.

The drill, on both engines: run changes, commit their receipts, let a CUSTOMER
witness the root with the standalone tool, keep a bundle. Then lose the
primary database entirely, restore a copy into a NEW database, and check the
old bundle against the root the customer kept -- not against anything the
restored service says about itself. Then the adversarial half: a restored or
live log that was rewritten must fail the witness's consistency check.

Scope: one host. This proves the mechanism needs nothing from the lost
database; it does not prove survival of a datacentre (RISK R-003).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


from sentinel.domain.transparency import MerkleLog
from sentinel.infrastructure.sql.evidence_commitments import RECEIPT_FIELDS
from tests_arch.test_execution_contract import ANALYST, _evaluate, _execute, _h, _make

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "standard" / "execution-passport-v1" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WITNESS, VERIFIER = _load("witness_root"), _load("verify_evidence_bundle")


def _run(harness, count: int, start: int = 0) -> None:
    for index in range(start, start + count):
        token = _evaluate(harness, arguments={"value": f"v{index}"}).json()["authorization"]["token"]
        assert _execute(harness, token, arguments={"value": f"v{index}"}).status_code == 200
    harness.container.evidence.commit_pending("acme", at="2026-09-20T00:00:00+00:00")


def _fetch(harness):
    def fetch(relative: str) -> dict:
        response = harness.client.get(relative, headers=_h(ANALYST))
        assert response.status_code == 200, response.text
        return response.json()
    return fetch


def _copy_evidence(source, target) -> None:
    """A logical backup and restore of the evidence tables into another database."""
    tables = {
        "transparency_leaves": ("tenant_id", "sequence", "digest", "appended_at"),
        "evidence_commitments": ("tenant_id", "receipt_id", "leaf_digest", "sequence", "committed_at"),
        "execution_receipts": ("tenant_id", *RECEIPT_FIELDS),
    }
    for table, columns in tables.items():
        with source.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant("acme")
            rows = conn.execute(f"SELECT {', '.join(columns)} FROM {table} WHERE tenant_id={conn.p}", ("acme",))  # noqa: S608 - fixed names
            conn.commit()
        with target.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant("acme")
            for row in rows:
                conn.execute_rowcount(
                    f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join([conn.p] * len(columns))})",  # noqa: S608
                    tuple(row[c] for c in columns),
                )
            conn.commit()


def test_the_witness_verifier_agrees_with_the_domain_on_every_prefix():
    log = MerkleLog(entries=tuple(bytes([i]) * 32 for i in range(1, 12)))
    for old in range(1, 12):
        earlier = MerkleLog(entries=log.entries[:old])
        proof = list(log.consistency_proof(old))
        assert WITNESS.consistent(earlier.root(), old, log.root(), log.size, proof)
        if old < log.size:
            forged = MerkleLog(entries=(b"\xff" * 32, *log.entries[1:old]))
            assert not WITNESS.consistent(forged.root(), old, log.root(), log.size, proof)


def test_evidence_verifies_after_the_primary_is_lost_and_restored_elsewhere(tmp_path, engine_config, monkeypatch, postgres_admin_dsn):
    witness_file = tmp_path / "customer" / "acme-roots.jsonl"
    for folder in ("primary", "restored"):
        (tmp_path / folder).mkdir()
    primary = _make(tmp_path / "primary", engine_config, monkeypatch, enforce=True)
    try:
        _run(primary, 4)
        assert WITNESS.witness(_fetch(primary), witness_file)[0] == 0
        bundle = primary.client.get("/v1/evidence/export", headers=_h(ANALYST)).json()
        _run(primary, 3, start=4)
        code, message = WITNESS.witness(_fetch(primary), witness_file)
        assert code == 0 and "size 7" in message, message

        restored = _make(tmp_path / "restored", _second_database(engine_config, tmp_path, postgres_admin_dsn), monkeypatch, enforce=True)
        try:
            _copy_evidence(primary.container, restored.container)
        finally:
            primary.container.close()
        primary = None
        try:
            kept = [json.loads(line) for line in witness_file.read_text().splitlines()]
            # The OLD bundle, checked against the root the CUSTOMER kept.
            assert VERIFIER.verify(bundle, trusted_root=kept[0]["root"], trusted_size=kept[0]["tree_size"]) == []
            # The restored service is a consistent continuation of what was witnessed.
            assert WITNESS.witness(_fetch(restored), witness_file) == (0, "unchanged at size 7")
            _run(restored, 2, start=7)
            assert WITNESS.witness(_fetch(restored), witness_file)[0] == 0
        finally:
            restored.container.close()
    finally:
        if primary is not None:
            primary.container.close()


def test_a_rewritten_log_fails_the_customers_witness(tmp_path, engine_config, monkeypatch):
    witness_file = tmp_path / "customer" / "acme-roots.jsonl"
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    try:
        _run(harness, 5)
        assert WITNESS.witness(_fetch(harness), witness_file)[0] == 0
        with harness.container.pool.acquire() as conn:      # an operator rewrites history
            conn.begin()
            conn.set_tenant("acme")
            conn.execute_rowcount(
                f"UPDATE transparency_leaves SET digest={conn.p} WHERE tenant_id={conn.p} AND sequence={conn.p}",
                ("ab" * 32, "acme", 2),
            )
            conn.commit()
        _run(harness, 1, start=5)
        code, message = WITNESS.witness(_fetch(harness), witness_file)
        assert code == 1 and "NOT AN EXTENSION" in message
        assert len(witness_file.read_text().splitlines()) == 1, "a forked root was recorded as witnessed"
    finally:
        harness.container.close()


def test_a_truncated_log_fails_too(tmp_path, engine_config, monkeypatch):
    witness_file = tmp_path / "customer" / "acme-roots.jsonl"
    harness = _make(tmp_path, engine_config, monkeypatch, enforce=True)
    try:
        _run(harness, 4)
        WITNESS.witness(_fetch(harness), witness_file)
        with harness.container.pool.acquire() as conn:
            conn.begin()
            conn.set_tenant("acme")
            conn.execute_rowcount(f"DELETE FROM evidence_commitments WHERE tenant_id={conn.p} AND sequence={conn.p}", ("acme", 3))
            conn.execute_rowcount(f"DELETE FROM transparency_leaves WHERE tenant_id={conn.p} AND sequence={conn.p}", ("acme", 3))
            conn.commit()
        code, message = WITNESS.witness(_fetch(harness), witness_file)
        assert code == 1 and "SHRANK" in message
    finally:
        harness.container.close()


def _second_database(engine_config, tmp_path, admin_dsn):
    """Another database of the same engine: a new file, or a new PostgreSQL database.

    The administrator DSN comes from the session fixture, NOT from
    `SENTINEL_TEST_POSTGRES_DSN`: that variable exists only when an operator
    points the suite at their own server. CI's suite job uses the embedded
    server, where reading the variable raised KeyError -- a test that passed
    on every developer machine and failed on the first hosted run.
    """
    from dataclasses import replace

    from sentinel.infrastructure.sql.engine import Dialect

    if engine_config.dialect is Dialect.SQLITE:
        return replace(engine_config, dsn=str(tmp_path / "restored-elsewhere.db"))
    import uuid

    import psycopg
    from psycopg import sql

    from tests_arch.conftest import APP_ROLE, _with_dbname

    name = f"sentinel_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(name), sql.Identifier(APP_ROLE)))
    return replace(engine_config, dsn=_with_dbname(engine_config.dsn, name))
