"""Fresh and previous-head cleanup with retained schema/security unchanged."""
import importlib

import pytest

from sentinel.infrastructure.sql.engine import Dialect, build_engine

migrations = importlib.import_module("sentinel.infrastructure.sql.migrate")
PARKED = frozenset({
    "a2a_agent_cards", "device_discovery", "organizations", "users",
    "user_credentials", "user_sessions", "enrolment_tickets", "webauthn_challenges",
})


def _catalog(pool):
    with pool.acquire() as conn:
        conn.begin()
        if conn.dialect is Dialect.SQLITE:
            objects = conn.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
            result = {
                "tables": {r["name"] for r in objects if r["type"] == "table"},
                "objects": [dict(r) for r in objects if r["tbl_name"] not in PARKED],
            }
        else:
            tables = conn.execute(
                "SELECT c.relname AS name, c.oid, c.relrowsecurity, c.relforcerowsecurity, "
                "c.relowner, c.relacl::text AS grants FROM pg_class c "
                "JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname"
            )
            indexes = conn.execute(
                "SELECT tablename, indexname, indexdef FROM pg_indexes "
                "WHERE schemaname='public' ORDER BY tablename, indexname"
            )
            policies = conn.execute(
                "SELECT tablename, policyname, permissive, roles::text, cmd, qual, with_check "
                "FROM pg_policies WHERE schemaname='public' ORDER BY tablename, policyname"
            )
            roles = conn.execute(
                "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, "
                "rolcanlogin, rolreplication, rolbypassrls FROM pg_roles ORDER BY rolname"
            )
            result = {
                "tables": {r["name"] for r in tables},
                "objects": [dict(r) for r in tables if r["name"] not in PARKED],
                "indexes": [dict(r) for r in indexes if r["tablename"] not in PARKED],
                "policies": [dict(r) for r in policies if r["tablename"] not in PARKED],
                "roles": [dict(r) for r in roles],
            }
        conn.commit()
        return result


@pytest.mark.parametrize("upgrade", [False, True], ids=["fresh", "from-v39"])
def test_cleanup_drops_only_parked_tables_and_preserves_core(engine_config, monkeypatch, upgrade):
    pool = build_engine(engine_config)
    try:
        before = None
        if upgrade:
            old = tuple(row for row in migrations.MIGRATIONS if row[0] <= 39)
            with monkeypatch.context() as patch:
                patch.setattr(migrations, "MIGRATIONS", old)
                assert migrations.migrate(pool) == 39
            before = _catalog(pool)
            assert PARKED <= before["tables"]
            with pool.acquire() as conn:
                conn.begin()
                conn.execute_rowcount(
                    "INSERT INTO tenants (tenant_id,name,created_at) VALUES "
                    f"({conn.p},{conn.p},{conn.p})",
                    ("preserved", "Preserve this tenant", "2026-10-31T00:00:00+00:00"),
                )
                conn.commit()
        assert migrations.migrate(pool) == 40
        assert migrations.verify(pool) == 40
        after = _catalog(pool)
        assert not (PARKED & after["tables"])
        from sentinel.infrastructure.sql.schema_cleanup import CURRENT_TABLES, CURRENT_PROTECTED_TABLES
        assert after["tables"] == set(CURRENT_TABLES)
        assert len(CURRENT_TABLES) >= 30
        assert set(CURRENT_PROTECTED_TABLES) <= after["tables"]
        if before:
            assert after["tables"] == before["tables"] - PARKED
            for key in before.keys() - {"tables"}:
                assert after[key] == before[key], key
            with pool.acquire() as conn:
                assert conn.one("SELECT name FROM tenants WHERE tenant_id='preserved'")["name"] == "Preserve this tenant"
        assert migrations.migrate(pool) == 40
        assert _catalog(pool) == after
    finally:
        pool.close()
