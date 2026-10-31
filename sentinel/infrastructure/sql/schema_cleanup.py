"""Migration 40 and its live-table view; historical DDL stays immutable."""
from typing import Final

from sentinel.infrastructure.sql.engine import Connection
from sentinel.infrastructure.sql.schema import PROTECTED_TABLES, SCHEMA_STATEMENTS

# Live inventories after migration 40. Historical DDL and PROTECTED_TABLES
# above remain unchanged because migrations 1–39 replay them.
PARKED_TABLES: Final[frozenset[str]] = frozenset({
    "user_credentials", "user_sessions", "enrolment_tickets", "webauthn_challenges",
    "users", "organizations", "a2a_agent_cards", "device_discovery",
})


def _current_tables() -> frozenset[str]:
    import re

    pattern = re.compile(r"CREATE TABLE IF NOT EXISTS\s+([a-z0-9_]+)", re.IGNORECASE)
    historical = {match.group(1) for statement in SCHEMA_STATEMENTS
                  if (match := pattern.search(statement))}
    return frozenset(historical - PARKED_TABLES) | {"schema_migrations"}


CURRENT_TABLES: Final[frozenset[str]] = _current_tables()
CURRENT_PROTECTED_TABLES: Final[tuple[str, ...]] = tuple(
    current_name for current_name in PROTECTED_TABLES if current_name not in PARKED_TABLES
)


def drop_parked_features(conn: Connection) -> None:
    """Retire only the enumerated Phase 3 feature tables; never cascade."""
    conn.execute_rowcount("DROP TABLE IF EXISTS user_credentials")
    conn.execute_rowcount("DROP TABLE IF EXISTS user_sessions")
    conn.execute_rowcount("DROP TABLE IF EXISTS enrolment_tickets")
    conn.execute_rowcount("DROP TABLE IF EXISTS webauthn_challenges")
    conn.execute_rowcount("DROP TABLE IF EXISTS users")
    conn.execute_rowcount("DROP TABLE IF EXISTS organizations")
    conn.execute_rowcount("DROP TABLE IF EXISTS a2a_agent_cards")
    conn.execute_rowcount("DROP TABLE IF EXISTS device_discovery")


