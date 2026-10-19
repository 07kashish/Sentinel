"""PostgreSQL: one read-only statement, under a tier ceiling.

THREE INDEPENDENT CONTAINMENTS
------------------------------
SQL is the one platform here where the classifier is a text matcher, and text
matchers lose to determined input. So this adapter does not rely on being right
about SQL:

  1. THE TIER CEILING, from `action_semantics`. Catches the honest shapes --
     DROP, GRANT, an UPDATE with no row filter.

  2. ONE STATEMENT PER CALL. A classified SELECT cannot carry a DROP behind a
     semicolon, because a second statement is refused before the database sees
     it. The classifier reads the first statement; PostgreSQL would run both.

  3. A READ ONLY TRANSACTION WITH A STATEMENT TIMEOUT, enforced by PostgreSQL
     rather than by this process. This is the only one of the three an attacker
     cannot argue with: it does not depend on any of this module's parsing being
     correct, and it is why the other two being defeated is not fatal.

Parameters are bound by the driver, never interpolated. The statement is the
agent's; the values are not spliced into it.

NOT SENTINEL'S OWN DATABASE
---------------------------
`PostgresCredentials.dsn` names the database agents may query. Pointing it at
Sentinel's own store would let an agent read the incidents, the evidence and the
audit trail that exist to describe that agent -- so the composition root refuses
a DSN equal to the store's, and this module says so here because the class is
where someone will look.

A CONSERVATIVE FALSE REFUSAL, RECORDED
--------------------------------------
The multi-statement check is textual, so a semicolon inside a string literal --
`SELECT 'a;b'` -- is refused even though it is a single statement. That is a
false refusal in favour of safety, and it is cheap to work around (bind the
literal as a parameter). The alternative is parsing SQL, which is a job this
module explicitly does not take on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.application.tool_proxy import RegisteredSideEffect
from sentinel.infrastructure.platforms.ceiling import (
    DEFAULT_CEILING,
    bounded,
    classify_or_refuse,
    enforce_ceiling,
    no_effect_possible,
    normalise_ceiling,
)
from sentinel.infrastructure.tool_adapters import ToolAdapterRefused

__all__ = ["MAX_SQL_ROWS", "PostgresCredentials", "sql_query_adapter"]

#: Cap on rows returned in one call. The result travels back through the API
#: response and into evidence; an unbounded SELECT is a memory-exhaustion
#: primitive and an exfiltration primitive at the same time.
MAX_SQL_ROWS = 500

#: Cap on statement length. A statement nobody can read is a statement nobody
#: reviewed.
MAX_STATEMENT_CHARS = 8192


@dataclass(frozen=True, slots=True)
class PostgresCredentials:
    """A DSN for the database agents may query. NOT Sentinel's own store."""

    dsn: str
    statement_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        if not str(self.dsn).strip():
            raise ToolAdapterRefused("PostgreSQL DSN is required")
        if int(self.statement_timeout_ms) <= 0:
            raise ToolAdapterRefused("statement_timeout_ms must be positive")


#: A statement separator followed by more input. Used ONLY to refuse
#: multi-statement calls -- not to parse SQL.
_TERMINATOR = re.compile(r";\s*\S")


def sql_query_adapter(
    *,
    credentials: PostgresCredentials,
    ceiling: str = DEFAULT_CEILING,
    connect: Any = None,
) -> RegisteredSideEffect:
    """Run one SQL statement in a read-only transaction, under a tier ceiling."""
    limit = normalise_ceiling(ceiling)

    def _open() -> Any:
        if connect is not None:
            return connect()
        # Imported here rather than at module scope so that
        # `test_every_module_is_importable_in_isolation` does not depend on the
        # driver, and so a deployment with no SQL adapter configured never pays
        # for it.
        import psycopg  # noqa: PLC0415

        return psycopg.connect(credentials.dsn, autocommit=False)

    def run(args: Mapping[str, Any]) -> dict[str, Any]:
        statement = str(args.get("statement", "")).strip()
        if not statement:
            raise ToolAdapterRefused("statement is required")
        if len(statement) > MAX_STATEMENT_CHARS:
            raise ToolAdapterRefused(
                f"statement is over {MAX_STATEMENT_CHARS} characters"
            )
        if _TERMINATOR.search(statement.rstrip().rstrip(";")):
            raise ToolAdapterRefused(
                "multiple statements in one call are refused; the classifier "
                "reads the first statement and the database would run them all"
            )

        semantics = classify_or_refuse(
            platform="sql", action=statement, resource="", metadata={}
        )
        enforce_ceiling(semantics, limit)

        parameters = args.get("parameters")
        if parameters is not None and not isinstance(parameters, (list, tuple)):
            raise ToolAdapterRefused(
                "parameters must be a list; they are bound by the driver, never "
                "interpolated into the statement"
            )
        bound = tuple(parameters or ())

        connection = _open()
        try:
            with connection.cursor() as cursor:
                # Set on the transaction, so PostgreSQL refuses a write this
                # module's text matching failed to recognise. The containment
                # that does not depend on being right about SQL.
                cursor.execute("SET TRANSACTION READ ONLY")
                cursor.execute(
                    "SET LOCAL statement_timeout = "
                    f"{int(credentials.statement_timeout_ms)}"
                )
                cursor.execute(statement, bound)
                columns = [d[0] for d in (cursor.description or ())]
                rows: Sequence[Any] = (
                    cursor.fetchmany(MAX_SQL_ROWS + 1) if columns else ()
                )
            # Even a successful read is rolled back: nothing this adapter does
            # commits, and a read-only transaction left open is a held snapshot.
            connection.rollback()
        except ToolAdapterRefused:
            raise
        except Exception as exc:
            try:
                connection.rollback()
            except Exception:  # pragma: no cover - rollback on a dead connection
                pass
            raise ToolAdapterRefused(f"query refused by the database: {exc}") from exc
        finally:
            try:
                connection.close()
            except Exception:  # pragma: no cover
                pass

        truncated = len(rows) > MAX_SQL_ROWS
        return bounded(
            {
                "platform": "postgresql",
                "operation": semantics.operation,
                "semantics": semantics.as_metadata(),
                "columns": columns,
                "rows": [list(r) for r in rows[:MAX_SQL_ROWS]],
                "row_count": min(len(rows), MAX_SQL_ROWS),
                # Reported rather than silently applied. An analyst reading
                # evidence needs to know the answer was cut off.
                "truncated": truncated,
            }
        )

    # READ ONLY is enforced by PostgreSQL itself, so no refusal here can follow an effect.
    return RegisteredSideEffect(name="sql_query", runner=no_effect_possible(run))
