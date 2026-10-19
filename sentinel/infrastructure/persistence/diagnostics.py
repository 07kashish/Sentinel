"""Query diagnostics: plan analysis, statement counting, and timing.

WHY THIS IS PRODUCTION CODE AND NOT A TEST HELPER
---------------------------------------------------
Two of the three things here are useful in production, not only in CI.
`StatementCounter` is how an N+1 is caught in a staging environment before a
customer finds it, and `explain` is what an operator reaches for when a query
that was fast last month is not. Putting them in the test tree would mean
reimplementing them the first time a real incident needed them.

WHAT "NO TABLE SCAN" ACTUALLY MEANS
------------------------------------
It cannot mean "no sequential scan anywhere". PostgreSQL is right to scan a
forty-row table: an index lookup costs a random page read and the whole table
fits in one page. Forbidding that outright makes the rule absurd and teaches
people to disable it.

The rule that holds is: **no sequential scan of a table that grows without
bound, on a query that runs on a hot path.** `PlanAnalysis.offending_scans`
takes the set of tables where that matters and reports scans of those, ignoring
the small static ones.

The other half is that the plan must be measured on a table with enough rows for
the planner to make a realistic choice. An EXPLAIN over ten rows proves nothing,
because a sequential scan is genuinely optimal there -- so the benchmark seeds
representative volume before it measures anything.
"""

from __future__ import annotations

import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Literal, Sequence

from sentinel.infrastructure.persistence.engine import Connection, Dialect

__all__ = [
    "PlanAnalysis",
    "QueryTiming",
    "StatementCounter",
    "analyse_plan",
    "count_statements",
    "time_query",
]

#: Tables that grow with usage. A sequential scan of one of these on a hot path
#: is a defect; a scan of anything else is usually the planner being sensible.
UNBOUNDED_TABLES: frozenset[str] = frozenset(
    {
        "incidents",
        "incident_transitions",
        "evidence",
        "reports",
        "approvals",
        "ledger_entries",
        "outbox",
        "inbox",
        "execution_steps",
        "work_queue",
        "domain_events",
        "replay_nonces",
        "audit_log",
    }
)

_PG_SCAN = re.compile(r"(Seq Scan|Parallel Seq Scan) on (\w+)")
_PG_INDEX = re.compile(r"(Index Scan|Index Only Scan|Bitmap Index Scan)[^\n]*? on (\w+)")
_PG_ROWS = re.compile(r"rows=(\d+)")
_LITE_SCAN = re.compile(r"SCAN (\w+)")
_LITE_INDEX = re.compile(r"(?:SEARCH|SCAN) (\w+) USING")


@dataclass(frozen=True, slots=True)
class PlanAnalysis:
    """What the planner decided, reduced to the questions worth asking."""

    sql: str
    plan: str
    dialect: Dialect
    sequential_scans: tuple[str, ...]
    index_scans: tuple[str, ...]
    estimated_rows: int

    def offending_scans(
        self, unbounded: frozenset[str] = UNBOUNDED_TABLES
    ) -> tuple[str, ...]:
        """Sequential scans of tables that grow without bound.

        A partition name like `domain_events_2026_07` is attributed to its parent
        so a scan of one month's partition is judged as a scan of the table it
        belongs to -- and a scan of a single pruned partition is still reported,
        because it means the index within that partition was not used.
        """
        offenders = []
        for table in self.sequential_scans:
            base = _parent_table(table)
            if base in unbounded:
                offenders.append(table)
        return tuple(offenders)

    @property
    def used_an_index(self) -> bool:
        return bool(self.index_scans)


def _parent_table(name: str) -> str:
    """Map `audit_log_2026_07` and `audit_log_default` to `audit_log`."""
    stripped = re.sub(r"_(\d{4}_\d{2}|default)$", "", name)
    return stripped


def analyse_plan(
    conn: Connection, sql: str, params: Sequence[Any] = (), *, analyze: bool = False
) -> PlanAnalysis:
    """EXPLAIN one statement and reduce the plan to a verdict.

    `analyze=True` EXECUTES the statement to get real row counts, so callers use
    it inside a transaction they roll back.
    """
    plan = conn.explain(sql, params, analyze=analyze)

    if conn.dialect is Dialect.POSTGRES:
        scans = tuple(match.group(2) for match in _PG_SCAN.finditer(plan))
        indexes = tuple(match.group(2) for match in _PG_INDEX.finditer(plan))
        rows_match = _PG_ROWS.search(plan)
        estimated = int(rows_match.group(1)) if rows_match else 0
    else:
        # SQLite's EXPLAIN QUERY PLAN says "SCAN t" for a full scan and
        # "SEARCH t USING INDEX ..." for an indexed lookup. A line matching the
        # index form is not a sequential scan even though it starts with SCAN.
        indexes = tuple(match.group(1) for match in _LITE_INDEX.finditer(plan))
        scans = tuple(
            match.group(1)
            for match in _LITE_SCAN.finditer(plan)
            if "USING" not in plan[match.start() : match.start() + 120]
        )
        estimated = 0

    return PlanAnalysis(
        sql=" ".join(sql.split())[:200],
        plan=plan,
        dialect=conn.dialect,
        sequential_scans=scans,
        index_scans=indexes,
        estimated_rows=estimated,
    )


class StatementCounter:
    """Counts statements executed on a connection.

    This is how an N+1 is DETECTED rather than reasoned about. A repository call
    that issues one query for a list and one more per element has a count that
    grows with the list; one that batches has a count that does not. The test
    runs the same operation over 1 and over 50 entities and asserts the number
    did not move.

    Uses `Connection.observe`, a first-class hook, rather than patching the
    method: `Connection` defines `__slots__`, so per-instance patching raises
    `AttributeError: attribute is read-only`. A hook the connection owns also
    works in staging, where an N+1 is cheapest to find.
    """

    __slots__ = ("_conn", "_statements", "_previous")

    def __init__(self, conn: Connection) -> None:
        self._conn = conn
        self._statements: list[str] = []
        self._previous: Any = None

    @property
    def count(self) -> int:
        return len(self._statements)

    @property
    def statements(self) -> tuple[str, ...]:
        return tuple(self._statements)

    def matching(self, fragment: str) -> tuple[str, ...]:
        needle = fragment.lower()
        return tuple(s for s in self._statements if needle in s.lower())

    def __enter__(self) -> "StatementCounter":
        self._previous = self._conn.observe(self._statements.append)
        return self

    def __exit__(self, *_exc: Any) -> Literal[False]:
        self._conn.observe(self._previous)
        return False


@contextmanager
def count_statements(conn: Connection) -> Iterator[StatementCounter]:
    counter = StatementCounter(conn)
    with counter:
        yield counter


@dataclass(frozen=True, slots=True)
class QueryTiming:
    """Wall-clock cost of one query, over several runs."""

    name: str
    runs: int
    median_ms: float
    p95_ms: float
    max_ms: float
    rows: int

    def __str__(self) -> str:
        return (
            f"{self.name:<44} median={self.median_ms:7.2f}ms "
            f"p95={self.p95_ms:7.2f}ms max={self.max_ms:7.2f}ms rows={self.rows}"
        )


def time_query(
    conn: Connection,
    name: str,
    sql: str,
    params: Sequence[Any] = (),
    *,
    runs: int = 25,
) -> QueryTiming:
    """Measure a query. Reports the median and p95, never the mean.

    A mean over 25 runs is dominated by whichever one hit a cold page. The
    median is what the query usually costs and the p95 is what it costs when it
    does not, and those are the two numbers an operator acts on.
    """
    samples: list[float] = []
    rows = 0
    for _ in range(runs):
        started = time.perf_counter()
        result = conn.execute(sql, params)
        samples.append((time.perf_counter() - started) * 1000)
        rows = len(result)
    samples.sort()
    return QueryTiming(
        name=name,
        runs=runs,
        median_ms=samples[len(samples) // 2],
        p95_ms=samples[min(len(samples) - 1, int(len(samples) * 0.95))],
        max_ms=samples[-1],
        rows=rows,
    )
