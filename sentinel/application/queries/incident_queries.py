"""Queries. Projections only — no aggregate is ever loaded on this path.

Each handler is one class with one dependency: the read model. They take no unit
of work, no row locks and no domain objects, which is what makes the read side
independently scalable and independently cacheable later without touching a
single write path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.application.messages import Query
from sentinel.application.ports import ReadModel
from sentinel.domain.primitives import IncidentId

__all__ = [
    "GetIncident",
    "GetIncidentHandler",
    "GetIncidentHistory",
    "GetIncidentHistoryHandler",
    "GetReport",
    "GetReportHandler",
    "ListIncidents",
    "ListIncidentsHandler",
    "TenantDashboard",
    "TenantDashboardHandler",
]


@dataclass(frozen=True, slots=True)
class GetIncident(Query):
    incident_id: IncidentId


class GetIncidentHandler:
    __slots__ = ("_read_model",)

    def __init__(self, *, read_model: ReadModel) -> None:
        self._read_model = read_model

    def handle(self, query: GetIncident) -> Mapping[str, Any] | None:
        return self._read_model.incident_summary(query.tenant, query.incident_id)


@dataclass(frozen=True, slots=True)
class ListIncidents(Query):
    limit: int = 50
    after: str | None = None


class ListIncidentsHandler:
    __slots__ = ("_read_model",)

    def __init__(self, *, read_model: ReadModel) -> None:
        self._read_model = read_model

    def handle(self, query: ListIncidents) -> Mapping[str, Any]:
        rows = list(
            self._read_model.list_incidents(
                query.tenant, limit=query.limit, after=query.after
            )
        )
        # A keyset cursor, returned to the caller. The predecessor had a
        # hard-coded LIMIT 200 with no way to see past it.
        next_cursor = rows[-1]["updated_at"] if len(rows) == query.limit else None
        return {"incidents": rows, "next_cursor": next_cursor}


@dataclass(frozen=True, slots=True)
class GetIncidentHistory(Query):
    incident_id: IncidentId


class GetIncidentHistoryHandler:
    __slots__ = ("_read_model",)

    def __init__(self, *, read_model: ReadModel) -> None:
        self._read_model = read_model

    def handle(self, query: GetIncidentHistory) -> Sequence[Mapping[str, Any]]:
        return self._read_model.incident_history(query.tenant, query.incident_id)


@dataclass(frozen=True, slots=True)
class GetReport(Query):
    incident_id: IncidentId


class GetReportHandler:
    __slots__ = ("_read_model",)

    def __init__(self, *, read_model: ReadModel) -> None:
        self._read_model = read_model

    def handle(self, query: GetReport) -> Mapping[str, Any]:
        content = self._read_model.report(query.tenant, query.incident_id)
        if content is not None:
            return {"incident_id": query.incident_id.value, "report": content}
        summary = self._read_model.incident_summary(query.tenant, query.incident_id)
        if summary is None:
            return {"incident_id": query.incident_id.value, "error": "no such incident"}
        return {
            "incident_id": query.incident_id.value,
            "error": (
                f"no report exists; this incident is {summary['state']}. A report "
                "is written when the incident reaches 'reported'."
            ),
        }


@dataclass(frozen=True, slots=True)
class TenantDashboard(Query):
    """Counts an operator needs, with attested and unattested kept separate."""


class TenantDashboardHandler:
    __slots__ = ("_read_model",)

    def __init__(self, *, read_model: ReadModel) -> None:
        self._read_model = read_model

    def handle(self, query: TenantDashboard) -> Mapping[str, Any]:
        return {
            "incidents_by_state": dict(self._read_model.counts_by_state(query.tenant)),
            "attestation": dict(self._read_model.attestation_summary(query.tenant)),
            # A countable hole, not a silent one.
            "dead_letters": self._read_model.dead_letter_count(query.tenant),
        }
