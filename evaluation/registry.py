"""Model / policy registry stubs that track actual versions present in-repo.

Does not invent AUC. Records whatever evaluate runners measure.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

DEFAULT_REGISTRY = Path("evaluation/model_registry.json")


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    name: str
    version: str
    kind: str
    recorded_at: str
    metrics: Mapping[str, Any]
    notes: str = ""


def load_registry(path: Path = DEFAULT_REGISTRY) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("registry must be a JSON list")
    return data


def record_entry(
    entry: RegistryEntry, *, path: Path = DEFAULT_REGISTRY
) -> list[dict[str, Any]]:
    rows = load_registry(path)
    rows.append(asdict(entry))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rows


def entry_from_metrics(
    *, name: str, version: str, kind: str, metrics: Mapping[str, Any], notes: str = ""
) -> RegistryEntry:
    return RegistryEntry(
        name=name,
        version=version,
        kind=kind,
        recorded_at=datetime.now(timezone.utc).isoformat(),
        metrics=dict(metrics),
        notes=notes,
    )
