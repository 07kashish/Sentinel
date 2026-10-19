"""Train / validation / test split tooling for evaluation corpora.

Deterministic splits by case_id hash so CI is reproducible. Does not invent
labels or metrics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Sequence, TypeVar

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Split:
    train: tuple[T, ...]
    val: tuple[T, ...]
    test: tuple[T, ...]

    def counts(self) -> dict[str, int]:
        return {
            "train": len(self.train),
            "val": len(self.val),
            "test": len(self.test),
        }


def _bucket(case_id: str, *, salt: str) -> float:
    digest = hashlib.sha256(f"{salt}:{case_id}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF


def split_by_id(
    items: Sequence[T],
    *,
    id_of,
    train_ratio: float = 0.6,
    val_ratio: float = 0.2,
    salt: str = "sentinel-eval-v1",
) -> Split[T]:
    if train_ratio <= 0 or val_ratio < 0 or train_ratio + val_ratio >= 1:
        raise ValueError("train_ratio/val_ratio must leave a positive test fraction")
    train: list[T] = []
    val: list[T] = []
    test: list[T] = []
    for item in items:
        score = _bucket(str(id_of(item)), salt=salt)
        if score < train_ratio:
            train.append(item)
        elif score < train_ratio + val_ratio:
            val.append(item)
        else:
            test.append(item)
    return Split(train=tuple(train), val=tuple(val), test=tuple(test))


def leave_one_source_out(
    items: Iterable[T], *, source_of
) -> list[tuple[str, tuple[T, ...], tuple[T, ...]]]:
    """Return (held_out_source, train, test) folds."""
    by_source: dict[str, list[T]] = {}
    for item in items:
        by_source.setdefault(str(source_of(item)), []).append(item)
    folds: list[tuple[str, tuple[T, ...], tuple[T, ...]]] = []
    for held in sorted(by_source):
        test = tuple(by_source[held])
        train = tuple(
            item for src, rows in by_source.items() if src != held for item in rows
        )
        folds.append((held, train, test))
    return folds
