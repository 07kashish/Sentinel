"""Bounds on attacker-supplied structure: the memory-poisoning and DoS class.

WHAT THIS IS DEFENDING
----------------------
`EventPayload.metadata` was the one field with arbitrary structure and no limit,
while every sibling had a length cap. The incident record is the context every
later pipeline step reads, so whatever lands in metadata is re-read repeatedly, is
canonicalised to compute the event digest a signature covers, and is copied into
the audit trail. Three concrete reachable failures:

  * deep nesting -> `RecursionError` from the canonicaliser, which is not a
    `ValueError`, so it escapes as a 500 rather than a 400
  * one enormous value -> persisted, then re-read by every step
  * very many small keys -> passes every per-value check, and the sort for
    canonicalisation pays for it

The checker is iterative for the first of those reasons: a recursive validator is
itself vulnerable to the input it exists to reject.
"""

from __future__ import annotations

import json

import pytest

from sentinel.domain.bounded import BoundsExceeded, StructureBounds, check_bounds

BOUNDS = StructureBounds()


def _nest(depth: int) -> dict:
    node: dict = {"leaf": 1}
    for _ in range(depth):
        node = {"n": node}
    return node


# ── Depth ────────────────────────────────────────────────────────────────────


def test_deep_nesting_is_refused_as_a_domain_error_not_a_recursion_error():
    """The distinction is the whole point.

    `RecursionError` is not a `ValueError` and not a `SentinelError`, so a handler
    that catches JSON or domain errors does not catch it: the request becomes a
    500 and the attacker learns they found something. A `BoundsExceeded` becomes a
    422 naming the limit.
    """
    with pytest.raises(BoundsExceeded) as refused:
        check_bounds(_nest(200), BOUNDS, field="metadata")
    assert "nesting is deeper than" in str(refused.value)
    assert "metadata" in str(refused.value)


def test_the_checker_survives_input_deep_enough_to_break_a_recursive_one():
    """A recursive checker would blow the stack here rather than refuse.

    10,000 levels is well past Python's default limit, so this test distinguishes
    "iterative" from "recursive but usually fine".
    """
    with pytest.raises(BoundsExceeded):
        check_bounds(_nest(10_000), BOUNDS, field="metadata")


def test_nesting_at_the_limit_is_accepted():
    """Off-by-one in a bound is how a legitimate client gets refused."""
    check_bounds(_nest(BOUNDS.max_depth - 1), BOUNDS)


def test_the_canonicaliser_genuinely_breaks_on_what_this_rejects():
    """Proves the bound is defending something real, not a theory.

    If `json.dumps` handled arbitrary depth there would be no reason for the depth
    limit. It does not, and this asserts that.
    """
    with pytest.raises(RecursionError):
        json.dumps(_nest(10_000))


# ── Size and breadth ─────────────────────────────────────────────────────────


def test_a_single_enormous_value_is_refused():
    with pytest.raises(BoundsExceeded) as refused:
        check_bounds({"blob": "x" * 1_000_000}, BOUNDS)
    assert "over the" in str(refused.value)


def test_many_small_keys_are_refused_by_the_total_budget():
    """Each key passes every per-value check; the total is what is unbounded."""
    with pytest.raises(BoundsExceeded):
        check_bounds({f"k{n}": "v" for n in range(50_000)}, BOUNDS)


def test_breadth_spread_across_many_small_containers_is_still_bounded():
    """No single container breaks its own limit, so only a total budget catches it.

    Every mapping here holds 60 keys, under the 64 limit, and the nesting is three
    deep, under the 6 limit. Each individual check passes. The structure still
    carries ~3,600 leaves, which is the shape a per-container limit cannot see and
    the reason `max_nodes` and `max_total_bytes` exist.
    """
    inner = {f"k{n}": "v" for n in range(60)}
    wide = {f"m{n}": dict(inner) for n in range(60)}

    # Confirm the premise: no per-container limit is what fires.
    assert len(wide) <= BOUNDS.max_keys
    assert all(len(child) <= BOUNDS.max_keys for child in wide.values())

    with pytest.raises(BoundsExceeded) as refused:
        check_bounds(wide, BOUNDS)
    message = str(refused.value)
    assert "keys" not in message and "items" not in message, (
        f"a per-container limit fired, so the total budget was never tested: {message}"
    )


def test_a_long_key_is_refused_as_well_as_a_long_value():
    """Keys are attacker-controlled too, and they are what gets sorted."""
    with pytest.raises(BoundsExceeded) as refused:
        check_bounds({"k" * 100_000: "v"}, BOUNDS)
    assert "a key" in str(refused.value)


def test_rejection_cost_is_proportional_to_the_limit_not_the_payload():
    """`len(json.dumps(value))` has already built the hostile string.

    Walking with a running budget means a 20MB payload is refused after examining
    roughly the limit's worth of it. Asserted by timing bound, loosely, because the
    property is asymptotic rather than a specific number.
    """
    import time

    huge = {f"k{n}": "x" * 4000 for n in range(5_000)}  # ~20MB serialised
    started = time.monotonic()
    with pytest.raises(BoundsExceeded):
        check_bounds(huge, BOUNDS)
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"refusal took {elapsed:.2f}s; it is walking the whole payload"


# ── Type discipline ──────────────────────────────────────────────────────────


def test_a_non_string_key_is_refused():
    """Non-string keys do not survive JSON canonicalisation.

    `{1: "a"}` serialises to `{"1": "a"}`, so the signed canonical form differs
    from what was submitted -- and a verifier reconstructing it from the stored
    record computes a different digest.
    """
    with pytest.raises(BoundsExceeded) as refused:
        check_bounds({1: "a"}, BOUNDS)
    assert "not a string" in str(refused.value)


def test_floats_are_refused_because_they_do_not_round_trip():
    """A signature over a canonical form containing a float is not reliably
    verifiable across platforms."""
    with pytest.raises(BoundsExceeded) as refused:
        check_bounds({"score": 0.1}, BOUNDS)
    assert "round-trip" in str(refused.value)


def test_non_json_types_are_refused():
    with pytest.raises(BoundsExceeded) as refused:
        check_bounds({"when": object()}, BOUNDS)
    assert "not permitted" in str(refused.value)


def test_booleans_and_none_and_integers_are_accepted():
    """bool is a subclass of int, so the order of the isinstance checks matters."""
    check_bounds({"ok": True, "missing": None, "count": 42, "big": 10**30}, BOUNDS)


def test_ordinary_telemetry_metadata_passes_untouched():
    """The bounds must not refuse the payload this field exists to carry."""
    check_bounds(
        {
            "tool": "shell",
            "args": ["cat", "/etc/passwd"],
            "session": "s-1234",
            "attempt": 2,
            "nested": {"parent_span": "abc", "flags": ["a", "b"]},
        },
        BOUNDS,
    )


# ── Through HTTP ─────────────────────────────────────────────────────────────


def test_a_hostile_metadata_payload_is_a_422_not_a_500(tmp_path):
    """End to end: the refusal must reach the client as a client error.

    A 500 tells an attacker they found an unhandled path and invites them to keep
    pulling. A 422 naming the limit tells a legitimate client what to fix.
    """
    from fastapi.testclient import TestClient

    from sentinel.composition.container import build_container
    from sentinel.composition.settings import Settings
    from sentinel.infrastructure.sql.engine import build_engine
    from sentinel.infrastructure.sql.migrate import migrate
    from sentinel.interface.http import create_app

    key = "i" * 40
    settings = Settings.from_environment(
        {
            "SENTINEL_API_KEYS": f"acme:{key}:ingest",
            "SENTINEL_DB_PATH": str(tmp_path / "bounds.db"),
        }
    )
    pool = build_engine(settings.engine)
    migrate(pool)
    pool.close()
    container = build_container(settings)
    try:
        client = TestClient(create_app(container), raise_server_exceptions=False)
        for hostile in (
            _nest(500),
            {"blob": "x" * 500_000},
            {f"k{n}": "v" for n in range(20_000)},
        ):
            response = client.post(
                "/v1/events",
                headers={"Authorization": f"Bearer {key}"},
                json={"agentId": "agent-1", "action": "x", "metadata": hostile},
            )
            assert response.status_code == 422, (
                f"expected 422, got {response.status_code}: {response.text[:300]}"
            )
            assert "metadata" in response.text
    finally:
        container.close()
