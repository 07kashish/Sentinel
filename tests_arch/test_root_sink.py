"""A local-file sink would be worse than no sink, and this is why.

`is_independently_verifiable` is the only thing separating "this log is
evidence" and "this log is the operator's assertion". A sink that wrote the
root to a disk the operator owns would set that flag to True while proving
nothing -- and a flag that means nothing gets read as if it meant something.

So the default refuses, and these tests are mostly about the ways a sink could
manufacture a green tick.
"""

from __future__ import annotations

import pytest

from sentinel.domain.root_sink import (
    PublicationReceipt,
    RefusingRootSink,
    RootSink,
    RootSinkUnavailable,
)

NOW = "2026-09-03T10:00:00Z"


# ── the default refuses, and says what is missing ───────────────────────────


def test_the_default_sink_refuses_to_publish():
    with pytest.raises(RootSinkUnavailable) as raised:
        RefusingRootSink().publish(
            tenant_id="acme", tree_size=4, root_hash="a" * 64
        )

    assert "no root sink is configured" in str(raised.value)


def test_the_refusal_explains_why_there_is_no_local_file_fallback():
    """The obvious "something is better than nothing" is the thing that breaks
    the flag.
    """
    with pytest.raises(RootSinkUnavailable) as raised:
        RefusingRootSink().publish(
            tenant_id="acme", tree_size=1, root_hash="b" * 64
        )

    message = str(raised.value)
    assert "no local-file fallback on purpose" in message
    assert "disk the operator owns" in message
    assert "separating evidence from an assertion" in message


def test_the_refusal_names_the_options_rather_than_leaving_it_open():
    """"Configure a sink" is a shrug. Naming the four real choices is
    something an operator can act on this afternoon.
    """
    with pytest.raises(RootSinkUnavailable) as raised:
        RefusingRootSink().publish(
            tenant_id="acme", tree_size=1, root_hash="c" * 64
        )

    message = str(raised.value)
    assert "Object Lock" in message
    assert "RFC 3161" in message
    assert "WORM" in message


def test_the_refusal_states_what_the_log_still_does_detect():
    """Left out, an operator reads the refusal as "the log is useless" and
    stops running it. It detects mistakes, partial restores and diverging
    replicas -- just not a determined operator.
    """
    with pytest.raises(RootSinkUnavailable) as raised:
        RefusingRootSink().publish(
            tenant_id="acme", tree_size=1, root_hash="d" * 64
        )

    message = str(raised.value)
    assert "partial restores" in message
    assert "does not detect a determined operator" in message


def test_the_refusing_sink_reports_its_name_as_none():
    """Which is the value the store uses for an unpublished root, so a
    publication that somehow got recorded from this sink would still read as
    unverifiable rather than as evidence.
    """
    assert RefusingRootSink().name == "none"


def test_the_refusing_sink_satisfies_the_protocol():
    """The refusing default must be substitutable for a real sink, or callers
    end up writing `if sink is not None` and forgetting one branch.
    """
    assert isinstance(RefusingRootSink(), RootSink)


# ── a receipt cannot be manufactured ────────────────────────────────────────


def test_a_receipt_with_no_reference_is_refused():
    """A publication with nothing a third party can fetch is the operator's
    word, and recording it would set is_independently_verifiable to True for a
    root only the operator can produce.
    """
    with pytest.raises(ValueError) as raised:
        PublicationReceipt(sink="s3-object-lock", reference="  ", published_at=NOW)

    assert "returned no reference" in str(raised.value)


def test_a_receipt_claiming_the_none_sink_is_refused():
    """`none` is the value the store uses for an UNPUBLISHED root, so a
    receipt claiming it would record an absence as a publication.
    """
    with pytest.raises(ValueError) as raised:
        PublicationReceipt(sink="none", reference="ref", published_at=NOW)

    assert "records an absence as a publication" in str(
        raised.value
    ) or "record an absence as a publication" in str(raised.value)


def test_a_receipt_with_an_empty_sink_is_refused():
    with pytest.raises(ValueError):
        PublicationReceipt(sink="   ", reference="ref", published_at=NOW)


def test_a_real_receipt_is_accepted():
    """The positive case must exist, or every publication path is dead code."""
    receipt = PublicationReceipt(
        sink="s3-object-lock", reference="version-id-abc", published_at=NOW
    )

    assert receipt.sink == "s3-object-lock"
    assert receipt.reference == "version-id-abc"


# ── the contract stays one method wide ──────────────────────────────────────


def test_the_protocol_exposes_only_a_name_and_publish():
    """Every additional capability is another thing an implementation can get
    wrong on the far side of the boundary that makes the log worth anything.
    """
    members = {
        name
        for name in dir(RootSink)
        if not name.startswith("_") and name not in {"mro"}
    }

    assert members == {"name", "publish"}, members


def test_the_module_states_that_the_maths_stops_at_the_operator():
    import inspect

    from sentinel.domain import root_sink

    doc = " ".join((inspect.getdoc(root_sink) or "").split())

    assert "EXCEPT the party that runs the log" in doc
    assert "Rewrite both and every proof verifies" in doc


def test_a_publish_failure_is_an_exception_and_not_a_return_value():
    """A caller cannot mistake failure for success by ignoring a return value.
    The store records only what a sink actually confirmed.
    """
    import inspect

    from sentinel.domain.root_sink import RootSink

    doc = inspect.getdoc(RootSink.publish) or ""

    assert "RAISE" in doc
    assert "green tick" in doc


def test_the_module_holds_no_mutable_state():
    import types

    from sentinel.domain import root_sink

    mutable = [
        name
        for name, value in vars(root_sink).items()
        if not name.startswith("__")
        and isinstance(value, (dict, list, set))
        and not isinstance(value, (frozenset, types.MappingProxyType))
    ]
    assert not mutable, f"module-level mutable state: {mutable}"
