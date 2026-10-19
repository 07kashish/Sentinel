"""SIEM export, tested as an injection problem rather than a formatting one.

THE ATTACK THIS IS ABOUT
------------------------
Several fields Sentinel exports are attacker-influenced: an MCP tool
description, a prompt, a resource path an agent chose, an MCP server id. CEF
separates fields with `|`, separates extension keys with `=` and spaces, and
separates EVENTS with newlines.

So a resource id containing

    x\\nCEF:0|Sentinel|SentinelSOC|1.0|login|Successful login|0|

is not a strange-looking log line. It is a second event, forged, sitting in the
analyst's console with Sentinel's name on it. That is worth more to an attacker
than evading detection: it actively misleads the investigation.

Every test below feeds a hostile value through a real formatter and asserts on
the OUTPUT, because escaping is the kind of code that looks obviously correct
and is obviously correct right up until the ordering is wrong.
"""

from __future__ import annotations

import json

import pytest

from sentinel.infrastructure.siem import (
    SUPPORTED_FORMATS,
    SiemEvent,
    escape_cef_extension,
    escape_cef_header,
    format_cef,
    format_ecs,
    render,
)

#: Values an attacker could plausibly get into an exported field, each aimed at
#: a different delimiter.
HOSTILE = {
    "newline_forges_an_event": "x\nCEF:0|Sentinel|SentinelSOC|1.0|login|ok|0|",
    "carriage_return": "x\rCEF:0|a|b|c|d|e|0|",
    "crlf": "x\r\nCEF:0|a|b|c|d|e|0|",
    "pipe_forges_a_header_field": "a|b|c|d|e|f|g",
    "equals_forges_a_key": "x outcome=success suser=admin",
    "backslash": "back\\slash",
    "backslash_then_pipe": "trailing\\|pipe",
    "unicode_line_separator": "x\u2028CEF:0|a|b|c|d|e|0|",
    "unicode_paragraph_separator": "x\u2029forged",
    "nul_byte": "x\x00truncated",
    "vertical_tab": "x\x0bforged",
    "form_feed": "x\x0cforged",
}


def _event(**over) -> SiemEvent:
    base = {
        "tenant_id": "acme",
        "occurred_at": "2026-08-22T00:00:00+00:00",
        "actor": "key:abc123",
        "action": "mcp.evaluate",
        "resource_type": "mcp_tool",
        "resource_id": "docs-mcp/search_docs",
        "outcome": "denied",
        "sequence": 7,
        "detail": {"allowed": False},
    }
    base.update(over)
    return SiemEvent(**base)


# ── The control case ─────────────────────────────────────────────────────────


def test_a_benign_event_renders_the_fields_it_was_given():
    """Without this, a formatter that emitted an empty string would pass every
    injection test in this module."""
    line = format_cef(_event())

    assert line.startswith("CEF:0|Sentinel|SentinelSOC|1.0|mcp.evaluate|")
    assert "cs1=acme" in line
    assert "cs3=docs-mcp/search_docs" in line
    assert "cn1=7" in line
    assert "suser=key:abc123" in line


def test_the_ecs_form_is_valid_json_with_the_same_facts():
    document = json.loads(format_ecs(_event()))
    assert document["organization"]["id"] == "acme"
    assert document["event"]["action"] == "mcp.evaluate"
    assert document["event"]["outcome"] == "failure"
    assert document["sentinel"]["resource_id"] == "docs-mcp/search_docs"


# ── One event in, one line out ───────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(HOSTILE))
@pytest.mark.parametrize("field", ["resource_id", "actor", "action", "resource_type"])
def test_a_hostile_field_cannot_produce_a_second_cef_line(name: str, field: str):
    """The headline property, asserted the blunt way.

    Whatever the field contains, `format_cef` returns exactly one line. If it
    can ever return two, the second one is an event the attacker wrote.
    """
    line = format_cef(_event(**{field: HOSTILE[name]}))

    assert "\n" not in line, f"{field}={name} produced a second line"
    assert "\r" not in line
    assert "\u2028" not in line and "\u2029" not in line
    assert "\x00" not in line


@pytest.mark.parametrize("name", sorted(HOSTILE))
@pytest.mark.parametrize("field", ["resource_id", "actor", "action"])
def test_a_hostile_field_cannot_produce_a_second_ecs_line(name: str, field: str):
    line = format_ecs(_event(**{field: HOSTILE[name]}))

    assert "\n" not in line and "\r" not in line
    # And it must still parse: escaping that produces invalid JSON drops the
    # event at the collector, which is the same outcome as never exporting it.
    json.loads(line)


def _header_fields(line: str) -> list[str]:
    """Split a CEF line into its header fields on UNESCAPED pipes.

    `|` delimits only the header; the extension that follows the seventh pipe
    may contain pipes freely, and the CEF spec does not escape them there.
    Splitting the whole line naively is what made the first version of this
    helper report 13 fields and nearly pass a broken assertion.
    """
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            fields.append("".join(current))
            current = []
            if len(fields) == 7:  # everything after this is the extension
                break
        else:
            current.append(char)
    return fields


def test_a_forged_cef_prefix_cannot_begin_a_line_or_shift_the_header():
    """The payload text may survive INSIDE a field. That is fine and is the
    point of escaping: a parser splits on newlines first, so text that never
    starts a line is inert no matter what it says.

    What must not happen is the two things that give it meaning -- starting a
    new line, or shifting the positional header so the attacker chooses what the
    SIEM reads as severity.
    """
    line = format_cef(_event(resource_id=HOSTILE["newline_forges_an_event"]))

    assert line.split("\n") == [line], "the payload started a second line"
    assert line.startswith("CEF:0|Sentinel|SentinelSOC|1.0|")

    fields = _header_fields(line)
    assert len(fields) == 7, f"header has {len(fields)} fields, expected 7"
    assert fields[6] == "7", f"severity was displaced to {fields[6]!r}"


# ── Delimiter escaping, in both directions ───────────────────────────────────


def test_a_pipe_in_a_header_field_is_escaped_and_does_not_add_a_field():
    """The header is positional: an extra `|` shifts every field after it, so
    the attacker chooses what the SIEM reads as severity."""
    line = format_cef(_event(action="a|b|c|d|e|f|g"))

    fields = _header_fields(line)
    assert len(fields) == 7, f"header has {len(fields)} fields, expected 7"
    # The hostile value stays in ONE field, escaped, rather than becoming six.
    assert fields[4] == "a\\|b\\|c\\|d\\|e\\|f\\|g"
    # And severity is still severity, not a value the attacker chose.
    assert fields[6] == "7"


def test_an_equals_in_an_extension_value_cannot_declare_a_new_key():
    """`outcome=denied` must not become `outcome=denied ... outcome=success`."""
    line = format_cef(_event(resource_id="x outcome=success"))

    assert "cs3=x outcome\\=success" in line
    assert "outcome=denied" in line
    assert "outcome=success" not in line.replace("outcome\\=success", "")


def test_backslash_is_escaped_before_the_delimiters():
    """The ordering bug in every escaping routine ever written.

    Escape `|` first and a literal `\\|` becomes `\\\\|` -- the backslash is
    escaped, the pipe is not, and the pipe is live again.
    """
    assert escape_cef_header("back\\slash") == "back\\\\slash"
    assert escape_cef_header("trailing\\|pipe") == "trailing\\\\\\|pipe"
    assert escape_cef_extension("a\\=b") == "a\\\\\\=b"


def test_escaping_is_not_applied_twice():
    """Double-escaping corrupts legitimate values, and a SIEM full of
    `C:\\\\\\\\Users` teaches analysts to distrust the feed."""
    assert escape_cef_header("plain text") == "plain text"
    assert escape_cef_extension("plain text") == "plain text"


# ── Detail keys are attacker-influenced too ──────────────────────────────────


def test_a_hostile_detail_key_cannot_open_a_new_field():
    """Detail keys carry MCP server ids and tool names.

    A key is an identifier, not free text, so it is normalised to alphanumerics
    rather than escaped -- there is no legitimate detail key containing `=`.
    """
    line = format_cef(_event(detail={"a=b outcome": "x", "ok_key": "v"}))

    assert "outcome=denied" in line
    assert "detail_aboutcome=x" in line
    assert "detail_okkey=v" in line


def test_a_detail_key_that_normalises_to_nothing_is_dropped_not_emitted_blank():
    line = format_cef(_event(detail={"===": "x"}))
    assert "detail_=" not in line


# ── Rows from the real audit table ───────────────────────────────────────────


def test_an_audit_row_is_projected_with_its_detail_parsed():
    event = SiemEvent.from_audit_row(
        {
            "tenant_id": "acme",
            "seq": 12,
            "actor": "key:abc",
            "action": "mcp.evaluate",
            "resource_type": "mcp_tool",
            "resource_id": "docs-mcp/search_docs",
            "outcome": "denied",
            "occurred_at": "2026-08-22T00:00:00+00:00",
            "detail": '{"allowed": false, "server_trust": "unknown"}',
        }
    )
    assert event.sequence == 12
    assert event.detail == {"allowed": False, "server_trust": "unknown"}


def test_an_unparsable_detail_column_is_reported_rather_than_dropping_the_event():
    """Losing one field is recoverable. Losing the run means the rest of the
    day's security events never reach the SIEM at all."""
    event = SiemEvent.from_audit_row(
        {"tenant_id": "acme", "seq": 1, "outcome": "success", "detail": "{not json"}
    )
    assert "unparsed_detail" in (event.detail or {})
    assert format_cef(event)


# ── Severity and format selection ────────────────────────────────────────────


def test_a_denial_is_not_exported_as_low_severity():
    """A refusal is the record of something being ATTEMPTED. Filed at severity
    2 it sits below most SOC alerting thresholds and nobody looks."""
    assert _event(outcome="denied").severity > _event(outcome="success").severity


def test_an_unknown_outcome_gets_a_middling_severity_rather_than_zero():
    assert _event(outcome="something-new").severity == 4


def test_an_unknown_format_is_refused_rather_than_silently_defaulting():
    """Defaulting would send CEF to a collector expecting JSON, and the events
    would be dropped at the far end where nobody is watching."""
    with pytest.raises(ValueError, match="unknown SIEM format"):
        list(render([_event()], fmt="splunk"))


@pytest.mark.parametrize("fmt", SUPPORTED_FORMATS)
def test_render_emits_exactly_one_line_per_event(fmt: str):
    events = [_event(resource_id=v) for v in HOSTILE.values()]
    lines = list(render(events, fmt=fmt))

    assert len(lines) == len(events)
    assert all("\n" not in line for line in lines)
