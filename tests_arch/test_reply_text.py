"""Retained reply extraction coverage from the parked protocol tests."""

from sentinel.domain.reply_text import text_parts


def test_text_parts_extracts_prose_and_ignores_binary():
    """A base64 blob scored as prose produces noise, and noise is how a detector
    comes to be ignored.
    """
    message = {
        "parts": [
            {"kind": "text", "text": "hello"},
            {"kind": "file", "file": {"bytes": "AAAA"}},
            {"kind": "text", "text": "world"},
        ]
    }
    assert text_parts(message) == ("hello", "world")


def test_text_extraction_is_bounded():
    from sentinel.domain.reply_text import MAX_TEXT_BYTES

    message = {"parts": [{"kind": "text", "text": "x" * (MAX_TEXT_BYTES * 2)}]}
    assert sum(len(p) for p in text_parts(message)) <= MAX_TEXT_BYTES


def test_a_deeply_nested_message_does_not_recurse_forever():
    node: dict = {"kind": "text", "text": "deep"}
    for _ in range(200):
        node = {"parts": [node]}
    text_parts(node)
